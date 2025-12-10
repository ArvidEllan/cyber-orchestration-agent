/**
 * GuardDuty Analyzer
 * Fetches and analyzes AWS GuardDuty findings
 */

import {
  GuardDutyClient,
  ListDetectorsCommand,
  ListFindingsCommand,
  GetFindingsCommand,
  type Finding as GDFinding,
} from '@aws-sdk/client-guardduty';
import {
  ThreatFinding,
  Finding,
  Severity,
  Category,
  FindingStatus,
  ResourceSource,
  ThreatIntelligence,
} from '../types';

export class GuardDutyAnalyzer {
  private client: GuardDutyClient;
  private region: string;

  constructor(region: string = 'us-east-1') {
    this.region = region;
    this.client = new GuardDutyClient({ region });
  }

  /**
   * Fetch and analyze GuardDuty findings
   */
  async analyzeFindings(
    detectorId?: string,
    maxResults: number = 100
  ): Promise<ThreatFinding[]> {
    try {
      // Get detector ID if not provided
      if (!detectorId) {
        detectorId = await this.getDetectorId();
        if (!detectorId) {
          console.warn('No GuardDuty detector found');
          return [];
        }
      }

      // List finding IDs
      const findingIds = await this.listFindings(detectorId, maxResults);

      if (findingIds.length === 0) {
        return [];
      }

      // Get detailed findings
      const findings = await this.getFindings(detectorId, findingIds);

      // Normalize to ThreatFinding format
      return findings.map((f) => this.normalizeFinding(f));
    } catch (error) {
      console.error('Error analyzing GuardDuty findings:', error);
      return [];
    }
  }

  /**
   * Get the GuardDuty detector ID
   */
  private async getDetectorId(): Promise<string | undefined> {
    try {
      const command = new ListDetectorsCommand({});
      const response = await this.client.send(command);

      if (response.DetectorIds && response.DetectorIds.length > 0) {
        return response.DetectorIds[0];
      }
    } catch (error) {
      console.error('Error getting GuardDuty detector:', error);
    }

    return undefined;
  }

  /**
   * List GuardDuty finding IDs
   */
  private async listFindings(
    detectorId: string,
    maxResults: number
  ): Promise<string[]> {
    try {
      const command = new ListFindingsCommand({
        DetectorId: detectorId,
        MaxResults: maxResults,
        FindingCriteria: {
          Criterion: {
            'severity': {
              Gte: 4, // Medium and above
            },
          },
        },
      });

      const response = await this.client.send(command);
      return response.FindingIds || [];
    } catch (error) {
      console.error('Error listing GuardDuty findings:', error);
      return [];
    }
  }

  /**
   * Get detailed GuardDuty findings
   */
  private async getFindings(
    detectorId: string,
    findingIds: string[]
  ): Promise<GDFinding[]> {
    try {
      const command = new GetFindingsCommand({
        DetectorId: detectorId,
        FindingIds: findingIds,
      });

      const response = await this.client.send(command);
      return response.Findings || [];
    } catch (error) {
      console.error('Error getting GuardDuty findings:', error);
      return [];
    }
  }

  /**
   * Normalize GuardDuty finding to ThreatFinding
   */
  private normalizeFinding(gdFinding: GDFinding): ThreatFinding {
    const severity = this.mapSeverity(gdFinding.Severity);
    const category = this.mapCategory(gdFinding.Type);

    const finding: ThreatFinding = {
      id: gdFinding.Id || `gd-${Date.now()}`,
      ruleId: gdFinding.Type || 'GUARDDUTY-UNKNOWN',
      resource: {
        id: this.extractResourceId(gdFinding),
        type: this.extractResourceType(gdFinding),
        service: this.extractService(gdFinding),
        region: gdFinding.Region || this.region,
        account: gdFinding.AccountId || 'unknown',
        properties: gdFinding.Resource || {},
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(gdFinding.UpdatedAt || Date.now()),
      },
      severity,
      category,
      title: gdFinding.Title || 'GuardDuty Finding',
      description: gdFinding.Description || 'No description available',
      evidence: {
        description: 'GuardDuty threat detection',
        details: {
          type: gdFinding.Type,
          severity: gdFinding.Severity,
          confidence: gdFinding.Confidence,
          service: gdFinding.Service,
          resource: gdFinding.Resource,
        },
      },
      remediation: {
        description: this.getRemediationGuidance(gdFinding.Type),
        steps: this.getRemediationSteps(gdFinding.Type),
      },
      complianceMapping: [],
      riskScore: this.calculateRiskScore(gdFinding),
      status: FindingStatus.OPEN,
      createdAt: new Date(gdFinding.CreatedAt || Date.now()),
      updatedAt: new Date(gdFinding.UpdatedAt || Date.now()),
      threatIntel: this.extractThreatIntel(gdFinding),
    };

    return finding;
  }

  /**
   * Map GuardDuty severity to our Severity enum
   */
  private mapSeverity(gdSeverity?: number): Severity {
    if (!gdSeverity) return Severity.INFO;

    if (gdSeverity >= 7) return Severity.CRITICAL;
    if (gdSeverity >= 4) return Severity.HIGH;
    if (gdSeverity >= 1) return Severity.MEDIUM;
    return Severity.LOW;
  }

  /**
   * Map GuardDuty finding type to our Category enum
   */
  private mapCategory(type?: string): Category {
    if (!type) return Category.IAM;

    if (type.includes('UnauthorizedAccess')) return Category.IAM;
    if (type.includes('Recon')) return Category.NETWORK;
    if (type.includes('Backdoor')) return Category.NETWORK;
    if (type.includes('Trojan')) return Category.COMPUTE;
    if (type.includes('CryptoCurrency')) return Category.COMPUTE;
    if (type.includes('Exfiltration')) return Category.STORAGE;
    if (type.includes('Impact')) return Category.COMPUTE;
    if (type.includes('Policy')) return Category.IAM;
    if (type.includes('Stealth')) return Category.LOGGING;

    return Category.IAM;
  }

  /**
   * Extract resource ID from GuardDuty finding
   */
  private extractResourceId(gdFinding: GDFinding): string {
    const resource = gdFinding.Resource;

    if (resource?.InstanceDetails?.InstanceId) {
      return resource.InstanceDetails.InstanceId;
    }

    if (resource?.AccessKeyDetails?.AccessKeyId) {
      return resource.AccessKeyDetails.AccessKeyId;
    }

    if (resource?.S3BucketDetails?.[0]?.Name) {
      return resource.S3BucketDetails[0].Name;
    }

    if (resource?.EksClusterDetails?.Name) {
      return resource.EksClusterDetails.Name;
    }

    return gdFinding.Id || 'unknown';
  }

  /**
   * Extract resource type from GuardDuty finding
   */
  private extractResourceType(gdFinding: GDFinding): string {
    const resource = gdFinding.Resource;

    if (resource?.InstanceDetails) return 'EC2::Instance';
    if (resource?.AccessKeyDetails) return 'IAM::AccessKey';
    if (resource?.S3BucketDetails) return 'S3::Bucket';
    if (resource?.EksClusterDetails) return 'EKS::Cluster';

    return 'AWS::Resource';
  }

  /**
   * Extract service from GuardDuty finding
   */
  private extractService(gdFinding: GDFinding): string {
    const resource = gdFinding.Resource;

    if (resource?.InstanceDetails) return 'ec2';
    if (resource?.AccessKeyDetails) return 'iam';
    if (resource?.S3BucketDetails) return 's3';
    if (resource?.EksClusterDetails) return 'eks';

    return 'unknown';
  }

  /**
   * Calculate risk score from GuardDuty finding
   */
  private calculateRiskScore(gdFinding: GDFinding): number {
    const severity = gdFinding.Severity || 0;
    const confidence = gdFinding.Confidence || 0;

    // Normalize severity (0-10) and confidence (0-10) to risk score (0-100)
    return Math.round((severity * 7 + confidence * 3) / 10);
  }

  /**
   * Extract threat intelligence from GuardDuty finding
   */
  private extractThreatIntel(gdFinding: GDFinding): ThreatIntelligence | undefined {
    const service = gdFinding.Service;

    if (!service) return undefined;

    const indicators: string[] = [];
    const references: string[] = [];

    // Extract threat indicators
    if (service.Action?.NetworkConnectionAction?.RemoteIpDetails?.IpAddressV4) {
      indicators.push(service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4);
    }

    if (service.Action?.AwsApiCallAction?.RemoteIpDetails?.IpAddressV4) {
      indicators.push(service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4);
    }

    // Add GuardDuty reference
    references.push(
      `https://console.aws.amazon.com/guardduty/home?region=${this.region}#/findings?search=id%3D${gdFinding.Id}`
    );

    if (indicators.length === 0 && references.length === 0) {
      return undefined;
    }

    return {
      source: 'AWS GuardDuty',
      description: gdFinding.Description || 'GuardDuty threat detection',
      indicators,
      references,
      lastUpdated: new Date(gdFinding.UpdatedAt || Date.now()),
    };
  }

  /**
   * Get remediation guidance for finding type
   */
  private getRemediationGuidance(type?: string): string {
    if (!type) return 'Review and remediate the security finding';

    if (type.includes('UnauthorizedAccess')) {
      return 'Investigate unauthorized access and revoke compromised credentials';
    }

    if (type.includes('Recon')) {
      return 'Block reconnaissance activity and review security group rules';
    }

    if (type.includes('Backdoor')) {
      return 'Remove backdoor and investigate compromise';
    }

    if (type.includes('Trojan')) {
      return 'Quarantine affected resource and scan for malware';
    }

    if (type.includes('CryptoCurrency')) {
      return 'Stop cryptocurrency mining activity and investigate compromise';
    }

    if (type.includes('Exfiltration')) {
      return 'Block data exfiltration and investigate data access';
    }

    return 'Review and remediate the security finding';
  }

  /**
   * Get remediation steps for finding type
   */
  private getRemediationSteps(type?: string): string[] {
    const commonSteps = [
      'Review the GuardDuty finding details',
      'Investigate the affected resource',
      'Determine if the activity is legitimate',
      'Take appropriate remediation action',
      'Monitor for similar activity',
    ];

    if (!type) return commonSteps;

    if (type.includes('UnauthorizedAccess:IAMUser')) {
      return [
        'Rotate the compromised IAM credentials immediately',
        'Review CloudTrail logs for unauthorized actions',
        'Check for any resources created by the compromised user',
        'Enable MFA for all IAM users',
        'Review IAM policies for least privilege',
      ];
    }

    if (type.includes('Recon:EC2')) {
      return [
        'Review security group rules for the affected instance',
        'Block the source IP at network level',
        'Enable VPC Flow Logs if not already enabled',
        'Consider using AWS Network Firewall',
        'Monitor for follow-up attacks',
      ];
    }

    if (type.includes('CryptoCurrency')) {
      return [
        'Stop the affected EC2 instance immediately',
        'Take a snapshot for forensic analysis',
        'Terminate the instance and launch a clean replacement',
        'Review IAM permissions that allowed the compromise',
        'Enable CloudWatch alarms for unusual CPU usage',
      ];
    }

    if (type.includes('Exfiltration:S3')) {
      return [
        'Review S3 bucket access logs',
        'Identify what data was accessed',
        'Revoke unauthorized access immediately',
        'Enable S3 Block Public Access',
        'Implement bucket policies with least privilege',
      ];
    }

    return commonSteps;
  }
}
