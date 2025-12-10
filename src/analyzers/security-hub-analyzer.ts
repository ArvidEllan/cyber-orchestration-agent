/**
 * Security Hub Analyzer
 * Aggregates and analyzes AWS Security Hub findings
 */

import {
  SecurityHubClient,
  GetFindingsCommand,
  type AwsSecurityFinding,
} from '@aws-sdk/client-securityhub';
import {
  ThreatFinding,
  Severity,
  Category,
  FindingStatus,
  ResourceSource,
  ThreatIntelligence,
} from '../types';

export class SecurityHubAnalyzer {
  private client: SecurityHubClient;
  private region: string;

  constructor(region: string = 'us-east-1') {
    this.region = region;
    this.client = new SecurityHubClient({ region });
  }

  /**
   * Fetch and analyze Security Hub findings
   */
  async analyzeFindings(maxResults: number = 100): Promise<ThreatFinding[]> {
    try {
      const findings = await this.getFindings(maxResults);
      return findings.map((f) => this.normalizeFinding(f));
    } catch (error) {
      console.error('Error analyzing Security Hub findings:', error);
      return [];
    }
  }

  /**
   * Get Security Hub findings
   */
  private async getFindings(maxResults: number): Promise<AwsSecurityFinding[]> {
    try {
      const command = new GetFindingsCommand({
        MaxResults: maxResults,
        Filters: {
          RecordState: [
            {
              Value: 'ACTIVE',
              Comparison: 'EQUALS',
            },
          ],
          WorkflowStatus: [
            {
              Value: 'NEW',
              Comparison: 'EQUALS',
            },
            {
              Value: 'NOTIFIED',
              Comparison: 'EQUALS',
            },
          ],
        },
      });

      const response = await this.client.send(command);
      return response.Findings || [];
    } catch (error) {
      console.error('Error getting Security Hub findings:', error);
      return [];
    }
  }

  /**
   * Normalize Security Hub finding to ThreatFinding
   */
  private normalizeFinding(shFinding: AwsSecurityFinding): ThreatFinding {
    const severity = this.mapSeverity(shFinding.Severity?.Label);
    const category = this.mapCategory(shFinding.Types);

    const finding: ThreatFinding = {
      id: shFinding.Id || `sh-${Date.now()}`,
      ruleId: shFinding.GeneratorId || 'SECURITYHUB-UNKNOWN',
      resource: {
        id: this.extractResourceId(shFinding),
        type: this.extractResourceType(shFinding),
        service: this.extractService(shFinding),
        region: shFinding.Region || this.region,
        account: shFinding.AwsAccountId || 'unknown',
        properties: shFinding.Resources?.[0] || {},
        tags: this.extractTags(shFinding),
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(shFinding.UpdatedAt || Date.now()),
      },
      severity,
      category,
      title: shFinding.Title || 'Security Hub Finding',
      description: shFinding.Description || 'No description available',
      evidence: {
        description: 'Security Hub finding',
        details: {
          types: shFinding.Types,
          productArn: shFinding.ProductArn,
          generatorId: shFinding.GeneratorId,
          compliance: shFinding.Compliance,
          resources: shFinding.Resources,
        },
      },
      remediation: {
        description: shFinding.Remediation?.Recommendation?.Text || 'Review and remediate the finding',
        steps: this.extractRemediationSteps(shFinding),
        references: shFinding.Remediation?.Recommendation?.Url
          ? [shFinding.Remediation.Recommendation.Url]
          : undefined,
      },
      complianceMapping: this.extractComplianceMapping(shFinding),
      riskScore: this.calculateRiskScore(shFinding),
      status: this.mapWorkflowStatus(shFinding.Workflow?.Status),
      createdAt: new Date(shFinding.CreatedAt || Date.now()),
      updatedAt: new Date(shFinding.UpdatedAt || Date.now()),
      threatIntel: this.extractThreatIntel(shFinding),
    };

    return finding;
  }

  /**
   * Map Security Hub severity to our Severity enum
   */
  private mapSeverity(label?: string): Severity {
    if (!label) return Severity.INFO;

    const normalized = label.toUpperCase();

    if (normalized === 'CRITICAL') return Severity.CRITICAL;
    if (normalized === 'HIGH') return Severity.HIGH;
    if (normalized === 'MEDIUM') return Severity.MEDIUM;
    if (normalized === 'LOW') return Severity.LOW;
    if (normalized === 'INFORMATIONAL') return Severity.INFO;

    return Severity.INFO;
  }

  /**
   * Map Security Hub finding types to our Category enum
   */
  private mapCategory(types?: string[]): Category {
    if (!types || types.length === 0) return Category.IAM;

    const typeStr = types.join(' ').toLowerCase();

    if (typeStr.includes('iam') || typeStr.includes('authentication')) {
      return Category.IAM;
    }
    if (typeStr.includes('network') || typeStr.includes('firewall')) {
      return Category.NETWORK;
    }
    if (typeStr.includes('encryption') || typeStr.includes('data protection')) {
      return Category.ENCRYPTION;
    }
    if (typeStr.includes('logging') || typeStr.includes('monitoring')) {
      return Category.LOGGING;
    }
    if (typeStr.includes('compute') || typeStr.includes('ec2')) {
      return Category.COMPUTE;
    }
    if (typeStr.includes('storage') || typeStr.includes('s3')) {
      return Category.STORAGE;
    }
    if (typeStr.includes('database') || typeStr.includes('rds')) {
      return Category.DATABASE;
    }
    if (typeStr.includes('container') || typeStr.includes('eks')) {
      return Category.CONTAINER;
    }
    if (typeStr.includes('api')) {
      return Category.API;
    }

    return Category.IAM;
  }

  /**
   * Map Security Hub workflow status to our FindingStatus enum
   */
  private mapWorkflowStatus(status?: string): FindingStatus {
    if (!status) return FindingStatus.OPEN;

    const normalized = status.toUpperCase();

    if (normalized === 'NEW' || normalized === 'NOTIFIED') {
      return FindingStatus.OPEN;
    }
    if (normalized === 'RESOLVED') {
      return FindingStatus.RESOLVED;
    }
    if (normalized === 'SUPPRESSED') {
      return FindingStatus.ACCEPTED_RISK;
    }

    return FindingStatus.OPEN;
  }

  /**
   * Extract resource ID from Security Hub finding
   */
  private extractResourceId(shFinding: AwsSecurityFinding): string {
    if (shFinding.Resources && shFinding.Resources.length > 0) {
      const resource = shFinding.Resources[0];
      return resource.Id || 'unknown';
    }
    return shFinding.Id || 'unknown';
  }

  /**
   * Extract resource type from Security Hub finding
   */
  private extractResourceType(shFinding: AwsSecurityFinding): string {
    if (shFinding.Resources && shFinding.Resources.length > 0) {
      const resource = shFinding.Resources[0];
      return resource.Type || 'AWS::Resource';
    }
    return 'AWS::Resource';
  }

  /**
   * Extract service from Security Hub finding
   */
  private extractService(shFinding: AwsSecurityFinding): string {
    if (shFinding.Resources && shFinding.Resources.length > 0) {
      const resource = shFinding.Resources[0];
      const type = resource.Type || '';

      // Extract service from resource type (e.g., "AwsEc2Instance" -> "ec2")
      const match = type.match(/Aws([A-Z][a-z0-9]+)/);
      if (match) {
        return match[1].toLowerCase();
      }
    }

    return 'unknown';
  }

  /**
   * Extract tags from Security Hub finding
   */
  private extractTags(shFinding: AwsSecurityFinding): Record<string, string> {
    const tags: Record<string, string> = {};

    if (shFinding.Resources && shFinding.Resources.length > 0) {
      const resource = shFinding.Resources[0];
      if (resource.Tags) {
        for (const [key, value] of Object.entries(resource.Tags)) {
          tags[key] = String(value);
        }
      }
    }

    return tags;
  }

  /**
   * Extract remediation steps from Security Hub finding
   */
  private extractRemediationSteps(shFinding: AwsSecurityFinding): string[] {
    const steps: string[] = [];

    if (shFinding.Remediation?.Recommendation?.Text) {
      steps.push(shFinding.Remediation.Recommendation.Text);
    }

    if (shFinding.Remediation?.Recommendation?.Url) {
      steps.push(`See: ${shFinding.Remediation.Recommendation.Url}`);
    }

    if (steps.length === 0) {
      steps.push('Review the Security Hub finding details');
      steps.push('Follow AWS best practices for remediation');
      steps.push('Verify compliance after remediation');
    }

    return steps;
  }

  /**
   * Extract compliance mapping from Security Hub finding
   */
  private extractComplianceMapping(shFinding: AwsSecurityFinding): any[] {
    const mappings: any[] = [];

    if (shFinding.Compliance?.RelatedRequirements) {
      for (const requirement of shFinding.Compliance.RelatedRequirements) {
        // Parse requirement format like "CIS AWS Foundations 1.1"
        const parts = requirement.split(' ');
        if (parts.length >= 2) {
          mappings.push({
            framework: parts.slice(0, -1).join(' '),
            controlId: parts[parts.length - 1],
            controlName: requirement,
            requirement: shFinding.Title || requirement,
            status: shFinding.Compliance.Status || 'NON_COMPLIANT',
          });
        }
      }
    }

    return mappings;
  }

  /**
   * Calculate risk score from Security Hub finding
   */
  private calculateRiskScore(shFinding: AwsSecurityFinding): number {
    const severity = shFinding.Severity?.Normalized || 0;
    const criticality = shFinding.Criticality || 0;

    // Combine normalized severity (0-100) and criticality (0-100)
    return Math.round((severity * 0.7 + criticality * 0.3));
  }

  /**
   * Extract threat intelligence from Security Hub finding
   */
  private extractThreatIntel(
    shFinding: AwsSecurityFinding
  ): ThreatIntelligence | undefined {
    const indicators: string[] = [];
    const references: string[] = [];

    // Extract threat indicators from finding
    if (shFinding.ThreatIntelIndicators) {
      for (const indicator of shFinding.ThreatIntelIndicators) {
        if (indicator.Value) {
          indicators.push(indicator.Value);
        }
        if (indicator.SourceUrl) {
          references.push(indicator.SourceUrl);
        }
      }
    }

    // Add Security Hub console link
    references.push(
      `https://console.aws.amazon.com/securityhub/home?region=${this.region}#/findings?search=Id%3D${encodeURIComponent(shFinding.Id || '')}`
    );

    // Add remediation URL if available
    if (shFinding.Remediation?.Recommendation?.Url) {
      references.push(shFinding.Remediation.Recommendation.Url);
    }

    if (indicators.length === 0 && references.length <= 1) {
      return undefined;
    }

    return {
      source: this.extractThreatSource(shFinding),
      description: shFinding.Description || 'Security Hub finding',
      indicators,
      references,
      lastUpdated: new Date(shFinding.UpdatedAt || Date.now()),
    };
  }

  /**
   * Extract threat source from Security Hub finding
   */
  private extractThreatSource(shFinding: AwsSecurityFinding): string {
    if (shFinding.ProductName) {
      return shFinding.ProductName;
    }

    if (shFinding.ProductArn) {
      // Extract product name from ARN
      const parts = shFinding.ProductArn.split('/');
      if (parts.length > 0) {
        return parts[parts.length - 1];
      }
    }

    return 'AWS Security Hub';
  }

  /**
   * Get findings by severity
   */
  async getFindingsBySeverity(severity: Severity): Promise<ThreatFinding[]> {
    try {
      const severityLabel = this.mapSeverityToLabel(severity);

      const command = new GetFindingsCommand({
        MaxResults: 100,
        Filters: {
          RecordState: [
            {
              Value: 'ACTIVE',
              Comparison: 'EQUALS',
            },
          ],
          SeverityLabel: [
            {
              Value: severityLabel,
              Comparison: 'EQUALS',
            },
          ],
        },
      });

      const response = await this.client.send(command);
      const findings = response.Findings || [];

      return findings.map((f) => this.normalizeFinding(f));
    } catch (error) {
      console.error('Error getting findings by severity:', error);
      return [];
    }
  }

  /**
   * Map our Severity enum to Security Hub severity label
   */
  private mapSeverityToLabel(severity: Severity): string {
    switch (severity) {
      case Severity.CRITICAL:
        return 'CRITICAL';
      case Severity.HIGH:
        return 'HIGH';
      case Severity.MEDIUM:
        return 'MEDIUM';
      case Severity.LOW:
        return 'LOW';
      case Severity.INFO:
        return 'INFORMATIONAL';
      default:
        return 'INFORMATIONAL';
    }
  }

  /**
   * Get findings by compliance status
   */
  async getFindingsByCompliance(
    complianceStatus: string
  ): Promise<ThreatFinding[]> {
    try {
      const command = new GetFindingsCommand({
        MaxResults: 100,
        Filters: {
          RecordState: [
            {
              Value: 'ACTIVE',
              Comparison: 'EQUALS',
            },
          ],
          ComplianceStatus: [
            {
              Value: complianceStatus,
              Comparison: 'EQUALS',
            },
          ],
        },
      });

      const response = await this.client.send(command);
      const findings = response.Findings || [];

      return findings.map((f) => this.normalizeFinding(f));
    } catch (error) {
      console.error('Error getting findings by compliance:', error);
      return [];
    }
  }
}
