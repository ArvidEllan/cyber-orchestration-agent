/**
 * Auditor Orchestrator
 * Coordinates AWS auditors and generates security Findings
 */

import { v4 as uuidv4 } from 'uuid';
import { AWSClient } from './aws-client';
import { IAMAuditor } from './iam-auditor';
import { S3Auditor } from './s3-auditor';
import { EKSAuditor } from './eks-auditor';
import { SecurityServicesAuditor } from './security-services-auditor';
import {
  Finding,
  FindingResource,
  Severity,
  FrameworkMapping,
  MitreMapping,
  ComplianceMappings,
  RuleMappingEntry,
} from '../types/core';

// Load compliance mappings
import mappingsJson from '../compliance/mappings.json';
const MAPPINGS: ComplianceMappings = mappingsJson as ComplianceMappings;

/**
 * Audit result containing findings and metadata
 */
export interface AuditResult {
  findings: Finding[];
  resourceCount: number;
  servicesAudited: string[];
  errors: Array<{ service: string; error: string }>;
  auditedAt: Date;
}

/**
 * Audit options
 */
export interface AuditOptions {
  services?: string[];
  regions?: string[];
  maxResources?: number;
}

/**
 * Auditor Orchestrator Class
 */
export class AuditorOrchestrator {
  private iamAuditor: IAMAuditor;
  private s3Auditor: S3Auditor;
  private eksAuditor: EKSAuditor;
  private securityServicesAuditor: SecurityServicesAuditor;

  constructor(awsClient: AWSClient) {
    this.iamAuditor = new IAMAuditor(awsClient);
    this.s3Auditor = new S3Auditor(awsClient);
    this.eksAuditor = new EKSAuditor(awsClient);
    this.securityServicesAuditor = new SecurityServicesAuditor(awsClient);
  }

  /**
   * Run a full security audit
   */
  async runAudit(accountId: string, options: AuditOptions = {}): Promise<AuditResult> {
    const findings: Finding[] = [];
    const errors: Array<{ service: string; error: string }> = [];
    const servicesAudited: string[] = [];
    let resourceCount = 0;

    const services = options.services || ['iam', 's3', 'cloudtrail', 'eks'];
    const regions = options.regions || ['us-east-1'];

    // Audit IAM (global service)
    if (services.includes('iam')) {
      try {
        const iamFindings = await this.auditIAM(accountId);
        findings.push(...iamFindings.findings);
        resourceCount += iamFindings.resourceCount;
        servicesAudited.push('iam');
      } catch (error) {
        errors.push({
          service: 'iam',
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Audit S3 (global service)
    if (services.includes('s3')) {
      try {
        const s3Findings = await this.auditS3(accountId);
        findings.push(...s3Findings.findings);
        resourceCount += s3Findings.resourceCount;
        servicesAudited.push('s3');
      } catch (error) {
        errors.push({
          service: 's3',
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Audit CloudTrail
    if (services.includes('cloudtrail')) {
      try {
        const ctFindings = await this.auditCloudTrail(accountId, regions);
        findings.push(...ctFindings.findings);
        resourceCount += ctFindings.resourceCount;
        servicesAudited.push('cloudtrail');
      } catch (error) {
        errors.push({
          service: 'cloudtrail',
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    // Audit EKS (per region)
    if (services.includes('eks')) {
      for (const region of regions) {
        try {
          const eksFindings = await this.auditEKSClusters(accountId, region);
          findings.push(...eksFindings.findings);
          resourceCount += eksFindings.resourceCount;
          if (!servicesAudited.includes('eks')) {
            servicesAudited.push('eks');
          }
        } catch (error) {
          errors.push({
            service: `eks:${region}`,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }

    return {
      findings,
      resourceCount,
      servicesAudited,
      errors,
      auditedAt: new Date(),
    };
  }

  // =========================================================================
  // IAM Security Checks
  // =========================================================================

  private async auditIAM(accountId: string): Promise<{ findings: Finding[]; resourceCount: number }> {
    const findings: Finding[] = [];
    const identityAudit = await this.iamAuditor.auditIdentity(accountId);

    let resourceCount = identityAudit.users.length + identityAudit.roles.length + identityAudit.policies.length;

    // Check for root account without MFA (would need separate API call to check credential report)
    // For now, check for users without recent activity that have active keys

    // Check for unused access keys (>90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

    for (const user of identityAudit.users) {
      for (const key of user.accessKeys) {
        if (key.status === 'Active') {
          const lastUsed = key.lastUsedDate || key.createDate;
          if (lastUsed < ninetyDaysAgo) {
            findings.push(this.createFinding(
              'IAM_UNUSED_KEY_90D',
              'IAM access key unused for 90+ days',
              `User "${user.userName}" has an active access key (${key.accessKeyId}) that hasn't been used in over 90 days. Unused credentials increase attack surface.`,
              'HIGH',
              'AWS::IAM::AccessKey',
              `${user.arn}/AccessKey/${key.accessKeyId}`,
              accountId
            ));
          }
        }
      }
    }

    // Check for inline policies on roles (prefer managed policies)
    // Note: Current auditor only collects attached policies, would need to extend for inline

    // Check for wildcard actions in customer-managed policies
    for (const policy of identityAudit.policies) {
      if (policy.document?.Statement) {
        for (const stmt of policy.document.Statement) {
          if (stmt.Effect === 'Allow') {
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            if (actions.includes('*')) {
              findings.push(this.createFinding(
                'IAM_WILDCARD_ACTION',
                'IAM policy grants full administrative access',
                `Policy "${policy.policyName}" contains Action: "*" which grants access to all AWS services. This violates the principle of least privilege.`,
                'CRITICAL',
                'AWS::IAM::Policy',
                policy.arn,
                accountId
              ));
            }
          }
        }
      }
    }

    return { findings, resourceCount };
  }

  // =========================================================================
  // S3 Security Checks
  // =========================================================================

  private async auditS3(accountId: string): Promise<{ findings: Finding[]; resourceCount: number }> {
    const findings: Finding[] = [];
    const buckets = await this.s3Auditor.auditBuckets(accountId);

    for (const bucket of buckets) {
      const bucketName = bucket.properties.bucketName;

      // Check for public access
      const publicAccessBlock = bucket.properties.publicAccessBlock;
      const isPublicAccessBlocked = publicAccessBlock &&
        publicAccessBlock.BlockPublicAcls &&
        publicAccessBlock.IgnorePublicAcls &&
        publicAccessBlock.BlockPublicPolicy &&
        publicAccessBlock.RestrictPublicBuckets;

      if (!isPublicAccessBlocked) {
        // Check ACL for public grants
        const acl = bucket.properties.acl;
        if (acl?.grants) {
          const hasPublicGrant = acl.grants.some((grant: { Grantee?: { URI?: string } }) =>
            grant.Grantee?.URI?.includes('AllUsers') ||
            grant.Grantee?.URI?.includes('AuthenticatedUsers')
          );

          if (hasPublicGrant) {
            findings.push(this.createFinding(
              'S3_PUBLIC_ACL',
              'S3 bucket has public ACL grant',
              `Bucket "${bucketName}" has an ACL that grants public access. This can expose sensitive data to the internet.`,
              'CRITICAL',
              'AWS::S3::Bucket',
              bucket.id,
              accountId
            ));
          }
        }
      }

      // Check for missing encryption
      const encryption = bucket.properties.encryption;
      if (!encryption || encryption.enabled === false) {
        findings.push(this.createFinding(
          'S3_NO_ENCRYPTION',
          'S3 bucket missing server-side encryption',
          `Bucket "${bucketName}" does not have server-side encryption enabled. Data at rest should be encrypted.`,
          'HIGH',
          'AWS::S3::Bucket',
          bucket.id,
          accountId
        ));
      }

      // Check for versioning
      const versioning = bucket.properties.versioning;
      if (!versioning || versioning.status !== 'Enabled') {
        findings.push(this.createFinding(
          'S3_NO_VERSIONING',
          'S3 bucket versioning not enabled',
          `Bucket "${bucketName}" does not have versioning enabled. Versioning protects against accidental deletion.`,
          'MEDIUM',
          'AWS::S3::Bucket',
          bucket.id,
          accountId
        ));
      }
    }

    return { findings, resourceCount: buckets.length };
  }

  // =========================================================================
  // CloudTrail Security Checks
  // =========================================================================

  private async auditCloudTrail(accountId: string, regions: string[]): Promise<{ findings: Finding[]; resourceCount: number }> {
    const findings: Finding[] = [];
    let resourceCount = 0;

    // Audit CloudTrail in first region (trails are typically multi-region)
    const region = regions[0] || 'us-east-1';
    const trailAudit = await this.securityServicesAuditor.auditSecurityServices(accountId, region);
    resourceCount = trailAudit.cloudTrail.trails.length;

    // Check if CloudTrail is enabled
    if (trailAudit.cloudTrail.trails.length === 0) {
      findings.push(this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail is not enabled',
        `No CloudTrail trails found in account ${accountId}. CloudTrail should be enabled for audit logging and security monitoring.`,
        'CRITICAL',
        'AWS::CloudTrail::Trail',
        `arn:aws:cloudtrail:${region}:${accountId}:trail`,
        accountId
      ));
    } else {
      // Check each trail
      for (const trail of trailAudit.cloudTrail.trails) {
        // Check for multi-region
        if (!trail.isMultiRegionTrail) {
          findings.push(this.createFinding(
            'CLOUDTRAIL_NOT_ENABLED',
            'CloudTrail not configured for multi-region',
            `Trail "${trail.name}" is not configured for multi-region logging. Events in other regions won't be captured.`,
            'HIGH',
            'AWS::CloudTrail::Trail',
            `arn:aws:cloudtrail:${region}:${accountId}:trail/${trail.name}`,
            accountId
          ));
        }

        // Check for log file validation
        if (!trail.logFileValidationEnabled) {
          findings.push(this.createFinding(
            'CLOUDTRAIL_NOT_ENABLED',
            'CloudTrail log file validation disabled',
            `Trail "${trail.name}" has log file validation disabled. Enable it to detect log tampering.`,
            'HIGH',
            'AWS::CloudTrail::Trail',
            `arn:aws:cloudtrail:${region}:${accountId}:trail/${trail.name}`,
            accountId
          ));
        }
      }
    }

    return { findings, resourceCount };
  }

  // =========================================================================
  // EKS Security Checks
  // =========================================================================

  private async auditEKSClusters(accountId: string, region: string): Promise<{ findings: Finding[]; resourceCount: number }> {
    const findings: Finding[] = [];
    const clusters = await this.eksAuditor.auditEKS(accountId, region);

    for (const cluster of clusters) {
      const clusterName = cluster.properties.name;

      // Check for public endpoint with private access disabled
      const vpcConfig = cluster.properties.resourcesVpcConfig;
      if (vpcConfig) {
        if (vpcConfig.endpointPublicAccess && !vpcConfig.endpointPrivateAccess) {
          findings.push(this.createFinding(
            'EKS_PUBLIC_ENDPOINT',
            'EKS cluster API endpoint publicly accessible',
            `EKS cluster "${clusterName}" has public endpoint access enabled with private access disabled. Enable private endpoint access for secure cluster communication.`,
            'HIGH',
            'AWS::EKS::Cluster',
            cluster.id,
            accountId
          ));
        }
      }

      // Check for audit logging
      const logging = cluster.properties.logging;
      const auditLogEnabled = logging?.clusterLogging?.some(
        (log: { types?: string[]; enabled?: boolean }) =>
          log.enabled && log.types?.includes('audit')
      );

      if (!auditLogEnabled) {
        findings.push(this.createFinding(
          'EKS_NO_AUDIT_LOG',
          'EKS cluster audit logging not enabled',
          `EKS cluster "${clusterName}" does not have audit logging enabled. Enable audit logs for security monitoring and compliance.`,
          'HIGH',
          'AWS::EKS::Cluster',
          cluster.id,
          accountId
        ));
      }
    }

    return { findings, resourceCount: clusters.length };
  }

  // =========================================================================
  // Helper Methods
  // =========================================================================

  /**
   * Create a Finding object
   */
  private createFinding(
    ruleId: string,
    title: string,
    description: string,
    severity: Severity,
    resourceType: string,
    resourceId: string,
    account: string
  ): Finding {
    const mapping = MAPPINGS[ruleId] as RuleMappingEntry | undefined;

    const frameworks: FrameworkMapping[] = mapping?.frameworks.map((f) => ({
      framework: f.framework,
      controlId: f.controlId,
      controlTitle: f.controlTitle,
      required: true,
    })) || [];

    const mitre: MitreMapping | undefined = mapping?.mitre
      ? {
          techniqueId: mapping.mitre.techniqueId,
          techniqueName: mapping.mitre.techniqueName,
          tactic: mapping.mitre.tactic,
          url: mapping.mitre.url,
        }
      : undefined;

    const resource: FindingResource = {
      type: resourceType,
      id: resourceId,
      account,
    };

    return {
      id: uuidv4(),
      title,
      description,
      severity,
      resource,
      source: 'live',
      provider: 'aws_live',
      frameworks,
      mitre,
      detectedAt: new Date(),
    };
  }
}

export const createAuditorOrchestrator = (awsClient: AWSClient): AuditorOrchestrator => {
  return new AuditorOrchestrator(awsClient);
};
