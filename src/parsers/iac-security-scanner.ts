/**
 * IaC Security Scanner
 * Reusable security scanner for CloudFormation and CDK parsed resources
 */

import { v4 as uuidv4 } from 'uuid';
import { Resource } from '../types';
import {
  Finding,
  FindingResource,
  Severity,
  FrameworkMapping,
  MitreMapping,
  ComplianceMappings,
  RuleMappingEntry,
  IaCProvider,
} from '../types/core';

// Load compliance mappings
import mappingsJson from '../compliance/mappings.json';
const MAPPINGS: ComplianceMappings = mappingsJson as ComplianceMappings;

/**
 * Scan result from IaC analysis
 */
export interface IaCScanResult {
  findings: Finding[];
  resourceCount: number;
  provider: IaCProvider;
  scannedAt: Date;
}

/**
 * IaC Security Scanner Class
 * Analyzes parsed resources for security misconfigurations
 */
export class IaCSecurityScanner {
  /**
   * Scan resources for security issues
   */
  scanResources(resources: Resource[], provider: IaCProvider): IaCScanResult {
    const findings: Finding[] = [];

    for (const resource of resources) {
      const resourceFindings = this.checkResource(resource, provider);
      findings.push(...resourceFindings);
    }

    return {
      findings,
      resourceCount: resources.length,
      provider,
      scannedAt: new Date(),
    };
  }

  /**
   * Check a single resource for security issues
   */
  private checkResource(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const type = resource.type;

    // S3 Bucket checks
    if (this.isS3Bucket(type)) {
      findings.push(...this.checkS3Bucket(resource, provider));
    }

    // IAM Policy checks
    if (this.isIAMPolicy(type)) {
      findings.push(...this.checkIAMPolicy(resource, provider));
    }

    // Security Group checks
    if (this.isSecurityGroup(type)) {
      findings.push(...this.checkSecurityGroup(resource, provider));
    }

    // RDS checks
    if (this.isRDSInstance(type)) {
      findings.push(...this.checkRDSInstance(resource, provider));
    }

    // EKS checks
    if (this.isEKSCluster(type)) {
      findings.push(...this.checkEKSCluster(resource, provider));
    }

    // CloudTrail checks
    if (this.isCloudTrail(type)) {
      findings.push(...this.checkCloudTrail(resource, provider));
    }

    // EBS Volume checks
    if (this.isEBSVolume(type)) {
      findings.push(...this.checkEBSVolume(resource, provider));
    }

    // EC2 Instance checks
    if (this.isEC2Instance(type)) {
      findings.push(...this.checkEC2Instance(resource, provider));
    }

    return findings;
  }

  // =========================================================================
  // Type Checks
  // =========================================================================

  private isS3Bucket(type: string): boolean {
    return type === 'AWS::S3::Bucket' || type === 'aws_s3_bucket';
  }

  private isIAMPolicy(type: string): boolean {
    return ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'aws_iam_policy', 'aws_iam_role_policy'].includes(type);
  }

  private isSecurityGroup(type: string): boolean {
    return type === 'AWS::EC2::SecurityGroup' || type === 'aws_security_group';
  }

  private isRDSInstance(type: string): boolean {
    return ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster', 'aws_db_instance', 'aws_rds_cluster'].includes(type);
  }

  private isEKSCluster(type: string): boolean {
    return type === 'AWS::EKS::Cluster' || type === 'aws_eks_cluster';
  }

  private isCloudTrail(type: string): boolean {
    return type === 'AWS::CloudTrail::Trail' || type === 'aws_cloudtrail';
  }

  private isEBSVolume(type: string): boolean {
    return type === 'AWS::EC2::Volume' || type === 'aws_ebs_volume';
  }

  private isEC2Instance(type: string): boolean {
    return type === 'AWS::EC2::Instance' || type === 'aws_instance';
  }

  // =========================================================================
  // Security Checks
  // =========================================================================

  private checkS3Bucket(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Check for public access (CloudFormation uses different property names)
    const accessControl = props.AccessControl || props.acl;

    // Public ACL check
    const publicAcls = ['PublicRead', 'PublicReadWrite', 'AuthenticatedRead', 'public-read', 'public-read-write'];
    if (accessControl && publicAcls.includes(accessControl)) {
      findings.push(this.createFinding(
        'S3_PUBLIC_ACL',
        'S3 bucket allows public access via ACL',
        `S3 bucket "${resource.id}" has ACL set to "${accessControl}" which allows public access.`,
        'CRITICAL',
        resource,
        provider
      ));
    }

    // Encryption check
    const encryption = props.BucketEncryption || props.server_side_encryption_configuration;
    if (!encryption) {
      findings.push(this.createFinding(
        'S3_NO_ENCRYPTION',
        'S3 bucket missing server-side encryption',
        `S3 bucket "${resource.id}" does not have server-side encryption configured.`,
        'HIGH',
        resource,
        provider
      ));
    }

    // Versioning check
    const versioning = props.VersioningConfiguration || props.versioning;
    const versioningEnabled = versioning?.Status === 'Enabled' || versioning?.enabled === true;
    if (!versioningEnabled) {
      findings.push(this.createFinding(
        'S3_NO_VERSIONING',
        'S3 bucket versioning not enabled',
        `S3 bucket "${resource.id}" does not have versioning enabled.`,
        'MEDIUM',
        resource,
        provider
      ));
    }

    return findings;
  }

  private checkIAMPolicy(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Get policy document
    let policyDoc = props.PolicyDocument || props.policy;
    if (typeof policyDoc === 'string') {
      try {
        policyDoc = JSON.parse(policyDoc);
      } catch {
        return findings;
      }
    }

    if (!policyDoc?.Statement) return findings;

    // Check for wildcard actions
    for (const stmt of policyDoc.Statement) {
      if (stmt.Effect === 'Allow') {
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        if (actions.includes('*')) {
          findings.push(this.createFinding(
            'IAM_WILDCARD_ACTION',
            'IAM policy contains wildcard actions',
            `IAM policy "${resource.id}" grants Action: "*" which provides full access to all AWS services.`,
            'CRITICAL',
            resource,
            provider
          ));
          break;
        }
      }
    }

    return findings;
  }

  private checkSecurityGroup(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Get ingress rules
    const ingressRules = props.SecurityGroupIngress || props.ingress || [];
    const rules = Array.isArray(ingressRules) ? ingressRules : [ingressRules];

    for (const rule of rules) {
      const fromPort = rule.FromPort || rule.from_port;
      const toPort = rule.ToPort || rule.to_port;
      const cidrIp = rule.CidrIp || rule.cidr_blocks?.[0];

      const isOpenToWorld = cidrIp === '0.0.0.0/0' || cidrIp === '::/0';

      if (isOpenToWorld) {
        // Check for SSH (port 22)
        if (this.portInRange(22, fromPort, toPort)) {
          findings.push(this.createFinding(
            'EC2_SG_OPEN_SSH',
            'Security group allows SSH from 0.0.0.0/0',
            `Security group "${resource.id}" allows SSH (port 22) from 0.0.0.0/0.`,
            'CRITICAL',
            resource,
            provider
          ));
        }

        // Check for RDP (port 3389)
        if (this.portInRange(3389, fromPort, toPort)) {
          findings.push(this.createFinding(
            'EC2_SG_OPEN_RDP',
            'Security group allows RDP from 0.0.0.0/0',
            `Security group "${resource.id}" allows RDP (port 3389) from 0.0.0.0/0.`,
            'CRITICAL',
            resource,
            provider
          ));
        }
      }
    }

    return findings;
  }

  private checkRDSInstance(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Public accessibility check
    const publiclyAccessible = props.PubliclyAccessible || props.publicly_accessible;
    if (publiclyAccessible === true) {
      findings.push(this.createFinding(
        'RDS_PUBLICLY_ACCESSIBLE',
        'RDS instance is publicly accessible',
        `RDS instance "${resource.id}" is publicly accessible. Databases should be in private subnets.`,
        'CRITICAL',
        resource,
        provider
      ));
    }

    // Encryption check
    const storageEncrypted = props.StorageEncrypted || props.storage_encrypted;
    if (storageEncrypted !== true) {
      findings.push(this.createFinding(
        'RDS_NO_ENCRYPTION',
        'RDS instance storage not encrypted',
        `RDS instance "${resource.id}" does not have storage encryption enabled.`,
        'HIGH',
        resource,
        provider
      ));
    }

    return findings;
  }

  private checkEKSCluster(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // VPC config check
    const vpcConfig = props.ResourcesVpcConfig || props.vpc_config?.[0];
    if (vpcConfig) {
      const endpointPublicAccess = vpcConfig.EndpointPublicAccess || vpcConfig.endpoint_public_access;
      const endpointPrivateAccess = vpcConfig.EndpointPrivateAccess || vpcConfig.endpoint_private_access;

      if (endpointPublicAccess === true && endpointPrivateAccess === false) {
        findings.push(this.createFinding(
          'EKS_PUBLIC_ENDPOINT',
          'EKS cluster API endpoint publicly accessible',
          `EKS cluster "${resource.id}" has public endpoint access enabled with private access disabled.`,
          'HIGH',
          resource,
          provider
        ));
      }
    }

    // Logging check
    const logging = props.Logging || props.enabled_cluster_log_types;
    const hasAuditLogging = logging?.ClusterLogging?.some(
      (log: { Types?: string[]; Enabled?: boolean }) => log.Enabled && log.Types?.includes('audit')
    ) || (Array.isArray(logging) && logging.includes('audit'));

    if (!hasAuditLogging) {
      findings.push(this.createFinding(
        'EKS_NO_AUDIT_LOG',
        'EKS cluster audit logging not enabled',
        `EKS cluster "${resource.id}" does not have audit logging enabled.`,
        'HIGH',
        resource,
        provider
      ));
    }

    return findings;
  }

  private checkCloudTrail(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Logging enabled check
    const enableLogging = props.EnableLogging ?? props.enable_logging;
    if (enableLogging === false) {
      findings.push(this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail logging is disabled',
        `CloudTrail "${resource.id}" has logging disabled.`,
        'CRITICAL',
        resource,
        provider
      ));
    }

    // Multi-region check
    const isMultiRegion = props.IsMultiRegionTrail || props.is_multi_region_trail;
    if (isMultiRegion === false) {
      findings.push(this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail not configured for multi-region',
        `CloudTrail "${resource.id}" is not configured for multi-region logging.`,
        'HIGH',
        resource,
        provider
      ));
    }

    // Log validation check
    const logValidation = props.EnableLogFileValidation || props.enable_log_file_validation;
    if (logValidation === false) {
      findings.push(this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail log file validation disabled',
        `CloudTrail "${resource.id}" has log file validation disabled.`,
        'HIGH',
        resource,
        provider
      ));
    }

    return findings;
  }

  private checkEBSVolume(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    const encrypted = props.Encrypted || props.encrypted;
    if (encrypted !== true) {
      findings.push(this.createFinding(
        'EC2_UNENCRYPTED_EBS',
        'EBS volume not encrypted',
        `EBS volume "${resource.id}" does not have encryption enabled.`,
        'HIGH',
        resource,
        provider
      ));
    }

    return findings;
  }

  private checkEC2Instance(resource: Resource, provider: IaCProvider): Finding[] {
    const findings: Finding[] = [];
    const props = resource.properties;

    // Check EBS block devices
    const blockDevices = props.BlockDeviceMappings || props.ebs_block_device || [];
    for (const device of blockDevices) {
      const ebs = device.Ebs || device;
      if (ebs.Encrypted === false || ebs.encrypted === false) {
        findings.push(this.createFinding(
          'EC2_UNENCRYPTED_EBS',
          'EC2 instance has unencrypted EBS volume',
          `EC2 instance "${resource.id}" has an unencrypted EBS block device.`,
          'HIGH',
          resource,
          provider
        ));
        break;
      }
    }

    return findings;
  }

  // =========================================================================
  // Helpers
  // =========================================================================

  private portInRange(port: number, from?: number, to?: number): boolean {
    if (from === undefined || to === undefined) return false;
    return port >= from && port <= to;
  }

  private createFinding(
    ruleId: string,
    title: string,
    description: string,
    severity: Severity,
    resource: Resource,
    provider: IaCProvider
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

    const findingResource: FindingResource = {
      type: resource.type,
      id: resource.id,
      region: resource.region,
      account: resource.account,
    };

    return {
      id: uuidv4(),
      title,
      description,
      severity,
      resource: findingResource,
      source: 'static',
      provider,
      frameworks,
      mitre,
      detectedAt: new Date(),
    };
  }
}

// Export singleton
export const iacSecurityScanner = new IaCSecurityScanner();
