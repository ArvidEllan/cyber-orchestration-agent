/**
 * Terraform Parser with Security Rules
 * Parses HCL files using @cdktf/hcl2json and runs security checks
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { parse as parseHCL } from '@cdktf/hcl2json';
import { v4 as uuidv4 } from 'uuid';
import {
  Finding,
  FindingResource,
  FrameworkMapping,
  MitreMapping,
  Severity,
  ComplianceMappings,
  RuleMappingEntry,
} from '../types/core';
import {
  IaCParser,
  IaCFormat,
  ParsedInfrastructure,
  ValidationResult,
  Resource,
  ResourceSource,
} from '../types';

// Load compliance mappings
import mappingsJson from '../compliance/mappings.json';
const MAPPINGS: ComplianceMappings = mappingsJson as ComplianceMappings;

/**
 * Parsed HCL structure from @cdktf/hcl2json
 */
interface HCLParseResult {
  resource?: Record<string, Record<string, Array<Record<string, unknown>>>>;
  variable?: Record<string, unknown>;
  output?: Record<string, unknown>;
  data?: Record<string, Record<string, Array<Record<string, unknown>>>>;
  terraform?: Record<string, unknown>;
  provider?: Record<string, unknown>;
}

/**
 * Internal resource representation during parsing
 */
interface ParsedResource {
  type: string;
  name: string;
  config: Record<string, unknown>;
  rawBlock: string;
  filePath: string;
  startLine?: number;
}

/**
 * Result of scanning a Terraform directory
 */
export interface TerraformScanResult {
  findings: Finding[];
  resourceCount: number;
  fileCount: number;
  errors: Array<{ file: string; error: string }>;
}

/**
 * Rule check function signature
 */
type RuleCheckFn = (
  resourceType: string,
  resourceName: string,
  config: Record<string, unknown>,
  rawBlock: string,
  filePath: string
) => Finding | null;

/**
 * Terraform Parser Class
 * Implements IaCParser interface for compatibility with ParserFactory
 */
export class TerraformParser implements IaCParser {
  private ruleChecks: Map<string, RuleCheckFn> = new Map();

  constructor() {
    this.registerRules();
  }

  /**
   * Register all security rule check functions
   */
  private registerRules(): void {
    this.ruleChecks.set('S3_PUBLIC_ACL', this.checkS3PublicAcl.bind(this));
    this.ruleChecks.set('S3_NO_ENCRYPTION', this.checkS3Encryption.bind(this));
    this.ruleChecks.set('S3_NO_VERSIONING', this.checkS3Versioning.bind(this));
    this.ruleChecks.set('IAM_WILDCARD_ACTION', this.checkIamWildcard.bind(this));
    this.ruleChecks.set('EC2_SG_OPEN_SSH', this.checkSgOpenSsh.bind(this));
    this.ruleChecks.set('EC2_SG_OPEN_RDP', this.checkSgOpenRdp.bind(this));
    this.ruleChecks.set('EC2_UNENCRYPTED_EBS', this.checkEbsEncryption.bind(this));
    this.ruleChecks.set('CLOUDTRAIL_NOT_ENABLED', this.checkCloudtrailEnabled.bind(this));
    this.ruleChecks.set('RDS_PUBLICLY_ACCESSIBLE', this.checkRdsPublic.bind(this));
    this.ruleChecks.set('RDS_NO_ENCRYPTION', this.checkRdsEncryption.bind(this));
    this.ruleChecks.set('EKS_PUBLIC_ENDPOINT', this.checkEksPublicEndpoint.bind(this));
  }

  // =========================================================================
  // IaCParser Interface Implementation
  // =========================================================================

  /**
   * Parse a Terraform file and return ParsedInfrastructure
   * Required by IaCParser interface
   */
  async parse(filePath: string, _format: IaCFormat): Promise<ParsedInfrastructure> {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = await this.parseHCLContent(filePath, content);
    const resources = this.extractResourcesFromHCL(parsed, content, filePath);

    return {
      format: IaCFormat.TERRAFORM,
      resources: resources.map((r) => this.toResource(r)),
      variables: this.extractVariables(parsed),
      outputs: this.extractOutputs(parsed),
      metadata: {
        filePath,
        parsedAt: new Date(),
      },
    };
  }

  /**
   * Validate parsed infrastructure
   * Required by IaCParser interface
   */
  validate(parsed: ParsedInfrastructure): ValidationResult {
    const errors: Array<{ message: string; code?: string }> = [];
    const warnings: Array<{ message: string; code?: string }> = [];

    // Basic validation
    if (!parsed.resources || parsed.resources.length === 0) {
      warnings.push({ message: 'No resources found in parsed infrastructure' });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Extract resources from parsed infrastructure
   * Required by IaCParser interface
   */
  extractResources(parsed: ParsedInfrastructure): Resource[] {
    return parsed.resources;
  }

  /**
   * Convert internal ParsedResource to Resource interface
   */
  private toResource(pr: ParsedResource): Resource {
    return {
      id: `${pr.type}.${pr.name}`,
      type: pr.type,
      service: this.getServiceFromType(pr.type),
      region: 'unknown',
      account: 'unknown',
      properties: pr.config,
      tags: (pr.config.tags as Record<string, string>) || {},
      relationships: [],
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };
  }

  /**
   * Extract service name from resource type
   */
  private getServiceFromType(resourceType: string): string {
    const serviceMap: Record<string, string> = {
      aws_s3_bucket: 's3',
      aws_iam_policy: 'iam',
      aws_iam_role_policy: 'iam',
      aws_iam_user_policy: 'iam',
      aws_iam_group_policy: 'iam',
      aws_security_group: 'ec2',
      aws_security_group_rule: 'ec2',
      aws_ebs_volume: 'ec2',
      aws_instance: 'ec2',
      aws_cloudtrail: 'cloudtrail',
      aws_db_instance: 'rds',
      aws_rds_cluster: 'rds',
      aws_eks_cluster: 'eks',
    };
    return serviceMap[resourceType] || 'aws';
  }

  /**
   * Extract variables from parsed HCL
   */
  private extractVariables(parsed: HCLParseResult): Array<{ name: string; type: string; defaultValue?: unknown; description?: string }> {
    const variables: Array<{ name: string; type: string; defaultValue?: unknown; description?: string }> = [];

    if (parsed.variable) {
      for (const [name, config] of Object.entries(parsed.variable)) {
        const varConfig = config as Record<string, unknown>;
        variables.push({
          name,
          type: (varConfig.type as string) || 'any',
          defaultValue: varConfig.default,
          description: varConfig.description as string | undefined,
        });
      }
    }

    return variables;
  }

  /**
   * Extract outputs from parsed HCL
   */
  private extractOutputs(parsed: HCLParseResult): Array<{ name: string; value: unknown; description?: string }> {
    const outputs: Array<{ name: string; value: unknown; description?: string }> = [];

    if (parsed.output) {
      for (const [name, config] of Object.entries(parsed.output)) {
        const outConfig = config as Record<string, unknown>;
        outputs.push({
          name,
          value: outConfig.value,
          description: outConfig.description as string | undefined,
        });
      }
    }

    return outputs;
  }

  /**
   * Scan a directory for Terraform files and run security checks
   */
  async scanDirectory(dirPath: string): Promise<TerraformScanResult> {
    const findings: Finding[] = [];
    const errors: Array<{ file: string; error: string }> = [];
    let resourceCount = 0;

    // Find all .tf files recursively
    const tfFiles = await this.findTerraformFiles(dirPath);

    for (const filePath of tfFiles) {
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const parsed = await this.parseHCLContent(filePath, content);
        const resources = this.extractResourcesFromHCL(parsed, content, filePath);

        resourceCount += resources.length;

        // Run all rule checks against each resource
        for (const resource of resources) {
          for (const [, checkFn] of this.ruleChecks) {
            const finding = checkFn(
              resource.type,
              resource.name,
              resource.config,
              resource.rawBlock,
              resource.filePath
            );
            if (finding) {
              findings.push(finding);
            }
          }
        }
      } catch (error) {
        errors.push({
          file: filePath,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return {
      findings,
      resourceCount,
      fileCount: tfFiles.length,
      errors,
    };
  }

  /**
   * Find all .tf files in a directory recursively
   */
  private async findTerraformFiles(dirPath: string): Promise<string[]> {
    const files: string[] = [];

    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        // Skip node_modules and hidden directories
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
          const subFiles = await this.findTerraformFiles(fullPath);
          files.push(...subFiles);
        }
      } else if (entry.isFile() && entry.name.endsWith('.tf')) {
        files.push(fullPath);
      }
    }

    return files;
  }

  /**
   * Parse HCL content using @cdktf/hcl2json
   */
  private async parseHCLContent(filePath: string, content: string): Promise<HCLParseResult> {
    return parseHCL(filePath, content) as Promise<HCLParseResult>;
  }

  /**
   * Extract resources from parsed HCL (internal method)
   */
  private extractResourcesFromHCL(
    parsed: HCLParseResult,
    originalContent: string,
    filePath: string
  ): ParsedResource[] {
    const resources: ParsedResource[] = [];

    if (!parsed.resource) {
      return resources;
    }

    for (const [resourceType, instances] of Object.entries(parsed.resource)) {
      for (const [resourceName, configs] of Object.entries(instances)) {
        // configs is an array, usually with one element
        const config = configs[0] || {};

        // Extract raw block from original content
        const rawBlock = this.extractRawBlock(originalContent, resourceType, resourceName);

        resources.push({
          type: resourceType,
          name: resourceName,
          config: config as Record<string, unknown>,
          rawBlock,
          filePath,
        });
      }
    }

    return resources;
  }

  /**
   * Extract raw HCL block for a resource from original content
   */
  private extractRawBlock(content: string, resourceType: string, resourceName: string): string {
    // Match resource block with proper brace balancing
    const resourcePattern = new RegExp(
      `resource\\s+"${resourceType}"\\s+"${resourceName}"\\s*\\{`,
      'g'
    );

    const match = resourcePattern.exec(content);
    if (!match) {
      return '';
    }

    const startIndex = match.index;
    let braceCount = 0;
    let endIndex = startIndex;
    let inString = false;
    let stringChar = '';

    for (let i = match.index + match[0].length - 1; i < content.length; i++) {
      const char = content[i];
      const prevChar = i > 0 ? content[i - 1] : '';

      // Handle string literals
      if ((char === '"' || char === "'") && prevChar !== '\\') {
        if (!inString) {
          inString = true;
          stringChar = char;
        } else if (char === stringChar) {
          inString = false;
        }
      }

      if (!inString) {
        if (char === '{') braceCount++;
        if (char === '}') braceCount--;

        if (braceCount === 0) {
          endIndex = i + 1;
          break;
        }
      }
    }

    return content.substring(startIndex, endIndex);
  }

  /**
   * Create a Finding object from rule violation
   */
  private createFinding(
    ruleId: string,
    title: string,
    description: string,
    severity: Severity,
    resourceType: string,
    resourceName: string,
    rawBlock: string,
    filePath: string
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
      id: `${resourceType}.${resourceName}`,
      location: {
        file: filePath,
        startLine: 0, // Could be computed from rawBlock position
        endLine: 0,
      },
    };

    return {
      id: uuidv4(),
      title,
      description,
      severity,
      resource,
      source: 'static',
      provider: 'terraform',
      rawBlock,
      frameworks,
      mitre,
      detectedAt: new Date(),
    };
  }

  // =========================================================================
  // Security Rule Check Functions
  // =========================================================================

  /**
   * S3_PUBLIC_ACL: Check for S3 bucket with public ACL
   */
  private checkS3PublicAcl(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_s3_bucket') return null;

    const acl = config.acl as string | undefined;
    const publicAcls = ['public-read', 'public-read-write', 'authenticated-read'];

    if (acl && publicAcls.includes(acl)) {
      return this.createFinding(
        'S3_PUBLIC_ACL',
        'S3 bucket allows public ACL',
        `S3 bucket "${resourceName}" has ACL set to "${acl}" which allows public access. This can expose sensitive data to the internet.`,
        'CRITICAL',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * S3_NO_ENCRYPTION: Check for S3 bucket missing encryption
   */
  private checkS3Encryption(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_s3_bucket') return null;

    // Check for server_side_encryption_configuration block
    const encryption = config.server_side_encryption_configuration as unknown[] | undefined;

    if (!encryption || encryption.length === 0) {
      return this.createFinding(
        'S3_NO_ENCRYPTION',
        'S3 bucket missing server-side encryption',
        `S3 bucket "${resourceName}" does not have server-side encryption configured. Data at rest should be encrypted.`,
        'HIGH',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * S3_NO_VERSIONING: Check for S3 bucket missing versioning
   */
  private checkS3Versioning(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_s3_bucket') return null;

    // Check for versioning block
    const versioning = config.versioning as Array<Record<string, unknown>> | undefined;
    const enabled = versioning?.[0]?.enabled;

    if (!versioning || enabled !== true) {
      return this.createFinding(
        'S3_NO_VERSIONING',
        'S3 bucket versioning not enabled',
        `S3 bucket "${resourceName}" does not have versioning enabled. Versioning protects against accidental deletion and enables recovery.`,
        'MEDIUM',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * IAM_WILDCARD_ACTION: Check for IAM policy with wildcard actions
   */
  private checkIamWildcard(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    const iamPolicyTypes = ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy'];
    if (!iamPolicyTypes.includes(resourceType)) return null;

    // Get policy document
    let policyDoc: string | Record<string, unknown> | undefined = config.policy as string | Record<string, unknown> | undefined;

    if (typeof policyDoc === 'string') {
      try {
        policyDoc = JSON.parse(policyDoc);
      } catch {
        // Check raw block for wildcards if JSON parse fails
        if (rawBlock.includes('"Action"') && rawBlock.includes('"*"')) {
          return this.createFinding(
            'IAM_WILDCARD_ACTION',
            'IAM policy contains wildcard actions',
            `IAM policy "${resourceName}" appears to contain wildcard (*) actions. This violates the principle of least privilege.`,
            'CRITICAL',
            resourceType,
            resourceName,
            rawBlock,
            filePath
          );
        }
        return null;
      }
    }

    if (typeof policyDoc === 'object' && policyDoc !== null) {
      const statements = (policyDoc as Record<string, unknown>).Statement as Array<Record<string, unknown>> | undefined;

      if (statements) {
        for (const stmt of statements) {
          if (stmt.Effect === 'Allow') {
            const action = stmt.Action;
            if (action === '*' || (Array.isArray(action) && action.includes('*'))) {
              return this.createFinding(
                'IAM_WILDCARD_ACTION',
                'IAM policy contains wildcard actions',
                `IAM policy "${resourceName}" grants Action: "*" which provides full access to all AWS services. Use specific actions instead.`,
                'CRITICAL',
                resourceType,
                resourceName,
                rawBlock,
                filePath
              );
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * EC2_SG_OPEN_SSH: Check for security group with SSH open to 0.0.0.0/0
   */
  private checkSgOpenSsh(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_security_group' && resourceType !== 'aws_security_group_rule') return null;

    return this.checkOpenPort(resourceType, resourceName, config, rawBlock, filePath, 22, 'SSH', 'EC2_SG_OPEN_SSH');
  }

  /**
   * EC2_SG_OPEN_RDP: Check for security group with RDP open to 0.0.0.0/0
   */
  private checkSgOpenRdp(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_security_group' && resourceType !== 'aws_security_group_rule') return null;

    return this.checkOpenPort(resourceType, resourceName, config, rawBlock, filePath, 3389, 'RDP', 'EC2_SG_OPEN_RDP');
  }

  /**
   * Helper: Check for open port in security group
   */
  private checkOpenPort(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string,
    port: number,
    portName: string,
    ruleId: string
  ): Finding | null {
    // For aws_security_group_rule
    if (resourceType === 'aws_security_group_rule') {
      const type = config.type as string | undefined;
      if (type !== 'ingress') return null;

      const fromPort = config.from_port as number | undefined;
      const toPort = config.to_port as number | undefined;
      const cidrBlocks = config.cidr_blocks as string[] | undefined;

      if (this.portInRange(port, fromPort, toPort) && this.hasOpenCidr(cidrBlocks)) {
        return this.createFinding(
          ruleId,
          `Security group allows ${portName} from 0.0.0.0/0`,
          `Security group rule "${resourceName}" allows ${portName} (port ${port}) from 0.0.0.0/0. This exposes the service to the internet.`,
          'CRITICAL',
          resourceType,
          resourceName,
          rawBlock,
          filePath
        );
      }
    }

    // For aws_security_group with inline ingress
    if (resourceType === 'aws_security_group') {
      const ingress = config.ingress as Array<Record<string, unknown>> | undefined;

      if (ingress) {
        for (const rule of ingress) {
          const fromPort = rule.from_port as number | undefined;
          const toPort = rule.to_port as number | undefined;
          const cidrBlocks = rule.cidr_blocks as string[] | undefined;

          if (this.portInRange(port, fromPort, toPort) && this.hasOpenCidr(cidrBlocks)) {
            return this.createFinding(
              ruleId,
              `Security group allows ${portName} from 0.0.0.0/0`,
              `Security group "${resourceName}" allows ${portName} (port ${port}) ingress from 0.0.0.0/0. This exposes the service to the internet.`,
              'CRITICAL',
              resourceType,
              resourceName,
              rawBlock,
              filePath
            );
          }
        }
      }
    }

    return null;
  }

  private portInRange(port: number, from?: number, to?: number): boolean {
    if (from === undefined || to === undefined) return false;
    return port >= from && port <= to;
  }

  private hasOpenCidr(cidrBlocks?: string[]): boolean {
    if (!cidrBlocks) return false;
    return cidrBlocks.includes('0.0.0.0/0') || cidrBlocks.includes('::/0');
  }

  /**
   * EC2_UNENCRYPTED_EBS: Check for unencrypted EBS volumes
   */
  private checkEbsEncryption(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType === 'aws_ebs_volume') {
      if (config.encrypted !== true) {
        return this.createFinding(
          'EC2_UNENCRYPTED_EBS',
          'EBS volume not encrypted',
          `EBS volume "${resourceName}" does not have encryption enabled. Enable encryption to protect data at rest.`,
          'HIGH',
          resourceType,
          resourceName,
          rawBlock,
          filePath
        );
      }
    }

    if (resourceType === 'aws_instance') {
      const ebsBlockDevices = config.ebs_block_device as Array<Record<string, unknown>> | undefined;

      if (ebsBlockDevices) {
        for (const device of ebsBlockDevices) {
          if (device.encrypted !== true) {
            return this.createFinding(
              'EC2_UNENCRYPTED_EBS',
              'EC2 instance has unencrypted EBS volume',
              `EC2 instance "${resourceName}" has an EBS block device without encryption enabled.`,
              'HIGH',
              resourceType,
              resourceName,
              rawBlock,
              filePath
            );
          }
        }
      }

      // Check root_block_device
      const rootBlockDevice = config.root_block_device as Array<Record<string, unknown>> | undefined;
      if (rootBlockDevice?.[0]?.encrypted === false) {
        return this.createFinding(
          'EC2_UNENCRYPTED_EBS',
          'EC2 instance has unencrypted root volume',
          `EC2 instance "${resourceName}" has an unencrypted root block device.`,
          'HIGH',
          resourceType,
          resourceName,
          rawBlock,
          filePath
        );
      }
    }

    return null;
  }

  /**
   * CLOUDTRAIL_NOT_ENABLED: Check for CloudTrail with logging disabled
   */
  private checkCloudtrailEnabled(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_cloudtrail') return null;

    // Check if logging is explicitly disabled
    if (config.enable_logging === false) {
      return this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail logging is disabled',
        `CloudTrail "${resourceName}" has enable_logging set to false. CloudTrail should be enabled for audit logging.`,
        'CRITICAL',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    // Check for log file validation
    if (config.enable_log_file_validation === false) {
      return this.createFinding(
        'CLOUDTRAIL_NOT_ENABLED',
        'CloudTrail log file validation disabled',
        `CloudTrail "${resourceName}" has log file validation disabled. Enable it to detect log tampering.`,
        'HIGH',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * RDS_PUBLICLY_ACCESSIBLE: Check for RDS instance that is publicly accessible
   */
  private checkRdsPublic(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_db_instance' && resourceType !== 'aws_rds_cluster') return null;

    if (config.publicly_accessible === true) {
      return this.createFinding(
        'RDS_PUBLICLY_ACCESSIBLE',
        'RDS instance is publicly accessible',
        `RDS instance "${resourceName}" is publicly accessible. Databases should be in private subnets.`,
        'CRITICAL',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * RDS_NO_ENCRYPTION: Check for RDS instance without storage encryption
   */
  private checkRdsEncryption(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_db_instance' && resourceType !== 'aws_rds_cluster') return null;

    if (config.storage_encrypted !== true) {
      return this.createFinding(
        'RDS_NO_ENCRYPTION',
        'RDS instance storage not encrypted',
        `RDS instance "${resourceName}" does not have storage encryption enabled. Enable encryption to protect data at rest.`,
        'HIGH',
        resourceType,
        resourceName,
        rawBlock,
        filePath
      );
    }

    return null;
  }

  /**
   * EKS_PUBLIC_ENDPOINT: Check for EKS cluster with public endpoint only
   */
  private checkEksPublicEndpoint(
    resourceType: string,
    resourceName: string,
    config: Record<string, unknown>,
    rawBlock: string,
    filePath: string
  ): Finding | null {
    if (resourceType !== 'aws_eks_cluster') return null;

    const vpcConfig = config.vpc_config as Array<Record<string, unknown>> | undefined;

    if (vpcConfig && vpcConfig[0]) {
      const endpointPublicAccess = vpcConfig[0].endpoint_public_access;
      const endpointPrivateAccess = vpcConfig[0].endpoint_private_access;

      // Flag if public access is enabled AND private access is disabled
      if (endpointPublicAccess === true && endpointPrivateAccess === false) {
        return this.createFinding(
          'EKS_PUBLIC_ENDPOINT',
          'EKS cluster API endpoint is publicly accessible',
          `EKS cluster "${resourceName}" has public endpoint access enabled with private access disabled. Enable private endpoint access.`,
          'HIGH',
          resourceType,
          resourceName,
          rawBlock,
          filePath
        );
      }
    }

    return null;
  }
}

// Export a singleton for convenience
export const terraformParser = new TerraformParser();
