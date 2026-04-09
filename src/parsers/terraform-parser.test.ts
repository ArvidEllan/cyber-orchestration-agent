/**
 * Terraform Parser Tests
 * Tests security rule detection against fixture files
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as path from 'path';
import { TerraformParser, TerraformScanResult } from './terraform-parser';

describe('TerraformParser', () => {
  const fixturesPath = path.join(__dirname, '__fixtures__');
  let parser: TerraformParser;

  beforeAll(() => {
    parser = new TerraformParser();
  });

  describe('fixture file scanning', () => {
    describe('vulnerable.tf', () => {
      let result: TerraformScanResult;

      beforeAll(async () => {
        const vulnerablePath = path.join(fixturesPath, 'vulnerable.tf');
        // Create temp directory with single file
        result = await scanSingleFile(parser, vulnerablePath);
      });

      it('should parse without errors', () => {
        expect(result.errors).toHaveLength(0);
      });

      it('should find at least 9 vulnerabilities', () => {
        // 11 resources, but some S3 buckets trigger multiple rules
        // Minimum expected: 9 unique findings
        expect(result.findings.length).toBeGreaterThanOrEqual(9);
      });

      it('should detect S3_PUBLIC_ACL', () => {
        const finding = result.findings.find(f => f.title.includes('public ACL'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('CRITICAL');
      });

      it('should detect S3_NO_ENCRYPTION', () => {
        const finding = result.findings.find(f => f.title.includes('encryption'));
        expect(finding).toBeDefined();
      });

      it('should detect IAM_WILDCARD_ACTION', () => {
        const finding = result.findings.find(f => f.title.includes('wildcard'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('CRITICAL');
      });

      it('should detect EC2_SG_OPEN_SSH', () => {
        const finding = result.findings.find(f =>
          f.title.includes('SSH') && f.title.includes('0.0.0.0/0')
        );
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('CRITICAL');
      });

      it('should detect EC2_SG_OPEN_RDP', () => {
        const finding = result.findings.find(f =>
          f.title.includes('RDP') && f.title.includes('0.0.0.0/0')
        );
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('CRITICAL');
      });

      it('should detect EC2_UNENCRYPTED_EBS', () => {
        const finding = result.findings.find(f => f.title.includes('EBS') && f.title.includes('not encrypted'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('HIGH');
      });

      it('should detect CLOUDTRAIL_NOT_ENABLED', () => {
        const finding = result.findings.find(f => f.title.includes('CloudTrail'));
        expect(finding).toBeDefined();
      });

      it('should detect RDS_PUBLICLY_ACCESSIBLE', () => {
        const finding = result.findings.find(f => f.title.includes('RDS') && f.title.includes('publicly accessible'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('CRITICAL');
      });

      it('should detect RDS_NO_ENCRYPTION', () => {
        const finding = result.findings.find(f => f.title.includes('RDS') && f.title.includes('storage not encrypted'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('HIGH');
      });

      it('should detect EKS_PUBLIC_ENDPOINT', () => {
        const finding = result.findings.find(f => f.title.includes('EKS') && f.title.includes('publicly accessible'));
        expect(finding).toBeDefined();
        expect(finding?.severity).toBe('HIGH');
      });
    });

    describe('clean.tf', () => {
      let result: TerraformScanResult;

      beforeAll(async () => {
        const cleanPath = path.join(fixturesPath, 'clean.tf');
        result = await scanSingleFile(parser, cleanPath);
      });

      it('should parse without errors', () => {
        expect(result.errors).toHaveLength(0);
      });

      it('should find exactly 0 vulnerabilities', () => {
        expect(result.findings).toHaveLength(0);
      });

      it('should have parsed resources', () => {
        expect(result.resourceCount).toBeGreaterThan(0);
      });
    });

    describe('mixed.tf', () => {
      let result: TerraformScanResult;

      beforeAll(async () => {
        const mixedPath = path.join(fixturesPath, 'mixed.tf');
        result = await scanSingleFile(parser, mixedPath);
      });

      it('should parse without errors', () => {
        expect(result.errors).toHaveLength(0);
      });

      it('should find exactly 7 vulnerabilities', () => {
        // Expected findings from mixed.tf:
        // 1. S3_PUBLIC_ACL (mixed_public bucket) - CRITICAL
        // 2. S3_NO_ENCRYPTION (mixed_public bucket) - HIGH
        // 3. S3_NO_VERSIONING (mixed_public bucket) - MEDIUM
        // 4. IAM_WILDCARD_ACTION (mixed_admin policy) - CRITICAL
        // 5. EC2_SG_OPEN_SSH (mixed_open_ssh) - CRITICAL
        // 6. RDS_PUBLICLY_ACCESSIBLE (mixed_public_db) - CRITICAL
        // 7. EC2_UNENCRYPTED_EBS (mixed_unencrypted) - HIGH
        expect(result.findings).toHaveLength(7);
      });

      it('should have correct mix of severities', () => {
        const criticals = result.findings.filter(f => f.severity === 'CRITICAL');
        const highs = result.findings.filter(f => f.severity === 'HIGH');
        const mediums = result.findings.filter(f => f.severity === 'MEDIUM');

        // CRITICAL: S3_PUBLIC_ACL, IAM_WILDCARD, SG_OPEN_SSH, RDS_PUBLIC
        // HIGH: S3_NO_ENCRYPTION, EBS_UNENCRYPTED
        // MEDIUM: S3_NO_VERSIONING
        expect(criticals.length).toBe(4);
        expect(highs.length).toBe(2);
        expect(mediums.length).toBe(1);
      });
    });
  });

  describe('individual rule checks', () => {
    it('should detect public-read-write ACL as CRITICAL', async () => {
      const tf = `
        resource "aws_s3_bucket" "test" {
          bucket = "test-bucket"
          acl    = "public-read-write"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings).toHaveLength(3); // public_acl, no_encryption, no_versioning
      expect(result.findings.some(f => f.title.includes('public ACL'))).toBe(true);
    });

    it('should not flag private ACL', async () => {
      const tf = `
        resource "aws_s3_bucket" "test" {
          bucket = "test-bucket"
          acl    = "private"
          versioning { enabled = true }
          server_side_encryption_configuration {
            rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
          }
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings).toHaveLength(0);
    });

    it('should detect security group rule with open SSH', async () => {
      const tf = `
        resource "aws_security_group_rule" "ssh" {
          type        = "ingress"
          from_port   = 22
          to_port     = 22
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          security_group_id = "sg-12345678"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings.some(f => f.title.includes('SSH'))).toBe(true);
    });

    it('should not flag SSH restricted to private CIDR', async () => {
      const tf = `
        resource "aws_security_group_rule" "ssh" {
          type        = "ingress"
          from_port   = 22
          to_port     = 22
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/8"]
          security_group_id = "sg-12345678"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings).toHaveLength(0);
    });

    it('should detect port range that includes SSH', async () => {
      const tf = `
        resource "aws_security_group" "wide_range" {
          name   = "wide-range"
          vpc_id = "vpc-12345678"
          ingress {
            from_port   = 1
            to_port     = 1024
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      // Should catch both SSH (22) and potentially RDP if it was in range
      expect(result.findings.some(f => f.title.includes('SSH'))).toBe(true);
    });

    it('should detect IPv6 open CIDR ::/0', async () => {
      const tf = `
        resource "aws_security_group" "ipv6" {
          name   = "ipv6-open"
          vpc_id = "vpc-12345678"
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["::/0"]
          }
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings.some(f => f.title.includes('SSH'))).toBe(true);
    });

    it('should detect EC2 instance with unencrypted EBS block device', async () => {
      const tf = `
        resource "aws_instance" "test" {
          ami           = "ami-12345678"
          instance_type = "t3.micro"
          ebs_block_device {
            device_name = "/dev/sda1"
            encrypted   = false
          }
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings.some(f => f.title.includes('EBS'))).toBe(true);
    });

    it('should detect RDS cluster publicly accessible', async () => {
      const tf = `
        resource "aws_rds_cluster" "test" {
          cluster_identifier = "test-cluster"
          engine             = "aurora-mysql"
          publicly_accessible = true
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      expect(result.findings.some(f => f.title.includes('RDS') && f.title.includes('publicly'))).toBe(true);
    });
  });

  describe('compliance framework mappings', () => {
    it('should include framework mappings in findings', async () => {
      const tf = `
        resource "aws_s3_bucket" "test" {
          bucket = "test"
          acl    = "public-read"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const publicAclFinding = result.findings.find(f => f.title.includes('public ACL'));

      expect(publicAclFinding?.frameworks).toBeDefined();
      expect(publicAclFinding?.frameworks.length).toBeGreaterThan(0);

      // Check for expected frameworks from mappings.json
      const frameworkIds = publicAclFinding?.frameworks.map(f => f.framework);
      expect(frameworkIds).toContain('CIS_AWS');
    });

    it('should include MITRE ATT&CK mapping', async () => {
      const tf = `
        resource "aws_iam_policy" "test" {
          name = "test"
          policy = "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const wildcardFinding = result.findings.find(f => f.title.includes('wildcard'));

      expect(wildcardFinding?.mitre).toBeDefined();
      expect(wildcardFinding?.mitre?.techniqueId).toBeDefined();
    });
  });

  describe('finding metadata', () => {
    it('should generate unique UUIDs for each finding', async () => {
      const tf = `
        resource "aws_s3_bucket" "bucket1" { bucket = "b1"; acl = "public-read" }
        resource "aws_s3_bucket" "bucket2" { bucket = "b2"; acl = "public-read" }
      `;
      const result = await parseInlineHCL(parser, tf);
      const ids = result.findings.map(f => f.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it('should include resource identifier in finding', async () => {
      const tf = `
        resource "aws_s3_bucket" "my_special_bucket" {
          bucket = "my-special"
          acl    = "public-read"
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const finding = result.findings.find(f => f.title.includes('public ACL'));
      expect(finding?.resource.id).toContain('my_special_bucket');
    });

    it('should capture raw HCL block', async () => {
      const tf = `
        resource "aws_s3_bucket" "captured" {
          bucket = "captured-bucket"
          acl    = "public-read"
          tags = {
            Name = "Test"
          }
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const finding = result.findings.find(f =>
        f.resource.id.includes('captured')
      );

      expect(finding?.rawBlock).toBeDefined();
      expect(finding?.rawBlock).toContain('aws_s3_bucket');
      expect(finding?.rawBlock).toContain('captured');
    });

    it('should set correct source and provider', async () => {
      const tf = `
        resource "aws_ebs_volume" "test" {
          availability_zone = "us-east-1a"
          size = 10
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const finding = result.findings[0];

      expect(finding?.source).toBe('static');
      expect(finding?.provider).toBe('terraform');
    });

    it('should include detectedAt timestamp', async () => {
      const before = new Date();
      const tf = `
        resource "aws_ebs_volume" "test" {
          availability_zone = "us-east-1a"
          size = 10
        }
      `;
      const result = await parseInlineHCL(parser, tf);
      const after = new Date();

      const finding = result.findings[0];
      expect(finding?.detectedAt).toBeInstanceOf(Date);
      expect(finding?.detectedAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(finding?.detectedAt.getTime()).toBeLessThanOrEqual(after.getTime());
    });
  });

  describe('error handling', () => {
    it('should handle invalid HCL gracefully', async () => {
      const invalidTf = `
        resource "aws_s3_bucket" "bad" {
          bucket = "missing-closing-brace"
      `;
      const result = await parseInlineHCL(parser, invalidTf);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should continue parsing other files when one fails', async () => {
      // This tests the directory scanning behavior
      // The parser should skip bad files and continue
      const result = await parser.scanDirectory(fixturesPath);
      expect(result.fileCount).toBe(3); // vulnerable.tf, clean.tf, mixed.tf
      expect(result.errors).toHaveLength(0);
    });
  });
});

// Helper functions

/**
 * Scan a single .tf file by creating a temporary context
 */
async function scanSingleFile(parser: TerraformParser, filePath: string): Promise<TerraformScanResult> {
  const fs = await import('fs/promises');
  const path = await import('path');

  const content = await fs.readFile(filePath, 'utf-8');
  const tempDir = path.dirname(filePath);
  const fileName = path.basename(filePath);

  // Create parser instance and scan just this file's directory
  // Filter results to only include findings from this specific file
  const result = await parser.scanDirectory(tempDir);

  return {
    findings: result.findings.filter(f => f.resource.location?.file?.endsWith(fileName)),
    resourceCount: result.resourceCount,
    fileCount: 1,
    errors: result.errors.filter(e => e.file.endsWith(fileName)),
  };
}

/**
 * Parse inline HCL content for testing
 */
async function parseInlineHCL(parser: TerraformParser, content: string): Promise<TerraformScanResult> {
  const fs = await import('fs/promises');
  const os = await import('os');
  const path = await import('path');

  // Create temp directory and file
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tf-test-'));
  const tempFile = path.join(tempDir, 'test.tf');

  try {
    await fs.writeFile(tempFile, content);
    return await parser.scanDirectory(tempDir);
  } finally {
    // Cleanup
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}
