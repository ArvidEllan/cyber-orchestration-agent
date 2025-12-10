/**
 * Encryption and Data Protection Rules Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleLoader } from '../rule-loader';
import { RulesEngine } from '../rules-engine';
import { Resource, ResourceSource, Severity, Category } from '../../types';

describe('Encryption and Data Protection Rules', () => {
  let engine: RulesEngine;

  beforeEach(async () => {
    const loader = new RuleLoader();
    engine = new RulesEngine();
    const ruleSet = await loader.loadBuiltInRules(Category.ENCRYPTION);
    engine.loadRules(ruleSet);
  });

  it('should detect S3 buckets without encryption', () => {
    const resource: Resource = {
      id: 'bucket-123',
      type: 'aws_s3_bucket',
      service: 's3',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        name: 'my-bucket',
      },
      tags: {},
      relationships: [],
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const finding = findings.find((f) => f.ruleId === 'ENC-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.HIGH);
  });

  it('should detect RDS databases without encryption', () => {
    const resource: Resource = {
      id: 'db-123',
      type: 'aws_db_instance',
      service: 'rds',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        engine: 'postgres',
        storageEncrypted: false,
      },
      tags: {},
      relationships: [],
      source: ResourceSource.LIVE,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const finding = findings.find((f) => f.ruleId === 'ENC-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.HIGH);
  });

  it('should detect public S3 bucket access', () => {
    const resource: Resource = {
      id: 'bucket-456',
      type: 'aws_s3_bucket',
      service: 's3',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        name: 'public-bucket',
        acl: 'public-read',
      },
      tags: {},
      relationships: [],
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const finding = findings.find((f) => f.ruleId === 'ENC-005');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.CRITICAL);
  });

  it('should detect EBS volumes without encryption', () => {
    const resource: Resource = {
      id: 'vol-123',
      type: 'aws_ebs_volume',
      service: 'ec2',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        size: 100,
        encrypted: false,
      },
      tags: {},
      relationships: [],
      source: ResourceSource.LIVE,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const finding = findings.find((f) => f.ruleId === 'ENC-006');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.HIGH);
  });

  it('should not flag encrypted resources', () => {
    const resource: Resource = {
      id: 'db-secure',
      type: 'aws_db_instance',
      service: 'rds',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        engine: 'postgres',
        storageEncrypted: true,
        kmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/12345',
      },
      tags: {},
      relationships: [],
      source: ResourceSource.LIVE,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const encryptionFinding = findings.find((f) => f.ruleId === 'ENC-002');
    expect(encryptionFinding).toBeUndefined();
  });
});
