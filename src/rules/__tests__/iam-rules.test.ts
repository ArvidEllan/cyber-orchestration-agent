/**
 * IAM Rules Tests
 * Tests for IAM security rules
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleLoader } from '../rule-loader';
import { RulesEngine } from '../rules-engine';
import { Resource, ResourceSource, Severity, Category } from '../../types';
import * as path from 'path';

describe('IAM Security Rules', () => {
  let loader: RuleLoader;
  let engine: RulesEngine;

  beforeEach(async () => {
    loader = new RuleLoader();
    engine = new RulesEngine();
    
    // Load IAM rules
    const ruleSet = await loader.loadBuiltInRules(Category.IAM);
    engine.loadRules(ruleSet);
  });

  describe('Rule Loading', () => {
    it('should load IAM rules from YAML file', async () => {
      const rules = engine.getRules();
      expect(rules.length).toBeGreaterThan(0);
    });

    it('should load IAM-001: Wildcard IAM Policy Actions', () => {
      const rule = engine.getRule('IAM-001');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Wildcard IAM Policy Actions');
      expect(rule?.severity).toBe(Severity.CRITICAL);
    });

    it('should load IAM-002: Missing MFA for IAM Users', () => {
      const rule = engine.getRule('IAM-002');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Missing MFA for IAM Users');
      expect(rule?.severity).toBe(Severity.HIGH);
    });

    it('should load IAM-003: Overly Permissive IAM Role Trust Policy', () => {
      const rule = engine.getRule('IAM-003');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Overly Permissive IAM Role Trust Policy');
      expect(rule?.severity).toBe(Severity.CRITICAL);
    });

    it('should load IAM-004: IAM Access Keys Older Than 90 Days', () => {
      const rule = engine.getRule('IAM-004');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('IAM Access Keys Older Than 90 Days');
      expect(rule?.severity).toBe(Severity.HIGH);
    });

    it('should load IAM-005: Root Account Usage Detected', () => {
      const rule = engine.getRule('IAM-005');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Root Account Usage Detected');
      expect(rule?.severity).toBe(Severity.CRITICAL);
    });
  });

  describe('Rule Evaluation', () => {
    it('should detect wildcard IAM policy actions', () => {
      const resource: Resource = {
        id: 'policy-123',
        type: 'aws_iam_policy',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
              },
            ],
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const wildcardFinding = findings.find((f) => f.ruleId === 'IAM-001');
      expect(wildcardFinding).toBeDefined();
      expect(wildcardFinding?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect IAM users without MFA', () => {
      const resource: Resource = {
        id: 'user-123',
        type: 'aws_iam_user',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          passwordEnabled: true,
          mfaEnabled: false,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const mfaFinding = findings.find((f) => f.ruleId === 'IAM-002');
      expect(mfaFinding).toBeDefined();
      expect(mfaFinding?.severity).toBe(Severity.HIGH);
    });

    it('should detect overly permissive IAM role trust policies', () => {
      const resource: Resource = {
        id: 'role-123',
        type: 'aws_iam_role',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          assumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'sts:AssumeRole',
              },
            ],
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const trustPolicyFinding = findings.find((f) => f.ruleId === 'IAM-003');
      expect(trustPolicyFinding).toBeDefined();
      expect(trustPolicyFinding?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect IAM access keys older than 90 days', () => {
      const resource: Resource = {
        id: 'access-key-123',
        type: 'aws_iam_access_key',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          ageInDays: 120,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const accessKeyFinding = findings.find((f) => f.ruleId === 'IAM-004');
      expect(accessKeyFinding).toBeDefined();
      expect(accessKeyFinding?.severity).toBe(Severity.HIGH);
    });

    it('should detect root account usage', () => {
      const resource: Resource = {
        id: 'root-account',
        type: 'aws_root_account_activity',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          recentActivity: true,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const rootAccountFinding = findings.find((f) => f.ruleId === 'IAM-005');
      expect(rootAccountFinding).toBeDefined();
      expect(rootAccountFinding?.severity).toBe(Severity.CRITICAL);
    });

    it('should not flag IAM policies with specific actions', () => {
      const resource: Resource = {
        id: 'policy-456',
        type: 'aws_iam_policy',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          document: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['s3:GetObject', 's3:PutObject'],
                Resource: 'arn:aws:s3:::my-bucket/*',
              },
            ],
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const wildcardFinding = findings.find((f) => f.ruleId === 'IAM-001');
      expect(wildcardFinding).toBeUndefined();
    });
  });
});
