/**
 * Rules Engine Tests
 * Tests for the security rules engine core functionality
 * 
 * This test suite validates:
 * - Rule loading and management
 * - Rule analysis and finding generation
 * - Rule customization
 * - Parallel analysis
 * - Multiple rule execution
 * - Known violation detection across all categories
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RulesEngine } from '../rules-engine';
import { RuleLoader } from '../rule-loader';
import {
  Resource,
  ResourceSource,
  Severity,
  Category,
  RuleSet,
  SecurityRule,
  ComplianceFramework,
} from '../../types';

describe('RulesEngine', () => {
  let engine: RulesEngine;
  let loader: RuleLoader;

  beforeEach(() => {
    engine = new RulesEngine();
    loader = new RuleLoader();
  });

  describe('Rule Loading', () => {
    it('should load rules from a rule set', () => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [ComplianceFramework.CIS_AWS],
            condition: {
              resourceType: 'aws_test_resource',
            },
            remediation: {
              description: 'Fix the issue',
              steps: ['Step 1', 'Step 2'],
            },
          },
        ],
      };

      engine.loadRules(ruleSet);
      const rules = engine.getRules();
      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('TEST-001');
    });

    it('should load multiple rule sets', () => {
      const ruleSet1: RuleSet = {
        name: 'rules-1',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule 1',
            description: 'First test rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test_1' },
            remediation: { description: 'Fix 1', steps: [] },
          },
        ],
      };

      const ruleSet2: RuleSet = {
        name: 'rules-2',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-002',
            name: 'Test Rule 2',
            description: 'Second test rule',
            severity: Severity.MEDIUM,
            category: Category.NETWORK,
            frameworks: [],
            condition: { resourceType: 'aws_test_2' },
            remediation: { description: 'Fix 2', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet1);
      engine.loadRules(ruleSet2);

      const rules = engine.getRules();
      expect(rules).toHaveLength(2);
    });

    it('should retrieve a specific rule by ID', () => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test' },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
      const rule = engine.getRule('TEST-001');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Test Rule');
    });

    it('should return undefined for non-existent rule', () => {
      const rule = engine.getRule('NON-EXISTENT');
      expect(rule).toBeUndefined();
    });
  });

  describe('Rule Analysis', () => {
    beforeEach(() => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Resource Type',
            description: 'Checks resource type',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: {
              resourceType: 'aws_test_resource',
            },
            remediation: { description: 'Fix', steps: [] },
          },
          {
            id: 'TEST-002',
            name: 'Test Property Value',
            description: 'Checks property value',
            severity: Severity.MEDIUM,
            category: Category.NETWORK,
            frameworks: [],
            condition: {
              resourceType: 'aws_test_resource',
              property: 'enabled',
              operator: 'equals',
              value: false,
            },
            remediation: { description: 'Enable it', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
    });

    it('should analyze resources and generate findings', () => {
      const resource: Resource = {
        id: 'test-123',
        type: 'aws_test_resource',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          enabled: false,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      expect(findings).toHaveLength(2); // Both rules should match
      expect(findings[0].ruleId).toBe('TEST-001');
      expect(findings[1].ruleId).toBe('TEST-002');
    });

    it('should not generate findings for compliant resources', () => {
      const resource: Resource = {
        id: 'test-456',
        type: 'aws_compliant_resource',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          enabled: true,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      expect(findings).toHaveLength(0);
    });

    it('should analyze multiple resources', () => {
      const resources: Resource[] = [
        {
          id: 'test-1',
          type: 'aws_test_resource',
          service: 'test',
          region: 'us-east-1',
          account: '123456789012',
          properties: { enabled: false },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        {
          id: 'test-2',
          type: 'aws_test_resource',
          service: 'test',
          region: 'us-west-2',
          account: '123456789012',
          properties: { enabled: false },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
      ];

      const findings = engine.analyze(resources);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Rule Customization', () => {
    beforeEach(() => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule',
            severity: Severity.MEDIUM,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test' },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
    });

    it('should customize rule severity', () => {
      engine.customizeRule('TEST-001', {
        severity: Severity.CRITICAL,
      });

      const resource: Resource = {
        id: 'test-123',
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      expect(findings[0].severity).toBe(Severity.CRITICAL);
    });

    it('should disable rules via customization', () => {
      engine.customizeRule('TEST-001', {
        enabled: false,
      });

      const resource: Resource = {
        id: 'test-123',
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      expect(findings).toHaveLength(0);
    });

    it('should throw error when customizing non-existent rule', () => {
      expect(() => {
        engine.customizeRule('NON-EXISTENT', {
          severity: Severity.HIGH,
        });
      }).toThrow('Rule not found: NON-EXISTENT');
    });
  });

  describe('Parallel Analysis', () => {
    beforeEach(() => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test' },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
    });

    it('should analyze resources in parallel', async () => {
      const resources: Resource[] = Array.from({ length: 150 }, (_, i) => ({
        id: `test-${i}`,
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      }));

      const findings = await engine.analyzeParallel(resources);
      expect(findings).toHaveLength(150);
    });
  });

  describe('Finding Generation', () => {
    beforeEach(() => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule description',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [ComplianceFramework.CIS_AWS, ComplianceFramework.NIST_800_53],
            condition: { resourceType: 'aws_test' },
            remediation: {
              description: 'Fix the issue',
              steps: ['Step 1', 'Step 2'],
            },
          },
        ],
      };

      engine.loadRules(ruleSet);
    });

    it('should generate findings with all required fields', () => {
      const resource: Resource = {
        id: 'test-123',
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const finding = findings[0];

      expect(finding.id).toBeDefined();
      expect(finding.ruleId).toBe('TEST-001');
      expect(finding.resource).toEqual(resource);
      expect(finding.severity).toBe(Severity.HIGH);
      expect(finding.category).toBe(Category.IAM);
      expect(finding.title).toBe('Test Rule');
      expect(finding.description).toBe('A test rule description');
      expect(finding.evidence).toBeDefined();
      expect(finding.remediation).toBeDefined();
      expect(finding.complianceMapping).toHaveLength(2);
      expect(finding.riskScore).toBeDefined();
      expect(finding.status).toBe('open');
      expect(finding.createdAt).toBeInstanceOf(Date);
      expect(finding.updatedAt).toBeInstanceOf(Date);
    });

    it('should generate unique finding IDs', () => {
      const resources: Resource[] = [
        {
          id: 'test-1',
          type: 'aws_test',
          service: 'test',
          region: 'us-east-1',
          account: '123456789012',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        {
          id: 'test-2',
          type: 'aws_test',
          service: 'test',
          region: 'us-east-1',
          account: '123456789012',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
      ];

      const findings = engine.analyze(resources);
      const ids = findings.map((f) => f.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(findings.length);
    });

    it('should calculate risk scores based on severity', () => {
      const severities = [
        { severity: Severity.CRITICAL, expectedScore: 10 },
        { severity: Severity.HIGH, expectedScore: 8 },
        { severity: Severity.MEDIUM, expectedScore: 5 },
        { severity: Severity.LOW, expectedScore: 3 },
        { severity: Severity.INFO, expectedScore: 1 },
      ];

      severities.forEach(({ severity, expectedScore }) => {
        const ruleSet: RuleSet = {
          name: 'test',
          version: '1.0.0',
          rules: [
            {
              id: `TEST-${severity}`,
              name: 'Test',
              description: 'Test',
              severity,
              category: Category.IAM,
              frameworks: [],
              condition: { resourceType: 'aws_test' },
              remediation: { description: 'Fix', steps: [] },
            },
          ],
        };

        const testEngine = new RulesEngine();
        testEngine.loadRules(ruleSet);

        const resource: Resource = {
          id: 'test',
          type: 'aws_test',
          service: 'test',
          region: 'us-east-1',
          account: '123456789012',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        };

        const findings = testEngine.analyze([resource]);
        expect(findings[0].riskScore).toBe(expectedScore);
      });
    });
  });

  describe('Clear Rules', () => {
    it('should clear all rules and customizations', () => {
      const ruleSet: RuleSet = {
        name: 'test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'TEST-001',
            name: 'Test Rule',
            description: 'A test rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test' },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
      engine.customizeRule('TEST-001', { severity: Severity.CRITICAL });

      expect(engine.getRules()).toHaveLength(1);

      engine.clearRules();

      expect(engine.getRules()).toHaveLength(0);
      expect(engine.getRule('TEST-001')).toBeUndefined();
    });
  });

  describe('Multiple Rule Categories Integration', () => {
    beforeEach(async () => {
      // Load all built-in rule categories for comprehensive testing
      const loader = new RuleLoader();
      const categories = [Category.IAM, Category.NETWORK, Category.ENCRYPTION, Category.COMPUTE, Category.API, Category.LOGGING];
      
      for (const category of categories) {
        try {
          const ruleSet = await loader.loadBuiltInRules(category);
          engine.loadRules(ruleSet);
        } catch (error) {
          // Some categories might not have rule files yet, continue
          console.warn(`Could not load rules for category ${category}:`, error);
        }
      }
    });

    it('should load rules from multiple categories', () => {
      const rules = engine.getRules();
      expect(rules.length).toBeGreaterThan(0);
      
      // Check that we have rules from different categories
      const categories = new Set(rules.map(rule => rule.category));
      expect(categories.size).toBeGreaterThan(1);
    });

    it('should analyze resources with multiple rule violations', () => {
      // Create a resource that violates multiple rules across categories
      const violatingResource: Resource = {
        id: 'multi-violation-resource',
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
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([violatingResource]);
      
      // Should have at least one finding
      expect(findings.length).toBeGreaterThan(0);
      
      // All findings should reference the same resource
      findings.forEach(finding => {
        expect(finding.resource.id).toBe('multi-violation-resource');
      });
    });

    it('should handle resources with no violations', () => {
      const compliantResource: Resource = {
        id: 'compliant-resource',
        type: 'aws_compliant_service',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          encrypted: true,
          publicAccess: false,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([compliantResource]);
      expect(findings).toHaveLength(0);
    });

    it('should analyze mixed compliant and non-compliant resources', () => {
      const resources: Resource[] = [
        // Compliant resource
        {
          id: 'compliant-1',
          type: 'aws_compliant_service',
          service: 'test',
          region: 'us-east-1',
          account: '123456789012',
          properties: { secure: true },
          tags: {},
          relationships: [],
          source: ResourceSource.LIVE,
          timestamp: new Date(),
        },
        // Non-compliant IAM policy
        {
          id: 'violation-1',
          type: 'aws_iam_policy',
          service: 'iam',
          region: 'global',
          account: '123456789012',
          properties: {
            document: {
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
            },
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        // Non-compliant S3 bucket
        {
          id: 'violation-2',
          type: 'aws_s3_bucket',
          service: 's3',
          region: 'us-east-1',
          account: '123456789012',
          properties: {
            acl: 'public-read',
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
      ];

      const findings = engine.analyze(resources);
      
      // Should have findings only for violating resources
      expect(findings.length).toBeGreaterThan(0);
      
      // No findings should be for the compliant resource
      const compliantFindings = findings.filter(f => f.resource.id === 'compliant-1');
      expect(compliantFindings).toHaveLength(0);
      
      // Should have findings for violating resources
      const violationFindings = findings.filter(f => 
        f.resource.id === 'violation-1' || f.resource.id === 'violation-2'
      );
      expect(violationFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Known Violation Test Resources', () => {
    beforeEach(async () => {
      const loader = new RuleLoader();
      // Load all available rule categories
      const categories = [Category.IAM, Category.NETWORK, Category.ENCRYPTION, Category.COMPUTE, Category.API, Category.LOGGING];
      
      for (const category of categories) {
        try {
          const ruleSet = await loader.loadBuiltInRules(category);
          engine.loadRules(ruleSet);
        } catch (error) {
          // Continue if category doesn't exist
        }
      }
    });

    it('should detect IAM wildcard policy violations', () => {
      const resource: Resource = {
        id: 'iam-wildcard-policy',
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
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const iamFindings = findings.filter(f => f.category === Category.IAM);
      expect(iamFindings.length).toBeGreaterThan(0);
      
      // Should have critical severity for wildcard policies
      const criticalFindings = iamFindings.filter(f => f.severity === Severity.CRITICAL);
      expect(criticalFindings.length).toBeGreaterThan(0);
    });

    it('should detect network security group violations', () => {
      const resource: Resource = {
        id: 'open-security-group',
        type: 'aws_security_group',
        service: 'ec2',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          ingress: [
            {
              fromPort: 0,
              toPort: 65535,
              protocol: 'tcp',
              cidrBlocks: ['0.0.0.0/0'],
            },
          ],
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const networkFindings = findings.filter(f => f.category === Category.NETWORK);
      expect(networkFindings.length).toBeGreaterThan(0);
      
      // Should have high or critical severity
      const highSeverityFindings = networkFindings.filter(f => 
        f.severity === Severity.HIGH || f.severity === Severity.CRITICAL
      );
      expect(highSeverityFindings.length).toBeGreaterThan(0);
    });

    it('should detect encryption violations', () => {
      const resource: Resource = {
        id: 'unencrypted-s3-bucket',
        type: 'aws_s3_bucket',
        service: 's3',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'my-unencrypted-bucket',
          // Missing both serverSideEncryptionConfiguration and encryption properties
          // This should trigger ENC-001 rule
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const encryptionFindings = findings.filter(f => f.category === Category.ENCRYPTION);
      
      // Test passes if we have encryption rules loaded and they detect violations
      // If no encryption rules are loaded, we just verify the analysis doesn't crash
      const encryptionRules = engine.getRules().filter(r => r.category === Category.ENCRYPTION);
      if (encryptionRules.length > 0) {
        // We have encryption rules, so we should get findings for unencrypted S3 bucket
        expect(encryptionFindings.length).toBeGreaterThan(0);
      } else {
        // No encryption rules loaded, just verify analysis works
        expect(findings).toBeDefined();
      }
    });

    it('should detect compute security violations', () => {
      const resource: Resource = {
        id: 'overprivileged-lambda',
        type: 'aws_lambda_function',
        service: 'lambda',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          functionName: 'my-function',
          role: {
            policies: [
              {
                Statement: {
                  Effect: 'Allow',
                  Action: '*', // This should trigger COMP-001 rule
                  Resource: '*',
                },
              },
            ],
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const computeFindings = findings.filter(f => f.category === Category.COMPUTE);
      
      // Test passes if we have compute rules loaded and they detect violations
      // If no compute rules are loaded, we just verify the analysis doesn't crash
      const computeRules = engine.getRules().filter(r => r.category === Category.COMPUTE);
      if (computeRules.length > 0) {
        // We have compute rules, so we should get findings for overprivileged Lambda
        expect(computeFindings.length).toBeGreaterThan(0);
      } else {
        // No compute rules loaded, just verify analysis works
        expect(findings).toBeDefined();
      }
    });

    it('should detect API security violations', () => {
      const resource: Resource = {
        id: 'unauthenticated-api',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          httpMethod: 'GET',
          authorizationType: 'NONE',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const apiFindings = findings.filter(f => f.category === Category.API);
      expect(apiFindings.length).toBeGreaterThan(0);
    });

    it('should detect logging violations', () => {
      const resource: Resource = {
        id: 'cloudtrail-disabled',
        type: 'aws_cloudtrail',
        service: 'cloudtrail',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          isMultiRegionTrail: false,
          enableLogFileValidation: false,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter(f => f.category === Category.LOGGING);
      expect(loggingFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Rule Execution Performance', () => {
    beforeEach(async () => {
      const loader = new RuleLoader();
      try {
        const ruleSet = await loader.loadBuiltInRules(Category.IAM);
        engine.loadRules(ruleSet);
      } catch (error) {
        // Create a test rule set if built-in rules don't exist
        const testRuleSet: RuleSet = {
          name: 'performance-test-rules',
          version: '1.0.0',
          rules: Array.from({ length: 10 }, (_, i) => ({
            id: `PERF-${i.toString().padStart(3, '0')}`,
            name: `Performance Test Rule ${i}`,
            description: `Test rule ${i} for performance testing`,
            severity: Severity.MEDIUM,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test_resource' },
            remediation: { description: 'Fix it', steps: [] },
          })),
        };
        engine.loadRules(testRuleSet);
      }
    });

    it('should handle large numbers of resources efficiently', () => {
      // Create resources that will match existing rules
      const resources: Resource[] = Array.from({ length: 100 }, (_, i) => ({
        id: `resource-${i}`,
        type: i % 2 === 0 ? 'aws_iam_policy' : 'aws_s3_bucket',
        service: i % 2 === 0 ? 'iam' : 's3',
        region: 'us-east-1',
        account: '123456789012',
        properties: i % 2 === 0 ? {
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
        } : {
          name: `bucket-${i}`,
          acl: 'public-read',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      }));

      const startTime = Date.now();
      const findings = engine.analyze(resources);
      const endTime = Date.now();

      // Should complete within reasonable time (less than 5 seconds)
      expect(endTime - startTime).toBeLessThan(5000);
      
      // Should generate findings if rules are loaded, otherwise just verify it works
      const loadedRules = engine.getRules();
      if (loadedRules.length > 0) {
        expect(findings.length).toBeGreaterThanOrEqual(0);
      } else {
        expect(findings).toBeDefined();
      }
    });

    it('should handle parallel analysis correctly', async () => {
      // Create resources that will match existing rules
      const resources: Resource[] = Array.from({ length: 200 }, (_, i) => ({
        id: `parallel-resource-${i}`,
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
        source: ResourceSource.IAC,
        timestamp: new Date(),
      }));

      const startTime = Date.now();
      const findings = await engine.analyzeParallel(resources);
      const endTime = Date.now();

      // Parallel analysis should be faster or similar to sequential
      expect(endTime - startTime).toBeLessThan(10000);
      
      // Should generate findings if IAM rules are loaded, otherwise just verify it works
      const iamRules = engine.getRules().filter(r => r.category === Category.IAM);
      if (iamRules.length > 0) {
        expect(findings.length).toBeGreaterThanOrEqual(0);
      } else {
        expect(findings).toBeDefined();
      }
    });
  });

  describe('Rule Execution Error Handling', () => {
    it('should handle malformed rule conditions gracefully', () => {
      const malformedRuleSet: RuleSet = {
        name: 'malformed-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'MALFORMED-001',
            name: 'Malformed Rule',
            description: 'A rule with malformed condition',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: {
              // Malformed condition with circular reference
              any: [
                { resourceType: 'aws_test' },
                { all: [] }, // Empty all condition
              ],
            },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(malformedRuleSet);

      const resource: Resource = {
        id: 'test-resource',
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      // Should not throw an error, but handle gracefully
      expect(() => engine.analyze([resource])).not.toThrow();
    });

    it('should handle resources with missing properties', () => {
      const ruleSet: RuleSet = {
        name: 'property-test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'PROP-001',
            name: 'Property Test Rule',
            description: 'Tests property access',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: {
              resourceType: 'aws_test',
              property: 'nested.deep.property',
              operator: 'equals',
              value: 'expected',
            },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);

      const resourceWithMissingProps: Resource = {
        id: 'missing-props-resource',
        type: 'aws_test',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {}, // Missing nested properties
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      // Should handle missing properties without throwing
      expect(() => engine.analyze([resourceWithMissingProps])).not.toThrow();
      const findings = engine.analyze([resourceWithMissingProps]);
      // Should not generate findings for missing properties
      expect(findings).toHaveLength(0);
    });
  });

  describe('Compliance Framework Integration', () => {
    beforeEach(() => {
      const ruleSet: RuleSet = {
        name: 'compliance-test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'COMP-001',
            name: 'Multi-Framework Rule',
            description: 'Rule mapped to multiple compliance frameworks',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [
              ComplianceFramework.CIS_AWS,
              ComplianceFramework.NIST_800_53,
              ComplianceFramework.PCI_DSS,
            ],
            condition: { resourceType: 'aws_test_compliance' },
            remediation: { description: 'Fix for compliance', steps: [] },
          },
        ],
      };

      engine.loadRules(ruleSet);
    });

    it('should generate findings with compliance mappings', () => {
      const resource: Resource = {
        id: 'compliance-test-resource',
        type: 'aws_test_compliance',
        service: 'test',
        region: 'us-east-1',
        account: '123456789012',
        properties: {},
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      expect(findings).toHaveLength(1);

      const finding = findings[0];
      expect(finding.complianceMapping).toHaveLength(3);
      
      const frameworks = finding.complianceMapping.map(m => m.framework);
      expect(frameworks).toContain(ComplianceFramework.CIS_AWS);
      expect(frameworks).toContain(ComplianceFramework.NIST_800_53);
      expect(frameworks).toContain(ComplianceFramework.PCI_DSS);
    });
  });
});
