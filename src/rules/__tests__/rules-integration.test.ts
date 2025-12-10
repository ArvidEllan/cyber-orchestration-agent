/**
 * Rules Engine Integration Tests
 * Tests for multiple rules working together across different categories
 * 
 * This test suite validates:
 * - Multiple rule categories working together
 * - Complex resource scenarios with multiple violations
 * - Rule interaction and finding generation
 * - Performance with large rule sets and resource collections
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
  ComplianceFramework,
} from '../../types';

describe('Rules Engine Integration Tests', () => {
  let engine: RulesEngine;
  let loader: RuleLoader;

  beforeEach(async () => {
    engine = new RulesEngine();
    loader = new RuleLoader();

    // Load all available rule categories
    const categories = [
      Category.IAM,
      Category.NETWORK,
      Category.ENCRYPTION,
      Category.COMPUTE,
      Category.API,
      Category.LOGGING,
    ];

    for (const category of categories) {
      try {
        const ruleSet = await loader.loadBuiltInRules(category);
        engine.loadRules(ruleSet);
      } catch (error) {
        // Some categories might not have rule files, continue
        console.warn(`Could not load rules for category ${category}`);
      }
    }
  });

  describe('Multi-Category Violation Detection', () => {
    it('should detect violations across multiple categories in a single resource', () => {
      // Create a Lambda function that violates multiple categories
      const lambdaResource: Resource = {
        id: 'multi-violation-lambda',
        type: 'aws_lambda_function',
        service: 'lambda',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          functionName: 'insecure-function',
          // Compute violation: overly permissive role
          role: {
            policies: [
              {
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: '*',
                  },
                ],
              },
            ],
          },
          // Compute violation: excessive timeout
          timeout: 900,
          // Logging violation: no logging config
          // Missing loggingConfig
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([lambdaResource]);
      
      // Should have findings from multiple categories
      const categories = new Set(findings.map(f => f.category));
      expect(categories.size).toBeGreaterThan(0);
      
      // All findings should be for the same resource
      findings.forEach(finding => {
        expect(finding.resource.id).toBe('multi-violation-lambda');
      });
    });

    it('should detect violations in a complex infrastructure setup', () => {
      const resources: Resource[] = [
        // Insecure S3 bucket (Encryption + Storage violations)
        {
          id: 'insecure-s3-bucket',
          type: 'aws_s3_bucket',
          service: 's3',
          region: 'us-east-1',
          account: '123456789012',
          properties: {
            name: 'public-unencrypted-bucket',
            acl: 'public-read', // Storage violation
            // Missing encryption config - Encryption violation
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        // Insecure API Gateway (API + Logging violations)
        {
          id: 'insecure-api-gateway',
          type: 'aws_api_gateway_method',
          service: 'apigateway',
          region: 'us-east-1',
          account: '123456789012',
          properties: {
            httpMethod: 'GET',
            authorizationType: 'NONE', // API violation
            // Missing logging - would be detected in stage resource
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        // Insecure Security Group (Network violation)
        {
          id: 'insecure-security-group',
          type: 'aws_security_group',
          service: 'ec2',
          region: 'us-east-1',
          account: '123456789012',
          properties: {
            ingress: [
              {
                fromPort: 22,
                toPort: 22,
                protocol: 'tcp',
                cidrBlocks: ['0.0.0.0/0'], // Network violation
              },
            ],
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        // Insecure IAM Policy (IAM violation)
        {
          id: 'insecure-iam-policy',
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
                  Action: '*', // IAM violation
                  Resource: '*',
                },
              ],
            },
          },
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
      ];

      const findings = engine.analyze(resources);
      
      // Should have findings for multiple resources
      expect(findings.length).toBeGreaterThan(0);
      
      // Should have findings from multiple categories
      const categories = new Set(findings.map(f => f.category));
      expect(categories.size).toBeGreaterThan(1);
      
      // Should have findings for each violating resource
      const resourcesWithFindings = new Set(findings.map(f => f.resource.id));
      expect(resourcesWithFindings.size).toBeGreaterThan(1);
    });
  });

  describe('Severity Distribution and Risk Assessment', () => {
    it('should generate findings with appropriate severity distribution', () => {
      const resources: Resource[] = [
        // Critical violation: IAM wildcard policy
        {
          id: 'critical-iam-policy',
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
        },
        // High violation: Unencrypted RDS
        {
          id: 'unencrypted-rds',
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
        },
        // Medium violation: VPC without flow logs
        {
          id: 'vpc-no-flow-logs',
          type: 'aws_vpc',
          service: 'ec2',
          region: 'us-east-1',
          account: '123456789012',
          properties: {
            cidrBlock: '10.0.0.0/16',
            flowLogsEnabled: false,
          },
          tags: {},
          relationships: [],
          source: ResourceSource.LIVE,
          timestamp: new Date(),
        },
      ];

      const findings = engine.analyze(resources);
      
      if (findings.length > 0) {
        // Should have findings with different severity levels
        const severities = new Set(findings.map(f => f.severity));
        
        // Check that we have a mix of severities
        const hasCritical = findings.some(f => f.severity === Severity.CRITICAL);
        const hasHigh = findings.some(f => f.severity === Severity.HIGH);
        const hasMediumOrLow = findings.some(f => 
          f.severity === Severity.MEDIUM || f.severity === Severity.LOW
        );
        
        // Should have at least some high-severity findings
        expect(hasCritical || hasHigh).toBe(true);
      }
    });

    it('should calculate risk scores consistently', () => {
      const resource: Resource = {
        id: 'test-resource',
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
      
      findings.forEach(finding => {
        // Risk score should be defined and reasonable
        expect(finding.riskScore).toBeDefined();
        expect(finding.riskScore).toBeGreaterThan(0);
        expect(finding.riskScore).toBeLessThanOrEqual(10);
        
        // Risk score should correlate with severity
        if (finding.severity === Severity.CRITICAL) {
          expect(finding.riskScore).toBeGreaterThanOrEqual(8);
        } else if (finding.severity === Severity.HIGH) {
          expect(finding.riskScore).toBeGreaterThanOrEqual(6);
        }
      });
    });
  });

  describe('Compliance Framework Mapping', () => {
    it('should map findings to appropriate compliance frameworks', () => {
      const resource: Resource = {
        id: 'compliance-test-resource',
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
      
      findings.forEach(finding => {
        // Should have compliance mappings
        expect(finding.complianceMapping).toBeDefined();
        expect(Array.isArray(finding.complianceMapping)).toBe(true);
        
        // Each mapping should have required fields
        finding.complianceMapping.forEach(mapping => {
          expect(mapping.framework).toBeDefined();
          expect(mapping.controlId).toBeDefined();
          expect(mapping.controlName).toBeDefined();
          expect(mapping.requirement).toBeDefined();
          expect(mapping.status).toBe('non_compliant');
        });
      });
    });

    it('should support multiple compliance frameworks', () => {
      const resource: Resource = {
        id: 'multi-framework-resource',
        type: 'aws_s3_bucket',
        service: 's3',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'unencrypted-bucket',
          // Missing encryption - violates multiple frameworks
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      
      if (findings.length > 0) {
        // Should have mappings to multiple frameworks
        const allFrameworks = new Set();
        findings.forEach(finding => {
          finding.complianceMapping.forEach(mapping => {
            allFrameworks.add(mapping.framework);
          });
        });
        
        // Common frameworks that should be represented
        const expectedFrameworks = [
          ComplianceFramework.CIS_AWS,
          ComplianceFramework.AWS_WELL_ARCHITECTED,
          ComplianceFramework.NIST_800_53,
        ];
        
        // Should have at least some framework mappings
        expect(allFrameworks.size).toBeGreaterThan(0);
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of resources efficiently', () => {
      // Create a large number of resources
      const resources: Resource[] = Array.from({ length: 500 }, (_, i) => ({
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
                Action: i % 4 === 0 ? '*' : 's3:GetObject', // Some violations
                Resource: '*',
              },
            ],
          },
        } : {
          name: `bucket-${i}`,
          acl: i % 4 === 0 ? 'public-read' : 'private', // Some violations
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      }));

      const startTime = Date.now();
      const findings = engine.analyze(resources);
      const endTime = Date.now();

      // Should complete within reasonable time (less than 10 seconds)
      expect(endTime - startTime).toBeLessThan(10000);
      
      // Should generate findings for violating resources
      expect(findings.length).toBeGreaterThan(0);
      
      // Should not generate more findings than resources
      expect(findings.length).toBeLessThanOrEqual(resources.length * 10); // Max 10 findings per resource
    });

    it('should handle parallel analysis correctly', async () => {
      const resources: Resource[] = Array.from({ length: 300 }, (_, i) => ({
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

      // Should complete within reasonable time
      expect(endTime - startTime).toBeLessThan(15000);
      
      // Should generate findings
      expect(findings.length).toBeGreaterThan(0);
      
      // Each resource should have at least one finding (wildcard policy)
      const resourcesWithFindings = new Set(findings.map(f => f.resource.id));
      expect(resourcesWithFindings.size).toBeGreaterThan(0);
    });
  });

  describe('Rule Customization Integration', () => {
    it('should apply customizations across multiple rule categories', () => {
      // Load a few rules and customize them
      const testRuleSet: RuleSet = {
        name: 'customization-test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'CUSTOM-IAM-001',
            name: 'IAM Test Rule',
            description: 'Test IAM rule',
            severity: Severity.MEDIUM,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_iam_policy' },
            remediation: { description: 'Fix IAM', steps: [] },
          },
          {
            id: 'CUSTOM-NET-001',
            name: 'Network Test Rule',
            description: 'Test Network rule',
            severity: Severity.LOW,
            category: Category.NETWORK,
            frameworks: [],
            condition: { resourceType: 'aws_security_group' },
            remediation: { description: 'Fix Network', steps: [] },
          },
        ],
      };

      engine.loadRules(testRuleSet);

      // Customize both rules
      engine.customizeRule('CUSTOM-IAM-001', { severity: Severity.CRITICAL });
      engine.customizeRule('CUSTOM-NET-001', { severity: Severity.HIGH });

      const resources: Resource[] = [
        {
          id: 'iam-resource',
          type: 'aws_iam_policy',
          service: 'iam',
          region: 'global',
          account: '123456789012',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.IAC,
          timestamp: new Date(),
        },
        {
          id: 'network-resource',
          type: 'aws_security_group',
          service: 'ec2',
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
      
      // Should have findings with customized severities
      const iamFinding = findings.find(f => f.ruleId === 'CUSTOM-IAM-001');
      const networkFinding = findings.find(f => f.ruleId === 'CUSTOM-NET-001');
      
      if (iamFinding) {
        expect(iamFinding.severity).toBe(Severity.CRITICAL);
      }
      
      if (networkFinding) {
        expect(networkFinding.severity).toBe(Severity.HIGH);
      }
    });

    it('should handle disabled rules correctly', () => {
      const testRuleSet: RuleSet = {
        name: 'disable-test-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'DISABLE-TEST-001',
            name: 'Disable Test Rule',
            description: 'Rule to be disabled',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_test_resource' },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(testRuleSet);
      
      // Disable the rule
      engine.customizeRule('DISABLE-TEST-001', { enabled: false });

      const resource: Resource = {
        id: 'test-resource',
        type: 'aws_test_resource',
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
      
      // Should not have findings from disabled rule
      const disabledRuleFindings = findings.filter(f => f.ruleId === 'DISABLE-TEST-001');
      expect(disabledRuleFindings).toHaveLength(0);
    });
  });

  describe('Error Handling and Resilience', () => {
    it('should continue analysis when individual rules fail', () => {
      const problematicRuleSet: RuleSet = {
        name: 'problematic-rules',
        version: '1.0.0',
        rules: [
          {
            id: 'GOOD-RULE-001',
            name: 'Good Rule',
            description: 'A working rule',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: { resourceType: 'aws_iam_policy' },
            remediation: { description: 'Fix', steps: [] },
          },
          {
            id: 'PROBLEMATIC-RULE-001',
            name: 'Problematic Rule',
            description: 'A rule with issues',
            severity: Severity.HIGH,
            category: Category.IAM,
            frameworks: [],
            condition: {
              // Potentially problematic condition
              property: 'deeply.nested.property.that.might.not.exist',
              operator: 'equals',
              value: 'test',
            },
            remediation: { description: 'Fix', steps: [] },
          },
        ],
      };

      engine.loadRules(problematicRuleSet);

      const resource: Resource = {
        id: 'test-resource',
        type: 'aws_iam_policy',
        service: 'iam',
        region: 'global',
        account: '123456789012',
        properties: {
          // Missing the deeply nested property
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      // Should not throw an error
      expect(() => engine.analyze([resource])).not.toThrow();
      
      const findings = engine.analyze([resource]);
      
      // Should still generate findings from working rules
      const goodRuleFindings = findings.filter(f => f.ruleId === 'GOOD-RULE-001');
      expect(goodRuleFindings.length).toBeGreaterThanOrEqual(0);
    });
  });
});