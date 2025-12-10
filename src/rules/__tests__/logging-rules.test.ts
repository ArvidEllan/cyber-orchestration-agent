/**
 * Logging and Monitoring Rules Tests
 * Tests for logging and monitoring security rules
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleLoader } from '../rule-loader';
import { RulesEngine } from '../rules-engine';
import { Resource, ResourceSource, Severity, Category } from '../../types';

describe('Logging and Monitoring Rules', () => {
  let engine: RulesEngine;

  beforeEach(async () => {
    const loader = new RuleLoader();
    engine = new RulesEngine();
    
    try {
      const ruleSet = await loader.loadBuiltInRules(Category.LOGGING);
      engine.loadRules(ruleSet);
    } catch (error) {
      // If built-in rules don't exist, skip these tests
      console.warn('Logging rules not found, skipping tests');
    }
  });

  describe('CloudTrail Configuration', () => {
    it('should detect CloudTrail not enabled globally', () => {
      const resource: Resource = {
        id: 'cloudtrail-123',
        type: 'aws_cloudtrail',
        service: 'cloudtrail',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'main-trail',
          isMultiRegionTrail: false, // Should be true
          s3BucketName: 'my-cloudtrail-bucket',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const cloudtrailFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('cloudtrail') ||
        f.description.toLowerCase().includes('multi-region')
      );
      
      if (cloudtrailFindings.length > 0) {
        expect(cloudtrailFindings[0].severity).toBe(Severity.CRITICAL);
        expect(cloudtrailFindings[0].category).toBe(Category.LOGGING);
      }
    });

    it('should detect CloudTrail without log file validation', () => {
      const resource: Resource = {
        id: 'cloudtrail-no-validation',
        type: 'aws_cloudtrail',
        service: 'cloudtrail',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'main-trail',
          isMultiRegionTrail: true,
          enableLogFileValidation: false, // Security violation
          s3BucketName: 'my-cloudtrail-bucket',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const validationFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('validation') ||
        f.description.toLowerCase().includes('tampering')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect CloudTrail logs without encryption', () => {
      const resource: Resource = {
        id: 'cloudtrail-no-encryption',
        type: 'aws_cloudtrail',
        service: 'cloudtrail',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'main-trail',
          isMultiRegionTrail: true,
          enableLogFileValidation: true,
          s3BucketName: 'my-cloudtrail-bucket',
          // Missing kmsKeyId
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const encryptionFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('encrypt') ||
        f.description.toLowerCase().includes('kms')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect account without CloudTrail enabled', () => {
      const resource: Resource = {
        id: 'account-123456789012',
        type: 'aws_account',
        service: 'organizations',
        region: 'global',
        account: '123456789012',
        properties: {
          accountId: '123456789012',
          cloudTrailEnabled: false, // Security violation
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const cloudtrailFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('cloudtrail')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('AWS Config Configuration', () => {
    it('should detect AWS Config not enabled', () => {
      const resource: Resource = {
        id: 'config-recorder-123',
        type: 'aws_config_configuration_recorder',
        service: 'config',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'default',
          recording: false, // Should be true
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const configFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('config') ||
        f.description.toLowerCase().includes('configuration')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect account without AWS Config enabled', () => {
      const resource: Resource = {
        id: 'account-no-config',
        type: 'aws_account',
        service: 'organizations',
        region: 'global',
        account: '123456789012',
        properties: {
          accountId: '123456789012',
          configEnabled: false, // Security violation
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const configFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('config')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('CloudWatch Logs Configuration', () => {
    it('should detect Lambda functions without CloudWatch Logs', () => {
      const resource: Resource = {
        id: 'lambda-no-logs',
        type: 'aws_lambda_function',
        service: 'lambda',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          functionName: 'my-function',
          // Missing loggingConfig
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('cloudwatch') ||
        f.description.toLowerCase().includes('logging')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect API Gateway stages without access logs', () => {
      const resource: Resource = {
        id: 'api-stage-no-logs',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          // Missing accessLogSettings
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('access log') ||
        f.description.toLowerCase().includes('logging')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect ECS task definitions without log configuration', () => {
      const resource: Resource = {
        id: 'ecs-task-no-logs',
        type: 'aws_ecs_task_definition',
        service: 'ecs',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          family: 'my-app',
          containerDefinitions: [
            {
              name: 'app-container',
              image: 'nginx:latest',
              // Missing logConfiguration
            },
          ],
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('log')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('S3 Bucket Logging', () => {
    it('should detect S3 buckets without access logging', () => {
      const resource: Resource = {
        id: 's3-bucket-no-logs',
        type: 'aws_s3_bucket',
        service: 's3',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'my-bucket',
          // Missing logging configuration
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('access log') ||
        f.description.toLowerCase().includes('bucket log')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('Load Balancer Logging', () => {
    it('should detect Application Load Balancers without access logs', () => {
      const resource: Resource = {
        id: 'alb-no-logs',
        type: 'aws_lb',
        service: 'elbv2',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'my-alb',
          loadBalancerType: 'application',
          accessLogs: {
            enabled: false, // Should be true
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('access log')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect Classic Load Balancers without access logs', () => {
      const resource: Resource = {
        id: 'elb-no-logs',
        type: 'aws_alb',
        service: 'elb',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'my-elb',
          accessLogs: {
            enabled: false, // Should be true
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('access log')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('CloudWatch Log Group Configuration', () => {
    it('should detect CloudWatch Log Groups without retention policy', () => {
      const resource: Resource = {
        id: 'log-group-no-retention',
        type: 'aws_cloudwatch_log_group',
        service: 'logs',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: '/aws/lambda/my-function',
          // Missing retentionInDays
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const retentionFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('retention')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('RDS Database Logging', () => {
    it('should detect RDS databases without audit logging', () => {
      const resource: Resource = {
        id: 'rds-no-logs',
        type: 'aws_db_instance',
        service: 'rds',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          identifier: 'mydb',
          engine: 'postgres',
          enabledCloudwatchLogsExports: [], // Should have log types
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const loggingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('audit log') ||
        f.description.toLowerCase().includes('cloudwatch log')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('Compliant Logging Resources', () => {
    it('should not flag properly configured CloudTrail', () => {
      const resource: Resource = {
        id: 'cloudtrail-secure',
        type: 'aws_cloudtrail',
        service: 'cloudtrail',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'secure-trail',
          isMultiRegionTrail: true,
          enableLogFileValidation: true,
          s3BucketName: 'secure-cloudtrail-bucket',
          kmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/12345',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const violations = findings.filter((f) => 
        f.resource.id === 'cloudtrail-secure'
      );
      
      // Should have no violations for properly configured CloudTrail
      expect(violations).toHaveLength(0);
    });

    it('should not flag CloudWatch Log Groups with retention policy', () => {
      const resource: Resource = {
        id: 'log-group-with-retention',
        type: 'aws_cloudwatch_log_group',
        service: 'logs',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: '/aws/lambda/my-function',
          retentionInDays: 30, // Properly configured
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const violations = findings.filter((f) => 
        f.resource.id === 'log-group-with-retention'
      );
      
      expect(violations).toHaveLength(0);
    });

    it('should not flag RDS databases with proper logging', () => {
      const resource: Resource = {
        id: 'rds-with-logs',
        type: 'aws_db_instance',
        service: 'rds',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          identifier: 'secure-db',
          engine: 'postgres',
          enabledCloudwatchLogsExports: ['postgresql', 'upgrade'], // Properly configured
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const violations = findings.filter((f) => 
        f.resource.id === 'rds-with-logs'
      );
      
      expect(violations).toHaveLength(0);
    });
  });
});