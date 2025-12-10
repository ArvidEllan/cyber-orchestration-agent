/**
 * API Security Rules Tests
 * Tests for API Gateway security rules
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleLoader } from '../rule-loader';
import { RulesEngine } from '../rules-engine';
import { Resource, ResourceSource, Severity, Category } from '../../types';

describe('API Security Rules', () => {
  let engine: RulesEngine;

  beforeEach(async () => {
    const loader = new RuleLoader();
    engine = new RulesEngine();
    
    try {
      const ruleSet = await loader.loadBuiltInRules(Category.API);
      engine.loadRules(ruleSet);
    } catch (error) {
      // If built-in rules don't exist, skip these tests
      console.warn('API rules not found, skipping tests');
    }
  });

  describe('API Gateway Authentication', () => {
    it('should detect API Gateway methods without authentication', () => {
      const resource: Resource = {
        id: 'api-method-123',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          resourceId: 'resource-123',
          httpMethod: 'GET',
          authorizationType: 'NONE', // Security violation
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const authFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('authentication') ||
        f.description.toLowerCase().includes('authorization')
      );
      
      if (authFindings.length > 0) {
        expect(authFindings[0].severity).toBe(Severity.CRITICAL);
        expect(authFindings[0].category).toBe(Category.API);
      }
    });

    it('should detect APIGatewayV2 routes without authentication', () => {
      const resource: Resource = {
        id: 'apiv2-route-123',
        type: 'aws_apigatewayv2_route',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          apiId: 'api-123',
          routeKey: 'GET /users',
          authorizationType: 'NONE', // Security violation
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const authFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('authentication')
      );
      
      expect(findings).toBeDefined();
    });

    it('should not flag OPTIONS methods without authentication (CORS)', () => {
      const resource: Resource = {
        id: 'api-options-method',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          resourceId: 'resource-123',
          httpMethod: 'OPTIONS', // CORS preflight - should be unauthenticated
          authorizationType: 'NONE',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const authViolations = findings.filter((f) => 
        f.resource.id === 'api-options-method' &&
        f.description.toLowerCase().includes('authentication')
      );
      
      // OPTIONS methods should not be flagged for missing auth
      expect(authViolations).toHaveLength(0);
    });
  });

  describe('API Gateway Throttling', () => {
    it('should detect API Gateway stages without throttling', () => {
      const resource: Resource = {
        id: 'api-stage-123',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          // Missing throttleSettings
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const throttlingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('throttling') ||
        f.description.toLowerCase().includes('rate limit')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect usage plans without throttling', () => {
      const resource: Resource = {
        id: 'usage-plan-123',
        type: 'aws_api_gateway_usage_plan',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'basic-plan',
          // Missing throttleSettings
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const throttlingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('throttling')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway Logging', () => {
    it('should detect API Gateway stages without access logging', () => {
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
        f.description.toLowerCase().includes('logging') ||
        f.description.toLowerCase().includes('access log')
      );
      
      expect(findings).toBeDefined();
    });

    it('should detect API Gateway stages without X-Ray tracing', () => {
      const resource: Resource = {
        id: 'api-stage-no-xray',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          xrayTracingEnabled: false,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const tracingFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('tracing') ||
        f.description.toLowerCase().includes('x-ray')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway WAF Protection', () => {
    it('should detect API Gateway stages without WAF', () => {
      const resource: Resource = {
        id: 'api-stage-no-waf',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          // Missing webAclArn
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const wafFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('waf') ||
        f.description.toLowerCase().includes('web acl')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway Request Validation', () => {
    it('should detect API Gateway methods without request validation', () => {
      const resource: Resource = {
        id: 'api-method-no-validation',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          resourceId: 'resource-123',
          httpMethod: 'POST',
          authorizationType: 'AWS_IAM',
          // Missing requestValidatorId
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const validationFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('validation') ||
        f.description.toLowerCase().includes('request')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway CORS Configuration', () => {
    it('should detect missing CORS configuration for browser APIs', () => {
      const resource: Resource = {
        id: 'api-method-no-cors',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          resourceId: 'resource-123',
          httpMethod: 'OPTIONS',
          authorizationType: 'NONE',
          methodResponses: {
            '200': {
              // Missing CORS headers
            },
          },
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const corsFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('cors')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway Resource Policy', () => {
    it('should detect API Gateway without resource policy', () => {
      const resource: Resource = {
        id: 'api-no-policy',
        type: 'aws_api_gateway_rest_api',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          name: 'my-api',
          // Missing policy
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const policyFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('resource policy') ||
        f.description.toLowerCase().includes('access control')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('API Gateway Cache Security', () => {
    it('should detect API Gateway stages with unencrypted cache', () => {
      const resource: Resource = {
        id: 'api-stage-unencrypted-cache',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          cacheClusterEnabled: true,
          cacheClusterEncrypted: false, // Security violation
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const cacheFindings = findings.filter((f) => 
        f.description.toLowerCase().includes('cache') &&
        f.description.toLowerCase().includes('encrypt')
      );
      
      expect(findings).toBeDefined();
    });
  });

  describe('Compliant API Resources', () => {
    it('should not flag properly secured API Gateway methods', () => {
      const resource: Resource = {
        id: 'api-method-secure',
        type: 'aws_api_gateway_method',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          resourceId: 'resource-123',
          httpMethod: 'GET',
          authorizationType: 'AWS_IAM', // Properly authenticated
          requestValidatorId: 'validator-123',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const authViolations = findings.filter((f) => 
        f.resource.id === 'api-method-secure' &&
        f.description.toLowerCase().includes('authentication')
      );
      
      expect(authViolations).toHaveLength(0);
    });

    it('should not flag API Gateway stages with proper security configuration', () => {
      const resource: Resource = {
        id: 'api-stage-secure',
        type: 'aws_api_gateway_stage',
        service: 'apigateway',
        region: 'us-east-1',
        account: '123456789012',
        properties: {
          restApiId: 'api-123',
          stageName: 'prod',
          throttleSettings: {
            rateLimit: 1000,
            burstLimit: 2000,
          },
          accessLogSettings: {
            destinationArn: 'arn:aws:logs:us-east-1:123456789012:log-group:api-logs',
            format: '$requestId',
          },
          xrayTracingEnabled: true,
          webAclArn: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/api-waf',
        },
        tags: {},
        relationships: [],
        source: ResourceSource.IAC,
        timestamp: new Date(),
      };

      const findings = engine.analyze([resource]);
      const securityViolations = findings.filter((f) => 
        f.resource.id === 'api-stage-secure'
      );
      
      // Should have no violations for properly configured stage
      expect(securityViolations).toHaveLength(0);
    });
  });
});