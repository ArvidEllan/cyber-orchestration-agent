/**
 * Network Security Rules Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { RuleLoader } from '../rule-loader';
import { RulesEngine } from '../rules-engine';
import { Resource, ResourceSource, Severity, Category } from '../../types';

describe('Network Security Rules', () => {
  let engine: RulesEngine;

  beforeEach(async () => {
    const loader = new RuleLoader();
    engine = new RulesEngine();
    const ruleSet = await loader.loadBuiltInRules(Category.NETWORK);
    engine.loadRules(ruleSet);
  });

  it('should detect security groups with unrestricted ingress', () => {
    const resource: Resource = {
      id: 'sg-123',
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
    const finding = findings.find((f) => f.ruleId === 'NET-001');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.CRITICAL);
  });

  it('should detect unrestricted SSH access', () => {
    const resource: Resource = {
      id: 'sg-456',
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
    const finding = findings.find((f) => f.ruleId === 'NET-002');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.CRITICAL);
  });

  it('should detect unrestricted RDP access', () => {
    const resource: Resource = {
      id: 'sg-789',
      type: 'aws_security_group',
      service: 'ec2',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        ingress: [
          {
            fromPort: 3389,
            toPort: 3389,
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
    const finding = findings.find((f) => f.ruleId === 'NET-003');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.CRITICAL);
  });

  it('should detect VPCs without flow logs', () => {
    const resource: Resource = {
      id: 'vpc-123',
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
    };

    const findings = engine.analyze([resource]);
    const finding = findings.find((f) => f.ruleId === 'NET-004');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe(Severity.MEDIUM);
  });

  it('should not flag security groups with restricted access', () => {
    const resource: Resource = {
      id: 'sg-secure',
      type: 'aws_security_group',
      service: 'ec2',
      region: 'us-east-1',
      account: '123456789012',
      properties: {
        ingress: [
          {
            fromPort: 443,
            toPort: 443,
            protocol: 'tcp',
            cidrBlocks: ['10.0.0.0/8'],
          },
        ],
      },
      tags: {},
      relationships: [],
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };

    const findings = engine.analyze([resource]);
    const unrestricted = findings.find((f) => f.ruleId === 'NET-001');
    expect(unrestricted).toBeUndefined();
  });
});
