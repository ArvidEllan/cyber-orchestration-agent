import { describe, it, expect } from 'vitest';
import { CloudFormationParser } from '../cloudformation-parser';
import { IaCFormat } from '../../types';
import * as path from 'path';

describe('CloudFormationParser', () => {
  const parser = new CloudFormationParser();
  const fixturesDir = path.join(__dirname, 'fixtures');
  const cfnFile = path.join(fixturesDir, 'template.json');

  it('should parse CloudFormation template', async () => {
    const result = await parser.parse(cfnFile, IaCFormat.CLOUDFORMATION);

    expect(result.format).toBe(IaCFormat.CLOUDFORMATION);
    expect(result.resources).toBeDefined();
    expect(result.variables).toBeDefined();
    expect(result.outputs).toBeDefined();
  });

  it('should extract resources', async () => {
    const result = await parser.parse(cfnFile, IaCFormat.CLOUDFORMATION);
    const resources = parser.extractResources(result);

    expect(resources.length).toBeGreaterThan(0);
    expect(resources[0]).toHaveProperty('id');
    expect(resources[0]).toHaveProperty('type');
    expect(resources[0].type).toContain('AWS::');
  });

  it('should extract parameters as variables', async () => {
    const result = await parser.parse(cfnFile, IaCFormat.CLOUDFORMATION);

    expect(result.variables.length).toBeGreaterThan(0);
    expect(result.variables[0]).toHaveProperty('name');
    expect(result.variables[0]).toHaveProperty('type');
  });

  it('should handle intrinsic functions', async () => {
    const result = await parser.parse(cfnFile, IaCFormat.CLOUDFORMATION);
    const resources = result.resources;

    // Check that intrinsic functions are preserved
    const bucket = resources.find((r) => r.id === 'ExampleBucket');
    expect(bucket).toBeDefined();
  });

  it('should extract dependencies', async () => {
    const result = await parser.parse(cfnFile, IaCFormat.CLOUDFORMATION);
    const role = result.resources.find((r) => r.id === 'ExampleRole');

    expect(role).toBeDefined();
    expect(role?.relationships.length).toBeGreaterThan(0);
  });
});
