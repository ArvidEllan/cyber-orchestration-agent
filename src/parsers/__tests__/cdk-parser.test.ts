import { describe, it, expect } from 'vitest';
import { CDKParser } from '../cdk-parser';
import { IaCFormat } from '../../types';
import * as path from 'path';

describe('CDKParser', () => {
  const parser = new CDKParser();
  const fixturesDir = path.join(__dirname, 'fixtures');
  const cdkFile = path.join(fixturesDir, 'stack.ts');

  it('should parse CDK TypeScript file', async () => {
    const result = await parser.parse(cdkFile, IaCFormat.CDK);

    expect(result.format).toBe(IaCFormat.CDK);
    expect(result.resources).toBeDefined();
    expect(result.metadata).toBeDefined();
  });

  it('should extract CDK constructs', async () => {
    const result = await parser.parse(cdkFile, IaCFormat.CDK);
    const resources = parser.extractResources(result);

    expect(resources.length).toBeGreaterThan(0);
    expect(resources[0]).toHaveProperty('id');
    expect(resources[0]).toHaveProperty('type');
  });

  it('should validate parsed infrastructure', async () => {
    const result = await parser.parse(cdkFile, IaCFormat.CDK);
    const validation = parser.validate(result);

    expect(validation).toHaveProperty('valid');
    expect(validation).toHaveProperty('errors');
    expect(validation).toHaveProperty('warnings');
  });
});
