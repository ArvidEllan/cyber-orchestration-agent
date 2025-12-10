import { describe, it, expect } from 'vitest';
import { TerraformParser } from '../terraform-parser';
import { IaCFormat } from '../../types';
import * as path from 'path';

describe('TerraformParser', () => {
  const parser = new TerraformParser();
  const fixturesDir = path.join(__dirname, 'fixtures');
  const terraformFile = path.join(fixturesDir, 'example.tf');

  it('should parse Terraform file', async () => {
    const result = await parser.parse(terraformFile, IaCFormat.TERRAFORM);

    expect(result.format).toBe(IaCFormat.TERRAFORM);
    expect(result.resources).toBeDefined();
    expect(result.variables).toBeDefined();
    expect(result.outputs).toBeDefined();
  });

  it('should extract resources', async () => {
    const result = await parser.parse(terraformFile, IaCFormat.TERRAFORM);
    const resources = parser.extractResources(result);

    expect(resources.length).toBeGreaterThan(0);
    expect(resources[0]).toHaveProperty('id');
    expect(resources[0]).toHaveProperty('type');
    expect(resources[0]).toHaveProperty('service');
  });

  it('should extract variables', async () => {
    const result = await parser.parse(terraformFile, IaCFormat.TERRAFORM);

    expect(result.variables.length).toBeGreaterThan(0);
    expect(result.variables[0]).toHaveProperty('name');
    expect(result.variables[0]).toHaveProperty('type');
  });

  it('should validate parsed infrastructure', async () => {
    const result = await parser.parse(terraformFile, IaCFormat.TERRAFORM);
    const validation = parser.validate(result);

    expect(validation).toHaveProperty('valid');
    expect(validation).toHaveProperty('errors');
    expect(validation).toHaveProperty('warnings');
  });
});
