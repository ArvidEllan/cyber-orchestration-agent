import { describe, it, expect } from 'vitest';
import { ParserFactory } from '../parser-factory';
import { IaCFormat } from '../../types';
import * as path from 'path';

describe('ParserFactory', () => {
  const fixturesDir = path.join(__dirname, 'fixtures');

  it('should detect Terraform format', () => {
    const format = ParserFactory.detectFormat(path.join(fixturesDir, 'example.tf'));
    expect(format).toBe(IaCFormat.TERRAFORM);
  });

  it('should detect CloudFormation format', () => {
    const format = ParserFactory.detectFormat(path.join(fixturesDir, 'template.json'));
    expect(format).toBe(IaCFormat.CLOUDFORMATION);
  });

  it('should detect CDK format', () => {
    const format = ParserFactory.detectFormat(path.join(fixturesDir, 'stack.ts'));
    expect(format).toBe(IaCFormat.CDK);
  });

  it('should get parser for format', () => {
    const parser = ParserFactory.getParser(IaCFormat.TERRAFORM);
    expect(parser).toBeDefined();
  });

  it('should parse file with auto-detection', async () => {
    const result = await ParserFactory.parseFile(path.join(fixturesDir, 'example.tf'));
    expect(result.format).toBe(IaCFormat.TERRAFORM);
  });
});
