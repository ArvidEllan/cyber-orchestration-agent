import * as path from 'path';
import { IaCParser, IaCFormat, ErrorCode, ErrorCategory, SecurityAgentError } from '../types';
import { TerraformParser } from './terraform-parser';
import { CloudFormationParser } from './cloudformation-parser';
import { CDKParser } from './cdk-parser';

/**
 * Factory for creating appropriate IaC parser based on file type
 */
export class ParserFactory {
  private static parsers: Map<IaCFormat, IaCParser> = new Map<IaCFormat, IaCParser>([
    [IaCFormat.TERRAFORM, new TerraformParser()],
    [IaCFormat.CLOUDFORMATION, new CloudFormationParser()],
    [IaCFormat.CDK, new CDKParser()],
  ]);

  /**
   * Get parser for the specified format
   */
  static getParser(format: IaCFormat): IaCParser {
    const parser = this.parsers.get(format);
    if (!parser) {
      throw new SecurityAgentError(
        `No parser available for format: ${format}`,
        ErrorCode.IAC_PARSE_ERROR,
        ErrorCategory.INPUT,
        false
      );
    }
    return parser;
  }

  /**
   * Detect IaC format from file path
   */
  static detectFormat(filePath: string): IaCFormat {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    // Terraform files
    if (ext === '.tf' || ext === '.tfvars') {
      return IaCFormat.TERRAFORM;
    }

    // CloudFormation files
    if (
      basename.includes('cloudformation') ||
      basename.includes('cfn') ||
      basename.includes('template')
    ) {
      if (ext === '.json' || ext === '.yaml' || ext === '.yml') {
        return IaCFormat.CLOUDFORMATION;
      }
    }

    // CDK files (TypeScript)
    if (ext === '.ts' && (basename.includes('stack') || basename.includes('cdk'))) {
      return IaCFormat.CDK;
    }

    // Default detection by extension
    if (ext === '.json' || ext === '.yaml' || ext === '.yml') {
      return IaCFormat.CLOUDFORMATION;
    }

    throw new SecurityAgentError(
      `Unable to detect IaC format for file: ${filePath}`,
      ErrorCode.IAC_PARSE_ERROR,
      ErrorCategory.INPUT,
      false
    );
  }

  /**
   * Parse file with automatic format detection
   */
  static async parseFile(filePath: string, format?: IaCFormat) {
    try {
      const detectedFormat = format || this.detectFormat(filePath);
      const parser = this.getParser(detectedFormat);
      return await parser.parse(filePath, detectedFormat);
    } catch (error) {
      if (error instanceof SecurityAgentError) {
        throw error;
      }
      throw new SecurityAgentError(
        `Failed to parse file ${filePath}: ${error}`,
        ErrorCode.IAC_PARSE_ERROR,
        ErrorCategory.INPUT,
        false,
        { filePath, originalError: error }
      );
    }
  }
}
