import * as fs from 'fs/promises';
import * as ts from 'typescript';
import {
  IaCParser,
  IaCFormat,
  ParsedInfrastructure,
  ValidationResult,
  Resource,
  Variable,
  Output,
  Metadata,
  ResourceSource,
  ValidationError,
  ValidationWarning,
} from '../types';

/**
 * Parser for AWS CDK TypeScript code
 * Analyzes CDK constructs and synthesized CloudFormation
 */
export class CDKParser implements IaCParser {
  /**
   * Parse CDK TypeScript code and extract infrastructure configuration
   */
  async parse(filePath: string, format: IaCFormat): Promise<ParsedInfrastructure> {
    if (format !== IaCFormat.CDK) {
      throw new Error(`CDKParser only supports CDK format, got ${format}`);
    }

    try {
      // Parse TypeScript AST
      const sourceFile = await this.parseTypeScript(filePath);
      
      // Extract CDK constructs from AST
      const constructs = this.extractCDKConstructs(sourceFile);
      
      // Try to synthesize CloudFormation if possible
      const synthesized = await this.trySynthesizeCDK(filePath);
      
      const resources = this.normalizeConstructs(constructs, synthesized, filePath);
      const variables = this.extractVariables(sourceFile);
      const outputs = this.extractOutputs(constructs);
      const metadata = this.extractMetadata(sourceFile);

      return {
        format: IaCFormat.CDK,
        resources,
        variables,
        outputs,
        metadata,
      };
    } catch (error) {
      throw new Error(`Failed to parse CDK file ${filePath}: ${error}`);
    }
  }

  /**
   * Validate parsed infrastructure
   */
  validate(parsed: ParsedInfrastructure): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (parsed.format !== IaCFormat.CDK) {
      errors.push({
        message: `Expected CDK format, got ${parsed.format}`,
        code: 'INVALID_FORMAT',
      });
    }

    for (const resource of parsed.resources) {
      if (!resource.id) {
        errors.push({
          message: `Resource missing ID`,
          code: 'MISSING_RESOURCE_ID',
        });
      }

      if (!resource.type) {
        errors.push({
          message: `Resource ${resource.id} missing type`,
          code: 'MISSING_RESOURCE_TYPE',
        });
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Extract resources from parsed infrastructure
   */
  extractResources(parsed: ParsedInfrastructure): Resource[] {
    return parsed.resources;
  }

  /**
   * Parse TypeScript file using TypeScript compiler API
   */
  private async parseTypeScript(filePath: string): Promise<ts.SourceFile> {
    const content = await fs.readFile(filePath, 'utf-8');
    return ts.createSourceFile(
      filePath,
      content,
      ts.ScriptTarget.Latest,
      true
    );
  }

  /**
   * Extract CDK constructs from TypeScript AST
   */
  private extractCDKConstructs(sourceFile: ts.SourceFile): Array<Record<string, any>> {
    const constructs: Array<Record<string, any>> = [];

    const visit = (node: ts.Node) => {
      // Look for new expressions (e.g., new s3.Bucket(...))
      if (ts.isNewExpression(node)) {
        const construct = this.parseConstructExpression(node);
        if (construct) {
          constructs.push(construct);
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return constructs;
  }

  /**
   * Parse a CDK construct expression
   */
  private parseConstructExpression(node: ts.NewExpression): Record<string, any> | null {
    const expression = node.expression;
    
    // Get construct type (e.g., s3.Bucket)
    let constructType = '';
    if (ts.isPropertyAccessExpression(expression)) {
      const namespace = expression.expression.getText();
      const className = expression.name.getText();
      constructType = `${namespace}.${className}`;
    } else if (ts.isIdentifier(expression)) {
      constructType = expression.getText();
    }

    // Extract constructor arguments
    const args = node.arguments || [];
    const properties: Record<string, any> = {};
    
    // Third argument is typically the props object
    if (args.length >= 3 && ts.isObjectLiteralExpression(args[2])) {
      this.extractObjectProperties(args[2], properties);
    }

    return {
      type: constructType,
      id: args[1]?.getText().replace(/['"]/g, '') || 'unknown',
      properties,
    };
  }

  /**
   * Extract properties from object literal
   */
  private extractObjectProperties(obj: ts.ObjectLiteralExpression, target: Record<string, any>): void {
    for (const prop of obj.properties) {
      if (ts.isPropertyAssignment(prop)) {
        const name = prop.name.getText();
        const value = this.extractValue(prop.initializer);
        target[name] = value;
      }
    }
  }

  /**
   * Extract value from expression
   */
  private extractValue(node: ts.Expression): any {
    if (ts.isStringLiteral(node) || ts.isNumericLiteral(node)) {
      return node.text;
    }
    
    if (node.kind === ts.SyntaxKind.TrueKeyword) {
      return true;
    }
    
    if (node.kind === ts.SyntaxKind.FalseKeyword) {
      return false;
    }

    if (ts.isObjectLiteralExpression(node)) {
      const obj: Record<string, any> = {};
      this.extractObjectProperties(node, obj);
      return obj;
    }

    if (ts.isArrayLiteralExpression(node)) {
      return node.elements.map((el) => this.extractValue(el as ts.Expression));
    }

    // For complex expressions, return the text representation
    return node.getText();
  }

  /**
   * Try to synthesize CDK to CloudFormation
   */
  private async trySynthesizeCDK(_filePath: string): Promise<Record<string, any> | null> {
    try {
      // This would require CDK to be installed and configured
      // For now, return null as synthesis is optional
      return null;
    } catch (error) {
      // Synthesis failed, continue without it
      return null;
    }
  }

  /**
   * Normalize CDK constructs to common Resource interface
   */
  private normalizeConstructs(
    constructs: Array<Record<string, any>>,
    synthesized: Record<string, any> | null,
    filePath: string
  ): Resource[] {
    const resources: Resource[] = [];

    for (const construct of constructs) {
      const resource = this.normalizeConstruct(construct, filePath);
      resources.push(resource);
    }

    // If we have synthesized CloudFormation, merge additional info
    if (synthesized && synthesized.Resources) {
      this.mergeSynthesizedResources(resources, synthesized.Resources);
    }

    return resources;
  }

  /**
   * Normalize a single CDK construct
   */
  private normalizeConstruct(construct: Record<string, any>, _filePath: string): Resource {
    const type = this.mapCDKTypeToCloudFormation(construct.type);
    const service = this.extractService(type);

    return {
      id: construct.id,
      type,
      service,
      region: construct.properties.region || 'us-east-1',
      account: 'unknown',
      properties: construct.properties,
      tags: construct.properties.tags || {},
      relationships: [],
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };
  }

  /**
   * Map CDK construct type to CloudFormation resource type
   */
  private mapCDKTypeToCloudFormation(cdkType: string): string {
    // Common CDK to CFN mappings
    const mappings: Record<string, string> = {
      's3.Bucket': 'AWS::S3::Bucket',
      'lambda.Function': 'AWS::Lambda::Function',
      'dynamodb.Table': 'AWS::DynamoDB::Table',
      'ec2.Instance': 'AWS::EC2::Instance',
      'rds.DatabaseInstance': 'AWS::RDS::DBInstance',
      'iam.Role': 'AWS::IAM::Role',
      'iam.Policy': 'AWS::IAM::Policy',
    };

    return mappings[cdkType] || cdkType;
  }

  /**
   * Extract service from resource type
   */
  private extractService(resourceType: string): string {
    const parts = resourceType.split('::');
    if (parts.length >= 2) {
      return parts[1].toLowerCase();
    }
    return 'unknown';
  }

  /**
   * Merge synthesized CloudFormation resources
   */
  private mergeSynthesizedResources(
    resources: Resource[],
    cfnResources: Record<string, any>
  ): void {
    // Match CDK constructs with synthesized resources and merge properties
    for (const resource of resources) {
      const cfnResource = cfnResources[resource.id];
      if (cfnResource) {
        resource.properties = {
          ...resource.properties,
          ...cfnResource.Properties,
        };
      }
    }
  }

  /**
   * Extract variables from CDK code
   */
  private extractVariables(sourceFile: ts.SourceFile): Variable[] {
    const variables: Variable[] = [];

    const visit = (node: ts.Node) => {
      // Look for variable declarations
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const name = node.name.getText();
        const type = node.type?.getText() || 'any';
        
        variables.push({
          name,
          type,
          defaultValue: this.extractValue(node.initializer),
        });
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return variables;
  }

  /**
   * Extract outputs from CDK constructs
   */
  private extractOutputs(constructs: Array<Record<string, any>>): Output[] {
    const outputs: Output[] = [];

    // Look for CfnOutput constructs
    for (const construct of constructs) {
      if (construct.type.includes('CfnOutput')) {
        outputs.push({
          name: construct.id,
          value: construct.properties.value,
          description: construct.properties.description,
        });
      }
    }

    return outputs;
  }

  /**
   * Extract metadata from CDK source file
   */
  private extractMetadata(sourceFile: ts.SourceFile): Metadata {
    const metadata: Metadata = {
      fileName: sourceFile.fileName,
      languageVersion: ts.ScriptTarget[sourceFile.languageVersion],
    };

    // Look for CDK version in imports
    const visit = (node: ts.Node) => {
      if (ts.isImportDeclaration(node)) {
        const moduleSpecifier = node.moduleSpecifier.getText().replace(/['"]/g, '');
        if (moduleSpecifier.startsWith('aws-cdk-lib') || moduleSpecifier.startsWith('@aws-cdk/')) {
          metadata.cdkImports = metadata.cdkImports || [];
          metadata.cdkImports.push(moduleSpecifier);
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return metadata;
  }
}
