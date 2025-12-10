import * as fs from 'fs/promises';
import * as yaml from 'js-yaml';
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

interface CFNTemplate {
  AWSTemplateFormatVersion?: string;
  Description?: string;
  Parameters?: Record<string, any>;
  Resources?: Record<string, any>;
  Outputs?: Record<string, any>;
  Mappings?: Record<string, any>;
  Conditions?: Record<string, any>;
  Metadata?: Record<string, any>;
}

/**
 * Parser for AWS CloudFormation templates (JSON/YAML)
 * Handles intrinsic functions and resource normalization
 */
export class CloudFormationParser implements IaCParser {
  /**
   * Parse CloudFormation template and extract infrastructure configuration
   */
  async parse(filePath: string, format: IaCFormat): Promise<ParsedInfrastructure> {
    if (format !== IaCFormat.CLOUDFORMATION) {
      throw new Error(`CloudFormationParser only supports CLOUDFORMATION format, got ${format}`);
    }

    try {
      const template = await this.loadTemplate(filePath);
      const resources = this.extractResourcesFromTemplate(template, filePath);
      const variables = this.extractParameters(template);
      const outputs = this.extractOutputs(template);
      const metadata = this.extractMetadata(template);

      return {
        format: IaCFormat.CLOUDFORMATION,
        resources,
        variables,
        outputs,
        metadata,
      };
    } catch (error) {
      throw new Error(`Failed to parse CloudFormation template ${filePath}: ${error}`);
    }
  }

  /**
   * Validate parsed infrastructure
   */
  validate(parsed: ParsedInfrastructure): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (parsed.format !== IaCFormat.CLOUDFORMATION) {
      errors.push({
        message: `Expected CLOUDFORMATION format, got ${parsed.format}`,
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
   * Load CloudFormation template from file (JSON or YAML)
   */
  private async loadTemplate(filePath: string): Promise<CFNTemplate> {
    const content = await fs.readFile(filePath, 'utf-8');
    
    if (filePath.endsWith('.json')) {
      return JSON.parse(content);
    } else if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      return yaml.load(content) as CFNTemplate;
    } else {
      // Try JSON first, then YAML
      try {
        return JSON.parse(content);
      } catch {
        return yaml.load(content) as CFNTemplate;
      }
    }
  }

  /**
   * Extract resources from CloudFormation template
   */
  private extractResourcesFromTemplate(template: CFNTemplate, filePath: string): Resource[] {
    const resources: Resource[] = [];

    if (!template.Resources) {
      return resources;
    }

    for (const [logicalId, resourceConfig] of Object.entries(template.Resources)) {
      const resource = this.normalizeResource(logicalId, resourceConfig, filePath);
      resources.push(resource);
    }

    return resources;
  }

  /**
   * Normalize CloudFormation resource to common Resource interface
   */
  private normalizeResource(
    logicalId: string,
    config: Record<string, any>,
    _filePath: string
  ): Resource {
    const type = config.Type;
    const service = this.extractService(type);
    const properties = this.resolveIntrinsicFunctions(config.Properties || {});
    const tags = this.extractTags(properties);
    const relationships = this.extractDependencies(config);

    return {
      id: logicalId,
      type,
      service,
      region: properties.Region || 'us-east-1',
      account: 'unknown',
      properties,
      tags,
      relationships,
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };
  }

  /**
   * Extract service name from CloudFormation resource type
   */
  private extractService(resourceType: string): string {
    // Format: AWS::Service::Resource (e.g., AWS::S3::Bucket)
    const parts = resourceType.split('::');
    if (parts.length >= 2) {
      return parts[1].toLowerCase();
    }
    return 'unknown';
  }

  /**
   * Resolve CloudFormation intrinsic functions
   */
  private resolveIntrinsicFunctions(obj: any): any {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.resolveIntrinsicFunctions(item));
    }

    // Handle intrinsic functions
    if ('Ref' in obj) {
      return { __ref: obj.Ref };
    }

    if ('Fn::GetAtt' in obj) {
      return { __getatt: obj['Fn::GetAtt'] };
    }

    if ('Fn::Sub' in obj) {
      return { __sub: obj['Fn::Sub'] };
    }

    if ('Fn::Join' in obj) {
      return { __join: obj['Fn::Join'] };
    }

    if ('Fn::Select' in obj) {
      return { __select: obj['Fn::Select'] };
    }

    if ('Fn::GetAZs' in obj) {
      return { __getazs: obj['Fn::GetAZs'] };
    }

    if ('Fn::ImportValue' in obj) {
      return { __import: obj['Fn::ImportValue'] };
    }

    // Recursively process nested objects
    const resolved: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      resolved[key] = this.resolveIntrinsicFunctions(value);
    }
    return resolved;
  }

  /**
   * Extract tags from resource properties
   */
  private extractTags(properties: Record<string, any>): Record<string, string> {
    const tags: Record<string, string> = {};

    if (properties.Tags && Array.isArray(properties.Tags)) {
      for (const tag of properties.Tags) {
        if (tag.Key && tag.Value) {
          tags[tag.Key] = tag.Value;
        }
      }
    }

    return tags;
  }

  /**
   * Extract dependencies from resource configuration
   */
  private extractDependencies(config: Record<string, any>): Array<{ type: string; targetId: string }> {
    const relationships: Array<{ type: string; targetId: string }> = [];

    // Explicit DependsOn
    if (config.DependsOn) {
      const deps = Array.isArray(config.DependsOn) ? config.DependsOn : [config.DependsOn];
      for (const dep of deps) {
        relationships.push({
          type: 'depends_on',
          targetId: dep,
        });
      }
    }

    // Find implicit dependencies through Ref and GetAtt
    this.findReferences(config.Properties, relationships);

    return relationships;
  }

  /**
   * Find resource references in properties
   */
  private findReferences(obj: any, relationships: Array<{ type: string; targetId: string }>): void {
    if (typeof obj !== 'object' || obj === null) {
      return;
    }

    if ('Ref' in obj && typeof obj.Ref === 'string') {
      relationships.push({
        type: 'reference',
        targetId: obj.Ref,
      });
    }

    if ('Fn::GetAtt' in obj && Array.isArray(obj['Fn::GetAtt'])) {
      relationships.push({
        type: 'getatt',
        targetId: obj['Fn::GetAtt'][0],
      });
    }

    // Recursively search
    for (const value of Object.values(obj)) {
      if (typeof value === 'object') {
        this.findReferences(value, relationships);
      }
    }
  }

  /**
   * Extract parameters as variables
   */
  private extractParameters(template: CFNTemplate): Variable[] {
    const variables: Variable[] = [];

    if (!template.Parameters) {
      return variables;
    }

    for (const [paramName, paramConfig] of Object.entries(template.Parameters)) {
      variables.push({
        name: paramName,
        type: paramConfig.Type || 'String',
        defaultValue: paramConfig.Default,
        description: paramConfig.Description,
      });
    }

    return variables;
  }

  /**
   * Extract outputs
   */
  private extractOutputs(template: CFNTemplate): Output[] {
    const outputs: Output[] = [];

    if (!template.Outputs) {
      return outputs;
    }

    for (const [outputName, outputConfig] of Object.entries(template.Outputs)) {
      outputs.push({
        name: outputName,
        value: outputConfig.Value,
        description: outputConfig.Description,
      });
    }

    return outputs;
  }

  /**
   * Extract metadata
   */
  private extractMetadata(template: CFNTemplate): Metadata {
    return {
      version: template.AWSTemplateFormatVersion,
      description: template.Description,
      ...template.Metadata,
    };
  }
}
