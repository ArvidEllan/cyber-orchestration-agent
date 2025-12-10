import * as fs from 'fs/promises';
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

interface HCLParsedOutput {
  resource?: Record<string, Record<string, Record<string, any>>>;
  variable?: Record<string, any>;
  output?: Record<string, any>;
  terraform?: Record<string, any>;
  provider?: Record<string, any>;
}

/**
 * Parser for Terraform (.tf) files
 * Handles HCL parsing, resource extraction, and normalization
 */
export class TerraformParser implements IaCParser {
  /**
   * Parse Terraform files and extract infrastructure configuration
   */
  async parse(filePath: string, format: IaCFormat): Promise<ParsedInfrastructure> {
    if (format !== IaCFormat.TERRAFORM) {
      throw new Error(`TerraformParser only supports TERRAFORM format, got ${format}`);
    }

    try {
      const hclContent = await this.parseHCL(filePath);
      const resources = this.extractResourcesFromHCL(hclContent, filePath);
      const variables = this.extractVariables(hclContent);
      const outputs = this.extractOutputs(hclContent);
      const metadata = this.extractMetadata(hclContent);

      return {
        format: IaCFormat.TERRAFORM,
        resources,
        variables,
        outputs,
        metadata,
      };
    } catch (error) {
      throw new Error(`Failed to parse Terraform file ${filePath}: ${error}`);
    }
  }

  /**
   * Validate parsed infrastructure
   */
  validate(parsed: ParsedInfrastructure): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validate format
    if (parsed.format !== IaCFormat.TERRAFORM) {
      errors.push({
        message: `Expected TERRAFORM format, got ${parsed.format}`,
        code: 'INVALID_FORMAT',
      });
    }

    // Validate resources
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

      // Check for common misconfigurations
      if (resource.type === 'aws_s3_bucket' && resource.properties.acl === 'public-read') {
        warnings.push({
          message: `Resource ${resource.id} has public-read ACL`,
          code: 'PUBLIC_S3_BUCKET',
        });
      }
    }

    // Validate variable references
    const variableNames = new Set(parsed.variables.map((v) => v.name));
    for (const resource of parsed.resources) {
      this.checkVariableReferences(resource.properties, variableNames, warnings);
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
   * Parse HCL content using hcl2json
   * Note: This requires terraform or hcl2json to be installed
   */
  private async parseHCL(filePath: string): Promise<HCLParsedOutput> {
    try {
      // Check if file exists
      await fs.access(filePath);

      // For now, return a basic parsed structure
      // In production, this would use terraform show -json or hcl2json
      const content = await fs.readFile(filePath, 'utf-8');
      
      // Simple regex-based parsing for basic Terraform syntax
      // This is a simplified implementation for demonstration
      return this.parseHCLSimple(content);
    } catch (error) {
      throw new Error(`Failed to parse HCL: ${error}`);
    }
  }

  /**
   * Simple HCL parser for basic Terraform syntax
   * Note: This is a simplified implementation. Production use should use proper HCL parser.
   */
  private parseHCLSimple(content: string): HCLParsedOutput {
    const result: HCLParsedOutput = {};

    // Parse resources
    const resourceRegex = /resource\s+"([^"]+)"\s+"([^"]+)"\s+\{([^}]+)\}/gs;
    let match;
    
    while ((match = resourceRegex.exec(content)) !== null) {
      const [, type, name, body] = match;
      if (!result.resource) result.resource = {};
      if (!result.resource[type]) result.resource[type] = {};
      result.resource[type][name] = this.parseBlock(body);
    }

    // Parse variables
    const variableRegex = /variable\s+"([^"]+)"\s+\{([^}]+)\}/gs;
    while ((match = variableRegex.exec(content)) !== null) {
      const [, name, body] = match;
      if (!result.variable) result.variable = {};
      result.variable[name] = this.parseBlock(body);
    }

    // Parse outputs
    const outputRegex = /output\s+"([^"]+)"\s+\{([^}]+)\}/gs;
    while ((match = outputRegex.exec(content)) !== null) {
      const [, name, body] = match;
      if (!result.output) result.output = {};
      result.output[name] = this.parseBlock(body);
    }

    return result;
  }

  /**
   * Parse a block of HCL content
   */
  private parseBlock(content: string): Record<string, any> {
    const result: Record<string, any> = {};
    
    // Parse simple key = value pairs
    const kvRegex = /(\w+)\s*=\s*([^\n]+)/g;
    let match;
    
    while ((match = kvRegex.exec(content)) !== null) {
      const [, key, value] = match;
      result[key] = value.trim().replace(/^["']|["']$/g, '');
    }

    return result;
  }

  /**
   * Extract resources from HCL parsed output
   */
  private extractResourcesFromHCL(hcl: HCLParsedOutput, filePath: string): Resource[] {
    const resources: Resource[] = [];

    if (!hcl.resource) {
      return resources;
    }

    // Iterate through resource types
    for (const [resourceType, resourceInstances] of Object.entries(hcl.resource)) {
      // Iterate through resource instances
      for (const [resourceName, resourceConfig] of Object.entries(resourceInstances)) {
        const resource = this.normalizeResource(
          resourceType,
          resourceName,
          resourceConfig,
          filePath
        );
        resources.push(resource);
      }
    }

    return resources;
  }

  /**
   * Normalize Terraform resource to common Resource interface
   */
  private normalizeResource(
    type: string,
    name: string,
    config: Record<string, any>,
    _filePath: string
  ): Resource {
    // Extract service from resource type (e.g., aws_s3_bucket -> s3)
    const service = this.extractService(type);

    // Handle variable interpolation
    const properties = this.resolveVariableInterpolation(config);

    // Extract tags
    const tags = properties.tags || {};

    // Extract dependencies
    const relationships = this.extractDependencies(config);

    return {
      id: `${type}.${name}`,
      type,
      service,
      region: properties.region || 'us-east-1', // Default region
      account: properties.account || 'unknown',
      properties,
      tags,
      relationships,
      source: ResourceSource.IAC,
      timestamp: new Date(),
    };
  }

  /**
   * Extract service name from resource type
   */
  private extractService(resourceType: string): string {
    // Format: provider_service_resource (e.g., aws_s3_bucket)
    const parts = resourceType.split('_');
    if (parts.length >= 2) {
      return parts[1]; // Return service part
    }
    return 'unknown';
  }

  /**
   * Resolve variable interpolation in properties
   */
  private resolveVariableInterpolation(config: Record<string, any>): Record<string, any> {
    const resolved: Record<string, any> = {};

    for (const [key, value] of Object.entries(config)) {
      if (typeof value === 'string' && value.includes('${var.')) {
        // Mark as variable reference but keep the reference string
        resolved[key] = value;
      } else if (typeof value === 'object' && value !== null) {
        resolved[key] = this.resolveVariableInterpolation(value);
      } else {
        resolved[key] = value;
      }
    }

    return resolved;
  }

  /**
   * Extract dependencies from resource configuration
   */
  private extractDependencies(config: Record<string, any>): Array<{ type: string; targetId: string }> {
    const relationships: Array<{ type: string; targetId: string }> = [];

    // Check for explicit depends_on
    if (config.depends_on && Array.isArray(config.depends_on)) {
      for (const dep of config.depends_on) {
        relationships.push({
          type: 'depends_on',
          targetId: dep,
        });
      }
    }

    // Check for implicit dependencies (resource references)
    this.findResourceReferences(config, relationships);

    return relationships;
  }

  /**
   * Find resource references in configuration
   */
  private findResourceReferences(
    obj: any,
    relationships: Array<{ type: string; targetId: string }>
  ): void {
    if (typeof obj === 'string') {
      // Look for resource references like ${aws_s3_bucket.example.id}
      const refMatch = obj.match(/\$\{([a-z_]+\.[a-z_]+)\./);
      if (refMatch) {
        relationships.push({
          type: 'reference',
          targetId: refMatch[1],
        });
      }
    } else if (Array.isArray(obj)) {
      obj.forEach((item) => this.findResourceReferences(item, relationships));
    } else if (typeof obj === 'object' && obj !== null) {
      Object.values(obj).forEach((value) => this.findResourceReferences(value, relationships));
    }
  }

  /**
   * Extract variables from HCL
   */
  private extractVariables(hcl: HCLParsedOutput): Variable[] {
    const variables: Variable[] = [];

    if (!hcl.variable) {
      return variables;
    }

    for (const [varName, varConfig] of Object.entries(hcl.variable)) {
      variables.push({
        name: varName,
        type: varConfig.type || 'string',
        defaultValue: varConfig.default,
        description: varConfig.description,
      });
    }

    return variables;
  }

  /**
   * Extract outputs from HCL
   */
  private extractOutputs(hcl: HCLParsedOutput): Output[] {
    const outputs: Output[] = [];

    if (!hcl.output) {
      return outputs;
    }

    for (const [outputName, outputConfig] of Object.entries(hcl.output)) {
      outputs.push({
        name: outputName,
        value: outputConfig.value,
        description: outputConfig.description,
      });
    }

    return outputs;
  }

  /**
   * Extract metadata from HCL
   */
  private extractMetadata(hcl: HCLParsedOutput): Metadata {
    const metadata: Metadata = {};

    if (hcl.terraform) {
      metadata.terraformVersion = hcl.terraform.required_version;
      metadata.requiredProviders = hcl.terraform.required_providers;
    }

    if (hcl.provider) {
      metadata.providers = hcl.provider;
    }

    return metadata;
  }

  /**
   * Check for undefined variable references
   */
  private checkVariableReferences(
    obj: any,
    variableNames: Set<string>,
    warnings: ValidationWarning[]
  ): void {
    if (typeof obj === 'string') {
      const varMatch = obj.match(/\$\{var\.([a-z_]+)\}/);
      if (varMatch && !variableNames.has(varMatch[1])) {
        warnings.push({
          message: `Reference to undefined variable: ${varMatch[1]}`,
          code: 'UNDEFINED_VARIABLE',
        });
      }
    } else if (Array.isArray(obj)) {
      obj.forEach((item) => this.checkVariableReferences(item, variableNames, warnings));
    } else if (typeof obj === 'object' && obj !== null) {
      Object.values(obj).forEach((value) =>
        this.checkVariableReferences(value, variableNames, warnings)
      );
    }
  }
}
