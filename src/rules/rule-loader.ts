/**
 * Rule Loader
 * Loads security rules from YAML/JSON files
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
import { SecurityRule, RuleSet, Severity, Category, ComplianceFramework } from '../types';

export class RuleLoader {
  /**
   * Load rules from a file
   */
  async loadFromFile(filePath: string): Promise<RuleSet> {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.yaml' || ext === '.yml') {
      return this.parseYaml(content);
    } else if (ext === '.json') {
      return this.parseJson(content);
    } else {
      throw new Error(`Unsupported file format: ${ext}`);
    }
  }

  /**
   * Load rules from a directory
   */
  async loadFromDirectory(dirPath: string): Promise<RuleSet> {
    const files = await fs.promises.readdir(dirPath);
    const ruleFiles = files.filter((f) =>
      ['.yaml', '.yml', '.json'].includes(path.extname(f).toLowerCase())
    );

    const ruleSets = await Promise.all(
      ruleFiles.map((f) => this.loadFromFile(path.join(dirPath, f)))
    );

    // Merge all rule sets
    return this.mergeRuleSets(ruleSets);
  }

  /**
   * Load built-in rules
   */
  async loadBuiltInRules(category?: Category): Promise<RuleSet> {
    const builtInPath = path.join(__dirname, 'definitions');
    
    if (category) {
      const filePath = path.join(builtInPath, `${category}-rules.yaml`);
      if (fs.existsSync(filePath)) {
        return this.loadFromFile(filePath);
      }
      return { name: category, version: '1.0.0', rules: [] };
    }

    return this.loadFromDirectory(builtInPath);
  }

  /**
   * Parse YAML content
   */
  private parseYaml(content: string): RuleSet {
    const data = yaml.parse(content);
    return this.validateAndNormalize(data);
  }

  /**
   * Parse JSON content
   */
  private parseJson(content: string): RuleSet {
    const data = JSON.parse(content);
    return this.validateAndNormalize(data);
  }

  /**
   * Validate and normalize rule set
   */
  private validateAndNormalize(data: any): RuleSet {
    if (!data.name || !data.rules || !Array.isArray(data.rules)) {
      throw new Error('Invalid rule set format: missing name or rules array');
    }

    const rules: SecurityRule[] = data.rules.map((rule: any) => {
      if (!rule.id || !rule.name || !rule.condition) {
        throw new Error(`Invalid rule format: ${JSON.stringify(rule)}`);
      }

      return {
        id: rule.id,
        name: rule.name,
        description: rule.description || '',
        severity: this.normalizeSeverity(rule.severity),
        category: this.normalizeCategory(rule.category),
        frameworks: this.normalizeFrameworks(rule.frameworks || []),
        condition: rule.condition,
        remediation: rule.remediation || {
          description: '',
          steps: [],
        },
      };
    });

    return {
      name: data.name,
      version: data.version || '1.0.0',
      rules,
    };
  }

  /**
   * Normalize severity value
   */
  private normalizeSeverity(severity: string): Severity {
    const normalized = severity?.toLowerCase();
    switch (normalized) {
      case 'critical':
        return Severity.CRITICAL;
      case 'high':
        return Severity.HIGH;
      case 'medium':
        return Severity.MEDIUM;
      case 'low':
        return Severity.LOW;
      case 'info':
        return Severity.INFO;
      default:
        return Severity.MEDIUM;
    }
  }

  /**
   * Normalize category value
   */
  private normalizeCategory(category: string): Category {
    const normalized = category?.toLowerCase();
    switch (normalized) {
      case 'iam':
        return Category.IAM;
      case 'network':
        return Category.NETWORK;
      case 'encryption':
        return Category.ENCRYPTION;
      case 'logging':
        return Category.LOGGING;
      case 'compute':
        return Category.COMPUTE;
      case 'storage':
        return Category.STORAGE;
      case 'database':
        return Category.DATABASE;
      case 'container':
        return Category.CONTAINER;
      case 'api':
        return Category.API;
      default:
        return Category.IAM;
    }
  }

  /**
   * Normalize framework values
   */
  private normalizeFrameworks(frameworks: string[]): ComplianceFramework[] {
    return frameworks
      .map((f) => {
        const normalized = f.toLowerCase().replace(/[- ]/g, '_');
        switch (normalized) {
          case 'cis_aws':
          case 'cis_aws_foundations':
            return ComplianceFramework.CIS_AWS;
          case 'aws_well_architected':
            return ComplianceFramework.AWS_WELL_ARCHITECTED;
          case 'iso_27001':
            return ComplianceFramework.ISO_27001;
          case 'nist_800_53':
            return ComplianceFramework.NIST_800_53;
          case 'pci_dss':
            return ComplianceFramework.PCI_DSS;
          case 'hipaa':
            return ComplianceFramework.HIPAA;
          case 'soc2':
            return ComplianceFramework.SOC2;
          default:
            return null;
        }
      })
      .filter((f): f is ComplianceFramework => f !== null);
  }

  /**
   * Merge multiple rule sets
   */
  private mergeRuleSets(ruleSets: RuleSet[]): RuleSet {
    if (ruleSets.length === 0) {
      return { name: 'empty', version: '1.0.0', rules: [] };
    }

    if (ruleSets.length === 1) {
      return ruleSets[0];
    }

    const allRules: SecurityRule[] = [];
    const seenIds = new Set<string>();

    for (const ruleSet of ruleSets) {
      for (const rule of ruleSet.rules) {
        if (!seenIds.has(rule.id)) {
          allRules.push(rule);
          seenIds.add(rule.id);
        }
      }
    }

    return {
      name: 'merged',
      version: '1.0.0',
      rules: allRules,
    };
  }
}
