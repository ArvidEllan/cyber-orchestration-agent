/**
 * Security Rules Engine
 * Main engine for evaluating security rules against resources
 */

import {
  SecurityRule,
  RuleSet,
  Resource,
  Finding,
  RuleResult,
  RuleCustomization,
  SecurityRulesEngine,
  Severity,
  FindingStatus,
  ResourceSource,
} from '../types';
import { RuleEvaluator } from './rule-evaluator';
import { RuleLoader } from './rule-loader';

export class RulesEngine implements SecurityRulesEngine {
  private rules: Map<string, SecurityRule> = new Map();
  private customizations: Map<string, RuleCustomization> = new Map();
  private evaluator: RuleEvaluator;
  private loader: RuleLoader;

  constructor() {
    this.evaluator = new RuleEvaluator();
    this.loader = new RuleLoader();
  }

  /**
   * Load rules from a rule set
   */
  loadRules(ruleSet: RuleSet): void {
    for (const rule of ruleSet.rules) {
      this.rules.set(rule.id, rule);
    }
  }

  /**
   * Load rules from a file
   */
  async loadRulesFromFile(filePath: string): Promise<void> {
    const ruleSet = await this.loader.loadFromFile(filePath);
    this.loadRules(ruleSet);
  }

  /**
   * Load rules from a directory
   */
  async loadRulesFromDirectory(dirPath: string): Promise<void> {
    const ruleSet = await this.loader.loadFromDirectory(dirPath);
    this.loadRules(ruleSet);
  }

  /**
   * Analyze resources and generate findings
   */
  analyze(resources: Resource[]): Finding[] {
    const findings: Finding[] = [];

    for (const resource of resources) {
      for (const rule of this.rules.values()) {
        // Check if rule is enabled
        const customization = this.customizations.get(rule.id);
        if (customization?.enabled === false) {
          continue;
        }

        const result = this.evaluateRule(rule, resource);
        if (!result.passed && result.finding) {
          findings.push(result.finding);
        }
      }
    }

    return findings;
  }

  /**
   * Analyze resources in parallel for better performance
   */
  async analyzeParallel(resources: Resource[]): Promise<Finding[]> {
    const batchSize = 100;
    const batches: Resource[][] = [];

    for (let i = 0; i < resources.length; i += batchSize) {
      batches.push(resources.slice(i, i + batchSize));
    }

    const results = await Promise.all(
      batches.map((batch) => Promise.resolve(this.analyze(batch)))
    );

    return results.flat();
  }

  /**
   * Evaluate a single rule against a resource
   */
  evaluateRule(rule: SecurityRule, resource: Resource): RuleResult {
    // Get customization if exists
    const customization = this.customizations.get(rule.id);
    const effectiveRule = this.applyCustomization(rule, customization);

    // Evaluate condition
    const conditionMet = this.evaluator.evaluateCondition(effectiveRule.condition, resource);

    if (conditionMet) {
      // Rule condition matched - this is a violation
      const finding = this.createFinding(effectiveRule, resource);
      return {
        rule: effectiveRule,
        passed: false,
        finding,
      };
    }

    return {
      rule: effectiveRule,
      passed: true,
    };
  }

  /**
   * Customize a rule
   */
  customizeRule(ruleId: string, customization: RuleCustomization): void {
    if (!this.rules.has(ruleId)) {
      throw new Error(`Rule not found: ${ruleId}`);
    }
    this.customizations.set(ruleId, customization);
  }

  /**
   * Get all loaded rules
   */
  getRules(): SecurityRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get a specific rule by ID
   */
  getRule(ruleId: string): SecurityRule | undefined {
    return this.rules.get(ruleId);
  }

  /**
   * Clear all rules
   */
  clearRules(): void {
    this.rules.clear();
    this.customizations.clear();
  }

  /**
   * Apply customization to a rule
   */
  private applyCustomization(
    rule: SecurityRule,
    customization?: RuleCustomization
  ): SecurityRule {
    if (!customization) {
      return rule;
    }

    return {
      ...rule,
      severity: customization.severity ?? rule.severity,
      condition: customization.condition ?? rule.condition,
    };
  }

  /**
   * Create a finding from a rule violation
   */
  private createFinding(rule: SecurityRule, resource: Resource): Finding {
    const now = new Date();
    const findingId = this.generateFindingId(rule, resource);

    return {
      id: findingId,
      ruleId: rule.id,
      resource,
      severity: rule.severity,
      category: rule.category,
      title: rule.name,
      description: rule.description,
      evidence: {
        description: `Resource ${resource.id} violates rule ${rule.id}`,
        details: {
          resourceType: resource.type,
          resourceId: resource.id,
          ruleId: rule.id,
          ruleName: rule.name,
        },
      },
      remediation: rule.remediation,
      complianceMapping: rule.frameworks.map((framework) => ({
        framework,
        controlId: rule.id,
        controlName: rule.name,
        requirement: rule.description,
        status: 'non_compliant' as const,
      })),
      riskScore: this.calculateRiskScore(rule.severity),
      status: FindingStatus.OPEN,
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * Generate a unique finding ID
   */
  private generateFindingId(rule: SecurityRule, resource: Resource): string {
    const timestamp = Date.now();
    const hash = this.simpleHash(`${rule.id}-${resource.id}-${timestamp}`);
    return `finding-${hash}`;
  }

  /**
   * Simple hash function for generating IDs
   */
  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Calculate risk score based on severity
   */
  private calculateRiskScore(severity: Severity): number {
    switch (severity) {
      case Severity.CRITICAL:
        return 10;
      case Severity.HIGH:
        return 8;
      case Severity.MEDIUM:
        return 5;
      case Severity.LOW:
        return 3;
      case Severity.INFO:
        return 1;
      default:
        return 5;
    }
  }
}
