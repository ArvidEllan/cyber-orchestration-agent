/**
 * Risk Narrator
 * Uses AI to generate executive-friendly risk summaries and narratives
 */

import Anthropic from '@anthropic-ai/sdk';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Finding, Severity } from '../types/core';

/**
 * Risk narrative structure
 */
export interface RiskNarrative {
  executiveSummary: string;
  riskOverview: string;
  topRisks: Array<{
    title: string;
    impact: string;
    likelihood: string;
    recommendation: string;
  }>;
  complianceImpact: string;
  recommendedActions: string[];
  timeline: string;
  generatedAt: Date;
}

/**
 * Options for narrative generation
 */
export interface NarrativeOptions {
  audience?: 'executive' | 'technical' | 'compliance';
  maxLength?: 'brief' | 'standard' | 'detailed';
  includeMetrics?: boolean;
}

/**
 * Risk Narrator Class
 */
export class RiskNarrator {
  private client: Anthropic | null = null;
  private cacheDir: string;
  private enabled: boolean;

  constructor(options?: { cacheDir?: string }) {
    this.cacheDir = options?.cacheDir || '.narrative-cache';
    this.enabled = this.initializeClient();
  }

  /**
   * Initialize the Anthropic client
   */
  private initializeClient(): boolean {
    const apiKey = process.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      return false;
    }

    try {
      this.client = new Anthropic({ apiKey });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if AI narration is available
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Generate a risk narrative from findings
   */
  async generateNarrative(
    findings: Finding[],
    options: NarrativeOptions = {}
  ): Promise<RiskNarrative> {
    const stats = this.calculateStats(findings);

    if (!this.enabled || !this.client) {
      return this.generateFallbackNarrative(findings, stats);
    }

    // Check cache
    const cacheKey = this.generateCacheKey(findings, options);
    const cached = await this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const prompt = this.buildNarrativePrompt(findings, stats, options);

      const response = await this.client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2048,
        temperature: 0.4,
        messages: [
          {
            role: 'user',
            content: prompt,
          },
        ],
      });

      const content = response.content[0];
      if (content.type !== 'text') {
        return this.generateFallbackNarrative(findings, stats);
      }

      const narrative = this.parseNarrativeResponse(content.text);

      // Cache result
      await this.saveToCache(cacheKey, narrative);

      return narrative;
    } catch (error) {
      console.error('Risk narrative generation failed:', error);
      return this.generateFallbackNarrative(findings, stats);
    }
  }

  /**
   * Calculate statistics from findings
   */
  private calculateStats(findings: Finding[]): {
    total: number;
    bySeverity: Record<Severity, number>;
    byFramework: Record<string, number>;
    uniqueResources: number;
    criticalCount: number;
    highCount: number;
  } {
    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const byFramework: Record<string, number> = {};
    const resources = new Set<string>();

    for (const finding of findings) {
      bySeverity[finding.severity]++;
      resources.add(finding.resource.id);

      if (finding.frameworks) {
        for (const fw of finding.frameworks) {
          byFramework[fw.framework] = (byFramework[fw.framework] || 0) + 1;
        }
      }
    }

    return {
      total: findings.length,
      bySeverity,
      byFramework,
      uniqueResources: resources.size,
      criticalCount: bySeverity.CRITICAL,
      highCount: bySeverity.HIGH,
    };
  }

  /**
   * Build the prompt for narrative generation
   */
  private buildNarrativePrompt(
    findings: Finding[],
    stats: ReturnType<typeof this.calculateStats>,
    options: NarrativeOptions
  ): string {
    const audience = options.audience || 'executive';
    const maxLength = options.maxLength || 'standard';

    const topFindings = findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .slice(0, 5);

    const lengthGuidance = {
      brief: 'Keep responses concise, 2-3 sentences per section.',
      standard: 'Provide balanced detail, 4-6 sentences per section.',
      detailed: 'Provide comprehensive analysis with specific details.',
    };

    return `You are a cybersecurity risk analyst. Generate a risk narrative for ${audience} audience based on these infrastructure security findings.

**Statistics:**
- Total Findings: ${stats.total}
- Critical: ${stats.criticalCount}
- High: ${stats.highCount}
- Medium: ${stats.bySeverity.MEDIUM}
- Low: ${stats.bySeverity.LOW}
- Affected Resources: ${stats.uniqueResources}
- Compliance Frameworks: ${Object.keys(stats.byFramework).join(', ') || 'None mapped'}

**Top Risk Findings:**
${topFindings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title}
   Resource: ${f.resource.id}
   Description: ${f.description}`).join('\n\n')}

**Guidance:** ${lengthGuidance[maxLength]}

Generate a structured risk narrative with the following sections:

---EXECUTIVE_SUMMARY---
[2-3 sentence summary for leadership]

---RISK_OVERVIEW---
[Overall risk posture assessment]

---TOP_RISKS---
[For each critical/high finding, provide:
- Title
- Impact: [business impact]
- Likelihood: [exploitation likelihood]
- Recommendation: [key action]]

---COMPLIANCE_IMPACT---
[How findings affect compliance posture]

---RECOMMENDED_ACTIONS---
[Prioritized list of remediation actions]

---TIMELINE---
[Suggested remediation timeline]`;
  }

  /**
   * Parse the AI response into a RiskNarrative
   */
  private parseNarrativeResponse(response: string): RiskNarrative {
    const extractSection = (name: string): string => {
      const regex = new RegExp(`---${name}---\\s*([\\s\\S]*?)(?=---[A-Z_]+---|$)`);
      const match = response.match(regex);
      return match ? match[1].trim() : '';
    };

    const topRisksText = extractSection('TOP_RISKS');
    const topRisks: RiskNarrative['topRisks'] = [];

    // Parse top risks
    const riskBlocks = topRisksText.split(/\n(?=[-*]|\d+\.)/);
    for (const block of riskBlocks) {
      if (block.trim()) {
        const titleMatch = block.match(/^[-*\d.]*\s*(.+?)(?:\n|$)/);
        const impactMatch = block.match(/Impact:\s*(.+?)(?:\n|$)/i);
        const likelihoodMatch = block.match(/Likelihood:\s*(.+?)(?:\n|$)/i);
        const recommendationMatch = block.match(/Recommendation:\s*(.+?)(?:\n|$)/i);

        if (titleMatch) {
          topRisks.push({
            title: titleMatch[1].trim(),
            impact: impactMatch ? impactMatch[1].trim() : 'Not specified',
            likelihood: likelihoodMatch ? likelihoodMatch[1].trim() : 'Not specified',
            recommendation: recommendationMatch ? recommendationMatch[1].trim() : 'Review and remediate',
          });
        }
      }
    }

    const actionsText = extractSection('RECOMMENDED_ACTIONS');
    const recommendedActions = actionsText
      .split('\n')
      .filter((line) => line.trim())
      .map((line) => line.replace(/^[-*\d.]\s*/, '').trim());

    return {
      executiveSummary: extractSection('EXECUTIVE_SUMMARY'),
      riskOverview: extractSection('RISK_OVERVIEW'),
      topRisks,
      complianceImpact: extractSection('COMPLIANCE_IMPACT'),
      recommendedActions,
      timeline: extractSection('TIMELINE'),
      generatedAt: new Date(),
    };
  }

  /**
   * Generate fallback narrative without AI
   */
  private generateFallbackNarrative(
    findings: Finding[],
    stats: ReturnType<typeof this.calculateStats>
  ): RiskNarrative {
    const riskLevel = stats.criticalCount > 0 ? 'critical' : stats.highCount > 0 ? 'high' : 'moderate';

    return {
      executiveSummary: `Infrastructure security scan identified ${stats.total} finding(s) across ${stats.uniqueResources} resource(s). ` +
        `${stats.criticalCount} critical and ${stats.highCount} high severity issues require immediate attention.`,

      riskOverview: `The current security posture presents ${riskLevel} risk. ` +
        `${stats.criticalCount + stats.highCount} high-priority findings could lead to unauthorized access, data exposure, or compliance violations.`,

      topRisks: findings
        .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
        .slice(0, 3)
        .map((f) => ({
          title: f.title,
          impact: f.severity === 'CRITICAL' ? 'Potential data breach or system compromise' : 'Elevated security risk',
          likelihood: f.severity === 'CRITICAL' ? 'High - actively exploitable' : 'Medium - requires specific conditions',
          recommendation: `Address ${f.resource.id} immediately`,
        })),

      complianceImpact: Object.keys(stats.byFramework).length > 0
        ? `Findings impact compliance with: ${Object.keys(stats.byFramework).join(', ')}. ` +
          `Non-compliance may result in audit findings and regulatory penalties.`
        : 'No specific compliance framework mappings identified.',

      recommendedActions: [
        stats.criticalCount > 0 ? 'Immediately remediate all CRITICAL findings' : null,
        stats.highCount > 0 ? 'Address HIGH severity findings within 7 days' : null,
        'Review and update infrastructure-as-code templates',
        'Implement automated security scanning in CI/CD pipeline',
        'Schedule recurring security assessments',
      ].filter(Boolean) as string[],

      timeline: stats.criticalCount > 0
        ? 'Critical issues: 24-48 hours. High issues: 1 week. Medium/Low: 30 days.'
        : 'High issues: 1 week. Medium issues: 2 weeks. Low issues: 30 days.',

      generatedAt: new Date(),
    };
  }

  /**
   * Generate cache key
   */
  private generateCacheKey(findings: Finding[], options: NarrativeOptions): string {
    const data = JSON.stringify({
      findingIds: findings.map((f) => f.id).sort(),
      options,
    });
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Get from cache
   */
  private async getFromCache(key: string): Promise<RiskNarrative | null> {
    try {
      const cachePath = path.join(this.cacheDir, `${key}.json`);
      const data = await fs.readFile(cachePath, 'utf-8');
      const cached = JSON.parse(data);

      // Cache valid for 1 hour
      const age = Date.now() - new Date(cached.generatedAt).getTime();
      if (age < 60 * 60 * 1000) {
        return cached;
      }
    } catch {
      // Cache miss
    }
    return null;
  }

  /**
   * Save to cache
   */
  private async saveToCache(key: string, narrative: RiskNarrative): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      const cachePath = path.join(this.cacheDir, `${key}.json`);
      await fs.writeFile(cachePath, JSON.stringify(narrative, null, 2));
    } catch {
      // Ignore cache errors
    }
  }
}

// Export singleton
export const riskNarrator = new RiskNarrator();
