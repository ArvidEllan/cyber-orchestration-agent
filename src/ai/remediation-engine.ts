/**
 * AI Remediation Engine
 * Uses Anthropic Claude API to generate intelligent remediation suggestions
 */

import Anthropic from '@anthropic-ai/sdk';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Finding, RemediationSuggestion, Severity } from '../types/core';

/**
 * Cache entry for remediation responses
 */
interface CacheEntry {
  key: string;
  response: RemediationSuggestion;
  createdAt: string;
  expiresAt: string;
}

/**
 * Options for remediation generation
 */
export interface RemediationOptions {
  includeCode?: boolean;
  maxTokens?: number;
  temperature?: number;
  provider?: 'terraform' | 'cloudformation' | 'cdk';
}

/**
 * AI Remediation Engine Class
 */
export class AIRemediationEngine {
  private client: Anthropic | null = null;
  private cacheDir: string;
  private cacheTTLMs: number;
  private enabled: boolean;

  constructor(options?: { cacheDir?: string; cacheTTLHours?: number }) {
    this.cacheDir = options?.cacheDir || '.remediation-cache';
    this.cacheTTLMs = (options?.cacheTTLHours || 24) * 60 * 60 * 1000;
    this.enabled = this.initializeClient();
  }

  /**
   * Initialize the Anthropic client
   */
  private initializeClient(): boolean {
    const apiKey = process.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      console.warn('ANTHROPIC_API_KEY not set. AI remediation disabled.');
      return false;
    }

    try {
      this.client = new Anthropic({ apiKey });
      return true;
    } catch (error) {
      console.warn('Failed to initialize Anthropic client:', error);
      return false;
    }
  }

  /**
   * Check if AI remediation is available
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Generate remediation suggestion for a finding
   */
  async generateRemediation(
    finding: Finding,
    options: RemediationOptions = {}
  ): Promise<RemediationSuggestion | null> {
    if (!this.enabled || !this.client) {
      return this.getFallbackRemediation(finding);
    }

    // Check cache first
    const cacheKey = this.generateCacheKey(finding, options);
    const cached = await this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const prompt = this.buildPrompt(finding, options);

      const response = await this.client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: options.maxTokens || 1024,
        temperature: options.temperature || 0.3,
        messages: [
          {
            role: 'user',
            content: prompt,
          },
        ],
      });

      const content = response.content[0];
      if (content.type !== 'text') {
        return this.getFallbackRemediation(finding);
      }

      const remediation = this.parseRemediationResponse(content.text, finding);

      // Cache the result
      await this.saveToCache(cacheKey, remediation);

      return remediation;
    } catch (error) {
      console.error('AI remediation generation failed:', error);
      return this.getFallbackRemediation(finding);
    }
  }

  /**
   * Generate remediations for multiple findings in batch
   */
  async generateRemediationsBatch(
    findings: Finding[],
    options: RemediationOptions = {}
  ): Promise<Map<string, RemediationSuggestion>> {
    const results = new Map<string, RemediationSuggestion>();

    // Process in parallel with concurrency limit
    const concurrency = 3;
    const batches: Finding[][] = [];

    for (let i = 0; i < findings.length; i += concurrency) {
      batches.push(findings.slice(i, i + concurrency));
    }

    for (const batch of batches) {
      const promises = batch.map(async (finding) => {
        const remediation = await this.generateRemediation(finding, options);
        if (remediation) {
          results.set(finding.id, remediation);
        }
      });

      await Promise.all(promises);
    }

    return results;
  }

  /**
   * Build the prompt for remediation generation
   */
  private buildPrompt(finding: Finding, options: RemediationOptions): string {
    const provider = options.provider || 'terraform';

    return `You are a cloud security expert. Analyze this security finding and provide remediation guidance.

**Finding Details:**
- Title: ${finding.title}
- Description: ${finding.description}
- Severity: ${finding.severity}
- Resource Type: ${finding.resource.type}
- Resource ID: ${finding.resource.id}

${finding.rawBlock ? `**Current Configuration (${provider}):**
\`\`\`hcl
${finding.rawBlock}
\`\`\`` : ''}

${finding.frameworks?.length ? `**Compliance Frameworks Affected:**
${finding.frameworks.map((f) => `- ${f.framework}: ${f.controlId} - ${f.controlTitle}`).join('\n')}` : ''}

${finding.mitre ? `**MITRE ATT&CK:**
- Technique: ${finding.mitre.techniqueId} - ${finding.mitre.techniqueName}
- Tactic: ${finding.mitre.tactic}` : ''}

**Please provide:**
1. A brief explanation of why this is a security risk
2. Step-by-step remediation instructions
3. ${options.includeCode !== false ? `The corrected ${provider} configuration code` : 'Key configuration changes needed'}
4. Any additional security best practices to consider

Format your response as follows:
---RISK---
[Risk explanation]
---STEPS---
[Numbered remediation steps]
---CODE---
[Corrected code if applicable]
---BEST_PRACTICES---
[Additional recommendations]`;
  }

  /**
   * Parse the AI response into a RemediationSuggestion
   */
  private parseRemediationResponse(response: string, finding: Finding): RemediationSuggestion {
    const sections = {
      risk: '',
      steps: [] as string[],
      code: '',
      bestPractices: [] as string[],
    };

    // Parse sections
    const riskMatch = response.match(/---RISK---\s*([\s\S]*?)(?=---STEPS---|$)/);
    const stepsMatch = response.match(/---STEPS---\s*([\s\S]*?)(?=---CODE---|---BEST_PRACTICES---|$)/);
    const codeMatch = response.match(/---CODE---\s*([\s\S]*?)(?=---BEST_PRACTICES---|$)/);
    const bestPracticesMatch = response.match(/---BEST_PRACTICES---\s*([\s\S]*?)$/);

    if (riskMatch) sections.risk = riskMatch[1].trim();
    if (stepsMatch) {
      sections.steps = stepsMatch[1]
        .trim()
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => line.replace(/^\d+\.\s*/, '').trim());
    }
    if (codeMatch) sections.code = codeMatch[1].trim();
    if (bestPracticesMatch) {
      sections.bestPractices = bestPracticesMatch[1]
        .trim()
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => line.replace(/^[-*]\s*/, '').trim());
    }

    // Build summary from risk explanation and steps
    const summary = sections.risk
      ? `${sections.risk}\n\nSteps:\n${sections.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`
      : `Remediation for ${finding.title}`;

    return {
      summary,
      fixedBlock: sections.code || undefined,
      effort: this.estimateEffort(finding.severity),
      automatable: false,
      pullRequestReady: !!sections.code,
    };
  }

  /**
   * Get fallback remediation when AI is unavailable
   */
  private getFallbackRemediation(finding: Finding): RemediationSuggestion {
    const remediationMap: Record<string, { summary: string; effort: 'LOW' | 'MEDIUM' | 'HIGH' }> = {
      S3_PUBLIC_ACL: {
        summary: `Remove public ACL from S3 bucket to prevent unauthorized access.

Steps:
1. Change the bucket ACL from public to private
2. Review bucket policies for any public access grants
3. Enable S3 Block Public Access settings
4. Audit existing objects for public permissions`,
        effort: 'LOW',
      },
      S3_NO_ENCRYPTION: {
        summary: `Enable server-side encryption to protect data at rest.

Steps:
1. Add server_side_encryption_configuration block to the S3 bucket
2. Choose SSE-S3 (AES256) or SSE-KMS encryption
3. For SSE-KMS, create or specify a KMS key
4. Update bucket policy to enforce encryption`,
        effort: 'LOW',
      },
      IAM_WILDCARD_ACTION: {
        summary: `Replace wildcard actions with specific permissions following least privilege.

Steps:
1. Identify the actual permissions needed by the principal
2. Replace Action: "*" with specific service:action permissions
3. Scope Resource to specific ARNs where possible
4. Test the policy with IAM Policy Simulator`,
        effort: 'MEDIUM',
      },
      EC2_SG_OPEN_SSH: {
        summary: `Restrict SSH access to known IP ranges.

Steps:
1. Identify authorized IP ranges for SSH access
2. Replace 0.0.0.0/0 with specific CIDR blocks
3. Consider using AWS Systems Manager Session Manager instead
4. Implement VPN or bastion host for secure access`,
        effort: 'LOW',
      },
      EC2_SG_OPEN_RDP: {
        summary: `Restrict RDP access to known IP ranges.

Steps:
1. Identify authorized IP ranges for RDP access
2. Replace 0.0.0.0/0 with specific CIDR blocks
3. Consider using AWS Systems Manager Fleet Manager
4. Implement VPN or jump box for secure access`,
        effort: 'LOW',
      },
      RDS_PUBLICLY_ACCESSIBLE: {
        summary: `Move RDS instance to private subnet.

Steps:
1. Set publicly_accessible to false
2. Place the instance in a private subnet
3. Use VPC endpoints or bastion hosts for access
4. Review security group rules`,
        effort: 'MEDIUM',
      },
    };

    const defaultRemediation = {
      summary: `Review and remediate: ${finding.title}

Steps:
1. Review the security finding details
2. Consult AWS security best practices documentation
3. Update the configuration to address the vulnerability
4. Test the changes in a non-production environment
5. Deploy and monitor for any issues`,
      effort: 'MEDIUM' as const,
    };

    // Extract rule ID from title or use default
    const ruleId = Object.keys(remediationMap).find(
      (key) => finding.title.toLowerCase().includes(key.replace(/_/g, ' ').toLowerCase()) ||
               finding.description.includes(key)
    );

    const matched = ruleId ? remediationMap[ruleId] : defaultRemediation;

    return {
      summary: matched.summary,
      effort: matched.effort,
      automatable: false,
      pullRequestReady: false,
    };
  }

  /**
   * Estimate remediation effort based on severity
   */
  private estimateEffort(severity: Severity): 'LOW' | 'MEDIUM' | 'HIGH' {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'HIGH';
      case 'MEDIUM':
        return 'MEDIUM';
      default:
        return 'LOW';
    }
  }

  /**
   * Generate a cache key for a finding
   */
  private generateCacheKey(finding: Finding, options: RemediationOptions): string {
    const data = JSON.stringify({
      title: finding.title,
      resourceType: finding.resource.type,
      resourceId: finding.resource.id,
      rawBlock: finding.rawBlock,
      options,
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Get cached remediation if available and not expired
   */
  private async getFromCache(key: string): Promise<RemediationSuggestion | null> {
    try {
      const cachePath = path.join(this.cacheDir, `${key}.json`);
      const data = await fs.readFile(cachePath, 'utf-8');
      const entry: CacheEntry = JSON.parse(data);

      const now = new Date().getTime();
      const expires = new Date(entry.expiresAt).getTime();

      if (now < expires) {
        return entry.response;
      }

      // Expired, delete the file
      await fs.unlink(cachePath).catch(() => {});
    } catch {
      // Cache miss or error
    }

    return null;
  }

  /**
   * Save remediation to cache
   */
  private async saveToCache(key: string, response: RemediationSuggestion): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });

      const entry: CacheEntry = {
        key,
        response,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + this.cacheTTLMs).toISOString(),
      };

      const cachePath = path.join(this.cacheDir, `${key}.json`);
      await fs.writeFile(cachePath, JSON.stringify(entry, null, 2));
    } catch (error) {
      console.warn('Failed to save to cache:', error);
    }
  }

  /**
   * Clear the remediation cache
   */
  async clearCache(): Promise<void> {
    try {
      const files = await fs.readdir(this.cacheDir);
      await Promise.all(
        files.map((file) => fs.unlink(path.join(this.cacheDir, file)).catch(() => {}))
      );
    } catch {
      // Directory might not exist
    }
  }
}

// Export singleton instance
export const remediationEngine = new AIRemediationEngine();
