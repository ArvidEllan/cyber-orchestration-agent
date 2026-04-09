/**
 * Core type definitions for Infrastructure Security Review Agent
 * These are the canonical data contracts — all modules must use these.
 */

// ============================================================================
// Enums and Literal Types
// ============================================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IaCProvider = 'terraform' | 'cloudformation' | 'cdk';

export type ComplianceFramework = 'CIS_AWS' | 'NIST_800_53' | 'ISO_27001' | 'PCI_DSS' | 'SOC2';

export type FindingSource = 'static' | 'live' | 'log';

export type FindingProvider = IaCProvider | 'aws_live' | 'cloudtrail';

export type RemediationEffort = 'LOW' | 'MEDIUM' | 'HIGH';

export type FalsePositiveLikelihood = 'LOW' | 'MEDIUM' | 'HIGH';

// ============================================================================
// Core Data Models
// ============================================================================

/**
 * Resource location within an IaC file
 */
export interface ResourceLocation {
  file: string;
  startLine: number;
  endLine: number;
}

/**
 * Resource reference within a Finding
 */
export interface FindingResource {
  type: string;                    // e.g. "aws_s3_bucket", "AWS::S3::Bucket"
  id: string;                      // resource name or ARN
  region?: string;
  account?: string;
  location?: ResourceLocation;
}

/**
 * Mapping to a compliance framework control
 */
export interface FrameworkMapping {
  framework: ComplianceFramework;
  controlId: string;               // e.g. "CIS 2.1.5", "AC-3"
  controlTitle: string;
  required: boolean;
}

/**
 * Mapping to MITRE ATT&CK technique
 */
export interface MitreMapping {
  techniqueId: string;             // e.g. "T1530"
  techniqueName: string;
  tactic: string;                  // e.g. "Collection"
  url: string;
}

/**
 * AI-generated remediation suggestion
 */
export interface RemediationSuggestion {
  summary: string;
  fixedBlock?: string;             // corrected IaC block
  effort: RemediationEffort;
  automatable: boolean;
  pullRequestReady: boolean;
}

/**
 * The canonical Finding interface — all modules emit this
 */
export interface Finding {
  id: string;                        // UUID v4
  title: string;
  description: string;
  severity: Severity;
  resource: FindingResource;
  source: FindingSource;
  provider: FindingProvider;
  rawBlock?: string;                 // original HCL/JSON/YAML block
  frameworks: FrameworkMapping[];
  mitre?: MitreMapping;
  remediation?: RemediationSuggestion;
  detectedAt: Date;
  falsePositiveLikelihood?: FalsePositiveLikelihood;
}

/**
 * Summary statistics for a scan
 */
export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  byFramework: Record<string, number>;
  passRate: number;
}

/**
 * Complete result of a scan operation
 */
export interface ScanResult {
  scanId: string;
  startedAt: Date;
  completedAt: Date;
  target: string;
  findings: Finding[];
  summary: ScanSummary;
}

// ============================================================================
// AI Engine Types
// ============================================================================

/**
 * Response from AI risk narrator
 */
export interface RiskNarratorResponse {
  headline: string;
  paragraphs: string[];
  riskScore: number;               // 0-100
}

/**
 * Full AI remediation response (parsed from Claude)
 */
export interface AIRemediationResponse {
  summary: string;
  rootCause: string;
  fixedBlock: string;
  changeExplanation: string;
  effort: RemediationEffort;
  automatable: boolean;
  pullRequestReady: boolean;
  additionalContext?: string;
}

// ============================================================================
// Compliance Mapping Data Types
// ============================================================================

/**
 * Static mapping entry in mappings.json
 */
export interface RuleMappingEntry {
  title: string;
  frameworks: Array<{
    framework: ComplianceFramework;
    controlId: string;
    controlTitle: string;
  }>;
  mitre?: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    url: string;
  };
}

/**
 * The entire mappings.json structure
 */
export interface ComplianceMappings {
  [ruleId: string]: RuleMappingEntry;
}

// ============================================================================
// Report Types
// ============================================================================

export type ReportFormat = 'markdown' | 'json' | 'pdf';

export interface ReportOptions {
  formats: ReportFormat[];
  outputBasename: string;
  includeAiRemediation: boolean;
  minSeverity?: Severity;
  frameworkFilter?: ComplianceFramework;
}

// ============================================================================
// CLI Configuration Types
// ============================================================================

export interface ScanOptions {
  iacPath: string;
  provider?: IaCProvider;
  output: string;
  formats: ReportFormat[];
  minSeverity?: Severity;
  framework?: ComplianceFramework;
  noAi: boolean;
  failOn?: Severity;
}

export interface AuditOptions {
  profile: string;
  regions: string[];
  output: string;
  formats: ReportFormat[];
  noAi: boolean;
}

export interface FullOptions extends ScanOptions, AuditOptions {}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert severity string to numeric value for comparison
 */
export function severityToNumber(severity: Severity): number {
  const map: Record<Severity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };
  return map[severity];
}

/**
 * Check if severity meets threshold
 */
export function severityMeetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityToNumber(severity) >= severityToNumber(threshold);
}

/**
 * Create a ScanSummary from findings
 */
export function summarizeFindings(findings: Finding[]): ScanSummary {
  const summary: ScanSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    byFramework: {},
    passRate: 0,
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH': summary.high++; break;
      case 'MEDIUM': summary.medium++; break;
      case 'LOW': summary.low++; break;
      case 'INFO': summary.info++; break;
    }

    for (const fm of finding.frameworks) {
      summary.byFramework[fm.framework] = (summary.byFramework[fm.framework] || 0) + 1;
    }
  }

  return summary;
}
