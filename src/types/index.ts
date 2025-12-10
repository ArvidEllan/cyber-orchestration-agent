/**
 * Core type definitions for Infrastructure Security Review Agent
 */

// ============================================================================
// Enums
// ============================================================================

export enum IaCFormat {
  TERRAFORM = 'terraform',
  CLOUDFORMATION = 'cloudformation',
  CDK = 'cdk',
}

export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum Category {
  IAM = 'iam',
  NETWORK = 'network',
  ENCRYPTION = 'encryption',
  LOGGING = 'logging',
  COMPUTE = 'compute',
  STORAGE = 'storage',
  DATABASE = 'database',
  CONTAINER = 'container',
  API = 'api',
}

export enum ResourceSource {
  IAC = 'iac',
  LIVE = 'live',
  BOTH = 'both',
}

export enum FindingStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  ACCEPTED_RISK = 'accepted_risk',
  FALSE_POSITIVE = 'false_positive',
}

export enum Environment {
  PRODUCTION = 'production',
  STAGING = 'staging',
  DEVELOPMENT = 'development',
  TEST = 'test',
}

export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
}

export enum ComplianceFramework {
  CIS_AWS = 'cis_aws_foundations',
  AWS_WELL_ARCHITECTED = 'aws_well_architected',
  ISO_27001 = 'iso_27001',
  NIST_800_53 = 'nist_800_53',
  PCI_DSS = 'pci_dss',
  HIPAA = 'hipaa',
  SOC2 = 'soc2',
}

export enum ComplianceStatus {
  COMPLIANT = 'compliant',
  NON_COMPLIANT = 'non_compliant',
  PARTIAL = 'partial',
  NOT_APPLICABLE = 'not_applicable',
}

export enum LogType {
  CLOUDTRAIL = 'cloudtrail',
  VPC_FLOW = 'vpc_flow',
  GUARDDUTY = 'guardduty',
  SECURITY_HUB = 'security_hub',
  CONFIG = 'config',
}

export enum ChannelType {
  SLACK = 'slack',
  EMAIL = 'email',
  JIRA = 'jira',
  PAGERDUTY = 'pagerduty',
  WEBHOOK = 'webhook',
}

export enum ReportFormat {
  PDF = 'pdf',
  HTML = 'html',
  JSON = 'json',
  CSV = 'csv',
  MARKDOWN = 'markdown',
}

export enum ErrorCode {
  IAC_PARSE_ERROR = 'IAC_PARSE_ERROR',
  AWS_AUTH_ERROR = 'AWS_AUTH_ERROR',
  AWS_API_ERROR = 'AWS_API_ERROR',
  RULE_EXECUTION_ERROR = 'RULE_EXECUTION_ERROR',
  REPORT_GENERATION_ERROR = 'REPORT_GENERATION_ERROR',
  NOTIFICATION_ERROR = 'NOTIFICATION_ERROR',
}

export enum TrendDirection {
  IMPROVING = 'improving',
  DEGRADING = 'degrading',
  STABLE = 'stable',
}

// ============================================================================
// Core Data Models
// ============================================================================

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
}

export interface Metadata {
  version?: string;
  author?: string;
  createdAt?: Date;
  [key: string]: any;
}

export interface Variable {
  name: string;
  type: string;
  defaultValue?: any;
  description?: string;
}

export interface Output {
  name: string;
  value: any;
  description?: string;
}

export interface Relationship {
  type: string;
  targetId: string;
  properties?: Record<string, any>;
}

export interface Resource {
  id: string;
  type: string;
  service: string;
  region: string;
  account: string;
  properties: Record<string, any>;
  tags: Record<string, string>;
  relationships: Relationship[];
  source: ResourceSource;
  timestamp: Date;
}

export interface Evidence {
  description: string;
  details: Record<string, any>;
  references?: string[];
}

export interface RemediationGuidance {
  description: string;
  steps: string[];
  code?: string;
  references?: string[];
}

export interface ComplianceMapping {
  framework: ComplianceFramework;
  controlId: string;
  controlName: string;
  requirement: string;
  status: ComplianceStatus;
}

export interface Finding {
  id: string;
  ruleId: string;
  resource: Resource;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  evidence: Evidence;
  remediation: RemediationGuidance;
  complianceMapping: ComplianceMapping[];
  riskScore: number;
  status: FindingStatus;
  createdAt: Date;
  updatedAt: Date;
}

// ============================================================================
// IaC Parser Interfaces
// ============================================================================

export interface ParsedInfrastructure {
  format: IaCFormat;
  resources: Resource[];
  variables: Variable[];
  outputs: Output[];
  metadata: Metadata;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  message: string;
  location?: SourceLocation;
  code?: string;
}

export interface ValidationWarning {
  message: string;
  location?: SourceLocation;
  code?: string;
}

export interface IaCParser {
  parse(filePath: string, format: IaCFormat): Promise<ParsedInfrastructure>;
  validate(parsed: ParsedInfrastructure): ValidationResult;
  extractResources(parsed: ParsedInfrastructure): Resource[];
}

// ============================================================================
// AWS Auditor Interfaces
// ============================================================================

export interface AWSCredentials {
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  profile?: string;
  roleArn?: string;
}

export interface AWSAccount {
  id: string;
  name: string;
  email: string;
  status: string;
}

export interface RegionAudit {
  region: string;
  services: ServiceAudit[];
  securityServices: SecurityServicesAudit;
}

export interface OrganizationAudit {
  organizationId: string;
  accounts: AWSAccount[];
  scps: ServiceControlPolicy[];
}

export interface ServiceControlPolicy {
  id: string;
  name: string;
  content: Record<string, any>;
  targets: string[];
}

export interface IdentityAudit {
  users: IAMUser[];
  roles: IAMRole[];
  policies: IAMPolicy[];
}

export interface IAMUser {
  userName: string;
  userId: string;
  arn: string;
  createDate: Date;
  passwordLastUsed?: Date;
  accessKeys: AccessKey[];
}

export interface AccessKey {
  accessKeyId: string;
  status: string;
  createDate: Date;
  lastUsedDate?: Date;
}

export interface IAMRole {
  roleName: string;
  roleId: string;
  arn: string;
  assumeRolePolicyDocument: Record<string, any>;
  attachedPolicies: string[];
}

export interface IAMPolicy {
  policyName: string;
  policyId: string;
  arn: string;
  document: Record<string, any>;
}

export interface SecurityServicesAudit {
  cloudTrail: CloudTrailStatus;
  config: ConfigStatus;
  securityHub: SecurityHubStatus;
  guardDuty: GuardDutyStatus;
}

export interface CloudTrailStatus {
  enabled: boolean;
  trails: Trail[];
}

export interface Trail {
  name: string;
  s3BucketName: string;
  isMultiRegionTrail: boolean;
  logFileValidationEnabled: boolean;
}

export interface ConfigStatus {
  enabled: boolean;
  recorders: ConfigRecorder[];
}

export interface ConfigRecorder {
  name: string;
  roleArn: string;
  recordingGroup: Record<string, any>;
}

export interface SecurityHubStatus {
  enabled: boolean;
  standards: Standard[];
}

export interface Standard {
  standardsArn: string;
  enabled: boolean;
}

export interface GuardDutyStatus {
  enabled: boolean;
  detectorId?: string;
}

export interface ServiceAudit {
  service: string;
  resources: Resource[];
  findings: Finding[];
}

export interface AccountAudit {
  accountId: string;
  regions: RegionAudit[];
  organizations: OrganizationAudit;
  identity: IdentityAudit;
  securityServices: SecurityServicesAudit;
}

export interface DriftReport {
  added: Resource[];
  removed: Resource[];
  modified: ResourceDiff[];
  unchanged: Resource[];
}

export interface ResourceDiff {
  resource: Resource;
  changes: PropertyChange[];
}

export interface PropertyChange {
  property: string;
  oldValue: any;
  newValue: any;
}

export interface AWSAuditor {
  connect(credentials: AWSCredentials): Promise<void>;
  listAccounts(): Promise<AWSAccount[]>;
  auditAccount(accountId: string): Promise<AccountAudit>;
  auditService(accountId: string, service: string): Promise<ServiceAudit>;
  detectDrift(iacResources: Resource[], liveResources: Resource[]): DriftReport;
}

// ============================================================================
// Security Rules Engine Interfaces
// ============================================================================

export interface RuleCondition {
  resourceType?: string;
  property?: string;
  operator?: string;
  value?: any;
  any?: RuleCondition[];
  all?: RuleCondition[];
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: Category;
  frameworks: ComplianceFramework[];
  condition: RuleCondition;
  remediation: RemediationGuidance;
}

export interface RuleResult {
  rule: SecurityRule;
  passed: boolean;
  finding?: Finding;
}

export interface RuleCustomization {
  severity?: Severity;
  enabled?: boolean;
  condition?: RuleCondition;
}

export interface RuleSet {
  name: string;
  version: string;
  rules: SecurityRule[];
}

export interface SecurityRulesEngine {
  loadRules(ruleSet: RuleSet): void;
  analyze(resources: Resource[]): Finding[];
  evaluateRule(rule: SecurityRule, resource: Resource): RuleResult;
  customizeRule(ruleId: string, customization: RuleCustomization): void;
}

// ============================================================================
// Threat Intelligence Interfaces
// ============================================================================

export interface TimeRange {
  start: Date;
  end: Date;
}

export interface LogSource {
  type: LogType;
  location: string;
  timeRange: TimeRange;
}

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  eventType: string;
  source: string;
  principal: string;
  resource: string;
  action: string;
  result: string;
  details: Record<string, any>;
}

export interface AttackPattern {
  name: string;
  description: string;
  mitreId?: string;
  tactics: string[];
  techniques: string[];
}

export interface Timeline {
  events: TimelineEvent[];
  startTime: Date;
  endTime: Date;
}

export interface TimelineEvent {
  timestamp: Date;
  description: string;
  severity: Severity;
}

export interface CorrelatedThreat {
  id: string;
  events: SecurityEvent[];
  attackPattern: AttackPattern;
  severity: Severity;
  timeline: Timeline;
  affectedResources: Resource[];
}

export interface ThreatIntelligence {
  source: string;
  description: string;
  indicators: string[];
  references: string[];
  lastUpdated: Date;
}

export interface Vulnerability {
  cve: string;
  component: string;
  version: string;
  severity: Severity;
  exploitability: number;
  threatIntel: ThreatIntelligence;
}

export interface Component {
  type: string;
  name: string;
  version: string;
  resource: Resource;
}

export interface ThreatFinding extends Finding {
  threatIntel?: ThreatIntelligence;
  correlatedEvents?: SecurityEvent[];
}

export interface EnrichedFinding extends Finding {
  threatIntel: ThreatIntelligence;
  vulnerabilities: Vulnerability[];
}

export interface ThreatAnalyzer {
  analyzeLogs(logSource: LogSource): Promise<ThreatFinding[]>;
  correlateEvents(events: SecurityEvent[]): CorrelatedThreat[];
  checkVulnerabilities(component: Component): Promise<Vulnerability[]>;
  enrichWithThreatIntel(finding: Finding): Promise<EnrichedFinding>;
}

// ============================================================================
// Compliance Mapper Interfaces
// ============================================================================

export interface ControlAssessment {
  controlId: string;
  controlName: string;
  requirement: string;
  status: ComplianceStatus;
  findings: Finding[];
  evidence: string[];
}

export interface ComplianceSummary {
  totalControls: number;
  compliantControls: number;
  nonCompliantControls: number;
  partialControls: number;
  notApplicableControls: number;
  compliancePercentage: number;
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  overallScore: number;
  controls: ControlAssessment[];
  summary: ComplianceSummary;
  timestamp: Date;
}

export interface ComplianceScore {
  framework: ComplianceFramework;
  score: number;
  compliantControls: number;
  totalControls: number;
}

export interface ComplianceMapper {
  mapFinding(finding: Finding): ComplianceMapping[];
  generateReport(findings: Finding[], framework: ComplianceFramework): ComplianceReport;
  assessCompliance(findings: Finding[]): ComplianceScore;
}

// ============================================================================
// AI Reasoning Engine Interfaces
// ============================================================================

export interface DataFlow {
  source: Resource;
  destination: Resource;
  dataType: string;
  encrypted: boolean;
}

export interface AttackSurface {
  resource: Resource;
  exposureLevel: string;
  vulnerabilities: Finding[];
}

export interface TrustBoundary {
  name: string;
  resources: Resource[];
  crossings: DataFlow[];
}

export interface CriticalPath {
  resources: Resource[];
  riskScore: number;
  description: string;
}

export interface ArchitectureInsight {
  dataFlows: DataFlow[];
  attackSurfaces: AttackSurface[];
  trustBoundaries: TrustBoundary[];
  criticalPaths: CriticalPath[];
}

export interface BusinessImpact {
  description: string;
  affectedAssets: string[];
  potentialLoss: string;
  regulatoryRisk: string;
}

export interface AttackScenario {
  description: string;
  steps: string[];
  likelihood: number;
  impact: number;
}

export interface RiskAssessment {
  finding: Finding;
  likelihood: number;
  impact: number;
  riskScore: number;
  businessImpact: BusinessImpact;
  attackScenarios: AttackScenario[];
}

export interface RemediationStep {
  order: number;
  description: string;
  code?: string;
  validation?: string;
}

export interface AutomatedFix {
  applicable: boolean;
  code: string;
  testable: boolean;
  reversible: boolean;
}

export interface RemediationPlan {
  finding: Finding;
  steps: RemediationStep[];
  automatedFix: AutomatedFix;
  estimatedEffort: string;
  priority: number;
}

export interface BusinessImpactExplanation {
  finding: Finding;
  businessRisk: string;
  affectedAssets: string[];
  potentialConsequences: string[];
  regulatoryImplications: string[];
}

export interface Feedback {
  findingId: string;
  type: string;
  comment: string;
  timestamp: Date;
}

export interface SecurityContext {
  environment: Environment;
  dataClassification: DataClassification;
  businessCriticality: string;
  complianceRequirements: ComplianceFramework[];
  threatModel?: Record<string, any>;
}

export interface AIReasoningEngine {
  analyzeArchitecture(resources: Resource[]): ArchitectureInsight;
  assessRisk(finding: Finding, context: SecurityContext): RiskAssessment;
  generateRemediation(finding: Finding): RemediationPlan;
  explainInBusinessTerms(finding: Finding): BusinessImpactExplanation;
  learnFromFeedback(feedback: Feedback): void;
}

// ============================================================================
// Remediation Engine Interfaces
// ============================================================================

export interface FixedCode {
  finding: Finding;
  original: string;
  fixed: string;
  diff: string;
  explanation: string;
}

export interface Repository {
  provider: string;
  owner: string;
  name: string;
  branch: string;
  token: string;
}

export interface FileChange {
  path: string;
  content: string;
  action: string;
}

export interface PullRequest {
  id: string;
  title: string;
  description: string;
  branch: string;
  files: FileChange[];
  url: string;
}

export interface Target {
  type: string;
  location: string;
}

export interface ApplyResult {
  success: boolean;
  message: string;
  changes: FileChange[];
}

export interface RemediationEngine {
  generateFix(finding: Finding, format: IaCFormat): FixedCode;
  createPullRequest(fixes: FixedCode[], repo: Repository): Promise<PullRequest>;
  applyFix(fix: FixedCode, target: Target): Promise<ApplyResult>;
  validateFix(fix: FixedCode): ValidationResult;
}

// ============================================================================
// Report Generator Interfaces
// ============================================================================

export interface DataPoint {
  timestamp: Date;
  value: number;
  label?: string;
}

export interface Trend {
  metric: string;
  dataPoints: DataPoint[];
  direction: TrendDirection;
}

export interface ExecutiveSummary {
  overallRiskScore: number;
  criticalFindings: number;
  topRisks: Finding[];
  complianceStatus: ComplianceScore;
  trends: Trend[];
  recommendations: string[];
}

export interface Appendix {
  methodology: string;
  glossary: Record<string, string>;
  references: string[];
}

export interface DetailedReport {
  summary: ExecutiveSummary;
  findingsByService: Map<string, Finding[]>;
  findingsBySeverity: Map<Severity, Finding[]>;
  complianceReports: ComplianceReport[];
  remediationPlan: RemediationPlan[];
  appendix: Appendix;
}

export interface Dashboard {
  metrics: Metric[];
  charts: Chart[];
  filters: Filter[];
}

export interface Metric {
  name: string;
  value: number;
  unit: string;
  trend?: TrendDirection;
}

export interface Chart {
  type: string;
  title: string;
  data: DataPoint[];
}

export interface Filter {
  name: string;
  options: string[];
  selected: string[];
}

export interface Report {
  id: string;
  type: string;
  timestamp: Date;
  content: ExecutiveSummary | DetailedReport | Dashboard;
}

export interface ReportGenerator {
  generateExecutiveSummary(findings: Finding[]): ExecutiveSummary;
  generateDetailedReport(findings: Finding[]): DetailedReport;
  exportReport(report: Report, format: ReportFormat): Promise<string>;
  generateDashboard(findings: Finding[]): Dashboard;
}

// ============================================================================
// Notification Service Interfaces
// ============================================================================

export interface NotificationFilter {
  minSeverity: Severity;
  services: string[];
  environments: string[];
}

export interface ChannelConfig {
  [key: string]: any;
}

export interface NotificationChannel {
  type: ChannelType;
  config: ChannelConfig;
  filter: NotificationFilter;
}

export interface TicketSystem {
  type: string;
  url: string;
  project: string;
  credentials: Record<string, string>;
}

export interface Ticket {
  id: string;
  key: string;
  url: string;
  status: string;
}

export interface Integration {
  name: string;
  type: string;
  config: Record<string, any>;
}

export interface NotificationService {
  sendNotification(finding: Finding, channels: NotificationChannel[]): Promise<void>;
  createTicket(finding: Finding, ticketSystem: TicketSystem): Promise<Ticket>;
  configureIntegration(integration: Integration): void;
}

// ============================================================================
// Findings Database Interfaces
// ============================================================================

export interface QueryCriteria {
  severity?: Severity[];
  services?: string[];
  timeRange?: TimeRange;
  status?: FindingStatus[];
  frameworks?: ComplianceFramework[];
}

export interface FindingsDatabase {
  store(findings: Finding[]): Promise<void>;
  query(criteria: QueryCriteria): Promise<Finding[]>;
  getTrends(timeRange: TimeRange): Promise<Trend[]>;
  getHistory(resourceId: string): Promise<Finding[]>;
}

// ============================================================================
// Configuration Interfaces
// ============================================================================

export interface AWSConfig {
  profiles: AWSProfile[];
  defaultRegion?: string;
}

export interface AWSProfile {
  name: string;
  roleArn?: string;
  regions: string[];
}

export interface RulesConfig {
  enabledRulesets: string[];
  severityOverrides: SeverityOverride[];
  customRules?: string[];
}

export interface SeverityOverride {
  ruleId: string;
  severity: Severity;
}

export interface ComplianceConfig {
  frameworks: ComplianceFramework[];
}

export interface NotificationConfig {
  slack?: SlackConfig;
  jira?: JiraConfig;
  email?: EmailConfig;
  webhook?: WebhookConfig;
}

export interface SlackConfig {
  webhookUrl: string;
  minSeverity: Severity;
  channel?: string;
}

export interface JiraConfig {
  url: string;
  project: string;
  token: string;
  minSeverity: Severity;
}

export interface EmailConfig {
  smtp: string;
  from: string;
  to: string[];
  minSeverity: Severity;
}

export interface WebhookConfig {
  url: string;
  headers?: Record<string, string>;
  minSeverity: Severity;
}

export interface IntegrationConfig {
  git?: GitConfig;
}

export interface GitConfig {
  provider: string;
  token: string;
  autoPr: boolean;
}

export interface OutputConfig {
  formats: ReportFormat[];
  destination: string;
  includeRemediation: boolean;
}

export interface AgentConfig {
  aws: AWSConfig;
  rules: RulesConfig;
  compliance: ComplianceConfig;
  notifications: NotificationConfig;
  integrations: IntegrationConfig;
  output: OutputConfig;
}

// ============================================================================
// Error Handling Interfaces
// ============================================================================

export enum ErrorCategory {
  INPUT = 'input',
  API = 'api',
  ANALYSIS = 'analysis',
  OUTPUT = 'output',
}

export class SecurityAgentError extends Error {
  constructor(
    message: string,
    public code: ErrorCode,
    public category: ErrorCategory,
    public recoverable: boolean,
    public context?: any
  ) {
    super(message);
    this.name = 'SecurityAgentError';
  }
}

export interface ErrorHandlingResult {
  success: boolean;
  error?: SecurityAgentError;
  partialResults?: any;
}

export interface ErrorHandler {
  handle(error: SecurityAgentError): ErrorHandlingResult;
  retry<T>(operation: () => Promise<T>, maxRetries: number): Promise<T>;
  logError(error: SecurityAgentError): void;
}
