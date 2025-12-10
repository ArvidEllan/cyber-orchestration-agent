# Implementation Plan

## Overview

This implementation plan breaks down the Infrastructure Security Review Agent into discrete, manageable coding tasks. Each task builds incrementally on previous work, starting with core infrastructure and progressing through parsing, analysis, and output generation.

- [x] 1. Set up project structure and core interfaces






  - Create TypeScript project with proper configuration (tsconfig.json, package.json)
  - Set up directory structure: src/{parsers, auditors, analyzers, rules, compliance, remediation, reports, notifications, database, utils}
  - Define core TypeScript interfaces and types in src/types/index.ts
  - Configure linting (ESLint) and formatting (Prettier)
  - Set up build tooling (esbuild or tsc)
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2. Implement IaC parser module






- [x] 2.1 Create Terraform parser

  - Install HCL parsing library (e.g., @cdktf/hcl2json)
  - Implement TerraformParser class that parses .tf files
  - Extract resources, variables, and outputs from parsed HCL
  - Normalize Terraform resources to common Resource interface
  - Handle Terraform modules and variable interpolation
  - _Requirements: 1.1_

- [x] 2.2 Create CloudFormation parser


  - Implement CloudFormationParser class for JSON/YAML templates
  - Parse CloudFormation resources and parameters
  - Handle intrinsic functions (Ref, GetAtt, Sub, etc.)
  - Normalize CloudFormation resources to common Resource interface
  - _Requirements: 1.2_

- [x] 2.3 Create CDK parser


  - Implement CDKParser using TypeScript compiler API
  - Parse CDK TypeScript code and extract resource definitions
  - Handle CDK constructs and synthesized CloudFormation
  - Normalize CDK resources to common Resource interface
  - _Requirements: 1.3_

- [x] 2.4 Implement parser factory and validation


  - Create ParserFactory to select appropriate parser based on file type
  - Implement validation logic for parsed infrastructure
  - Add error handling for malformed IaC files
  - Create utility functions for resource extraction
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2.5 Write parser tests


  - Create test fixtures with sample Terraform, CloudFormation, and CDK files
  - Write unit tests for each parser implementation
  - Test error handling with malformed files
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 3. Implement AWS auditor module






- [x] 3.1 Set up AWS SDK integration

  - Install AWS SDK v3 packages (@aws-sdk/client-*)
  - Implement AWSCredentials handling with support for profiles, roles, and environment variables
  - Create AWSClient wrapper for credential management
  - Implement region enumeration and selection
  - _Requirements: 5.1_


- [x] 3.2 Implement account and organization auditing

  - Create OrganizationsAuditor to enumerate accounts via AWS Organizations API
  - Implement account listing and metadata collection
  - Add support for cross-account assume-role
  - Implement SCP (Service Control Policy) validation
  - _Requirements: 5.3, 5.4_



- [x] 3.3 Implement service-specific auditors

  - Create IAMAuditor for IAM users, roles, policies, and access keys
  - Create S3Auditor for bucket configurations and policies
  - Create EC2Auditor for instances, security groups, and network ACLs
  - Create RDSAuditor for database instances and configurations
  - Create LambdaAuditor for function configurations and permissions
  - Create EKSAuditor for cluster configurations
  - Create APIGatewayAuditor for API configurations
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 5.1_



- [x] 3.4 Implement security services auditor

  - Create SecurityServicesAuditor for CloudTrail, Config, Security Hub, GuardDuty
  - Check if services are enabled in each region
  - Validate service configurations against best practices
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 3.5 Implement drift detection


  - Create DriftDetector to compare IaC resources with live AWS resources
  - Implement resource matching algorithm (by ID, tags, properties)
  - Generate DriftReport with added, removed, and modified resources
  - _Requirements: 5.2_


- [x] 3.6 Write AWS auditor tests

  - Create mock AWS SDK clients for testing
  - Write unit tests for each auditor implementation
  - Test credential handling and error scenarios
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 4. Implement security rules engine







- [x] 4.1 Create rule definition system


  - Define SecurityRule interface and data structure
  - Implement rule loader that reads rules from YAML/JSON files
  - Create rule categories (IAM, Network, Encryption, Logging, etc.)
  - Implement rule condition evaluation engine
  - _Requirements: 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4.2 Implement IAM security rules










  - Create rules for wildcard IAM policies (Action: "*")
  - Create rules for missing MFA requirements
  - Create rules for overly permissive IAM roles
  - Create rules for access keys older than 90 days
  - Create rules for root account usage
  - _Requirements: 1.4, 2.1, 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 4.3 Implement network security rules


  - Create rules for security groups with 0.0.0.0/0 ingress
  - Create rules for unrestricted SSH/RDP access
  - Create rules for VPC flow logs disabled
  - Create rules for public subnet configurations
  - _Requirements: 2.2_

- [x] 4.4 Implement encryption and data protection rules


  - Create rules for S3 buckets without encryption
  - Create rules for RDS databases without encryption at rest
  - Create rules for missing KMS key usage
  - Create rules for missing TLS/SSL enforcement
  - Create rules for public S3 bucket access
  - _Requirements: 1.5, 2.3, 3.3, 3.4_

- [x] 4.5 Implement logging and monitoring rules


  - Create rules for CloudTrail disabled or misconfigured
  - Create rules for missing CloudWatch logs
  - Create rules for AWS Config disabled
  - _Requirements: 3.5_

- [x] 4.6 Implement compute and container security rules


  - Create rules for Lambda functions with overly permissive roles
  - Create rules for EKS clusters with public endpoints
  - Create rules for EC2 instances with public IPs in production
  - _Requirements: 2.4_

- [x] 4.7 Implement API security rules


  - Create rules for API Gateway without authentication
  - Create rules for missing API throttling
  - Create rules for missing API logging
  - _Requirements: 2.5_

- [x] 4.8 Implement rule execution engine


  - Create RulesEngine class that applies rules to resources
  - Implement parallel rule execution for performance
  - Generate Finding objects for rule violations
  - Add support for rule customization and severity overrides
  - _Requirements: 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4.9 Write rules engine tests





  - Create test resources with known violations
  - Write unit tests for each rule implementation
  - Test rule execution engine with multiple rules
  - _Requirements: 1.4, 2.1, 2.2, 2.3, 2.4, 2.5_

- [-] 5. Implement threat intelligence analyzer


- [x] 5.1 Create log analysis module


  - Implement CloudTrailAnalyzer to parse and analyze CloudTrail logs
  - Implement VPCFlowLogAnalyzer for network traffic analysis
  - Create SecurityEvent data model for normalized events
  - Implement log fetching from S3 and CloudWatch Logs
  - _Requirements: 8.1, 8.2_


- [ ] 5.2 Implement GuardDuty and Security Hub integration
  - Create GuardDutyAnalyzer to fetch and parse GuardDuty findings
  - Create SecurityHubAnalyzer to aggregate Security Hub findings
  - Normalize findings to common Finding interface
  - _Requirements: 8.3, 8.4_

- [ ] 5.3 Implement event correlation engine
  - Create EventCorrelator to identify related security events
  - Implement time-window based correlation
  - Detect privilege escalation + access key creation patterns
  - Detect suspicious IAM activity + network changes
  - Generate CorrelatedThreat objects with attack timelines
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 5.4 Implement vulnerability checking
  - Create VulnerabilityChecker to identify EOL Lambda runtimes
  - Implement CVE database integration (NVD API)
  - Check EC2 AMIs against known vulnerabilities
  - Check container images for vulnerabilities
  - Enrich findings with threat intelligence
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [ ] 5.5 Write threat analyzer tests
  - Create mock CloudTrail and VPC Flow Log data
  - Write unit tests for event correlation logic
  - Test vulnerability checking with known CVEs
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 9.1, 9.2, 9.3, 9.4, 9.5_

- [ ] 6. Implement compliance mapper
- [ ] 6.1 Create compliance framework definitions
  - Define CIS AWS Foundations Benchmark control mappings
  - Define AWS Well-Architected Security Pillar mappings
  - Define ISO 27001 control mappings
  - Define NIST 800-53 control mappings
  - Store mappings in JSON/YAML configuration files
  - _Requirements: 3.1, 3.2, 11.1, 11.2, 11.3_

- [ ] 6.2 Implement compliance mapping engine
  - Create ComplianceMapper class to map findings to controls
  - Implement framework-specific mapping logic
  - Calculate compliance status per control
  - Generate ComplianceMapping objects
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 6.3 Implement compliance scoring
  - Create compliance score calculation algorithm
  - Calculate overall compliance percentage per framework
  - Track compliant vs non-compliant controls
  - Generate ComplianceScore objects
  - _Requirements: 11.4, 11.5_

- [ ] 6.4 Implement compliance report generation
  - Create ComplianceReport generator for each framework
  - Include control assessments with evidence
  - Generate compliance summary with key metrics
  - Support multiple framework versions
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 6.5 Write compliance mapper tests
  - Create test findings with known control mappings
  - Write unit tests for compliance scoring
  - Test report generation for each framework
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 7. Implement AI reasoning engine
- [ ] 7.1 Create architecture analysis module
  - Implement resource graph builder from Resource relationships
  - Create data flow inference algorithm
  - Identify attack surfaces based on network topology
  - Detect trust boundaries and security zones
  - Generate ArchitectureInsight objects
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

- [ ] 7.2 Implement risk assessment engine
  - Create risk scoring algorithm combining likelihood and impact
  - Implement business context evaluation
  - Calculate risk scores for findings
  - Generate attack scenario descriptions
  - Create RiskAssessment objects with business impact
  - _Requirements: 15.3, 15.4_

- [ ] 7.3 Implement business impact translator
  - Create business impact explanation generator
  - Map technical findings to business risks (PII exposure, transaction integrity)
  - Generate regulatory implication descriptions
  - Create BusinessImpactExplanation objects
  - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

- [ ] 7.4 Implement learning system
  - Create feedback storage mechanism
  - Implement pattern recognition from historical findings
  - Adjust detection rules based on false positive feedback
  - Store successful remediation patterns
  - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

- [ ] 7.5 Write AI reasoning tests
  - Create test resource graphs with known patterns
  - Write unit tests for risk scoring algorithm
  - Test business impact translation
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 16.1, 16.2, 16.3_

- [ ] 8. Implement remediation engine
- [ ] 8.1 Create remediation plan generator
  - Implement RemediationPlan generator from findings
  - Create step-by-step remediation instructions
  - Estimate effort and priority for each remediation
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ] 8.2 Implement IaC fix generator
  - Create Terraform fix generator using HCL manipulation
  - Create CloudFormation fix generator using template patching
  - Create CDK fix generator using code transformation
  - Generate before/after code diffs
  - Validate generated fixes for syntax correctness
  - _Requirements: 4.2, 17.1_

- [ ] 8.3 Implement Git integration
  - Install Git client library (simple-git or isomorphic-git)
  - Implement branch creation for remediation fixes
  - Create commit messages with security rationale
  - Generate pull request descriptions with finding details
  - _Requirements: 17.2, 17.3, 17.4, 17.5_

- [ ] 8.4 Implement GitHub/GitLab PR creation
  - Integrate with GitHub API for PR creation
  - Integrate with GitLab API for merge request creation
  - Include before/after comparisons in PR description
  - Add security labels and reviewers
  - _Requirements: 17.2, 17.3, 17.4, 17.5_

- [ ] 8.5 Write remediation engine tests
  - Create test findings with known fixes
  - Write unit tests for fix generation
  - Test Git operations with mock repository
  - _Requirements: 4.1, 4.2, 17.1, 17.2, 17.3_

- [ ] 9. Implement report generator
- [ ] 9.1 Create executive summary generator
  - Calculate overall risk score from findings
  - Identify top risks by severity and impact
  - Generate compliance status summary
  - Create trend visualizations
  - Generate actionable recommendations
  - _Requirements: 4.5, 16.3, 16.4, 16.5_

- [ ] 9.2 Create detailed report generator
  - Organize findings by service and severity
  - Include compliance reports for all frameworks
  - Generate remediation plan section
  - Add appendix with methodology and glossary
  - _Requirements: 4.4, 4.5_

- [ ] 9.3 Implement report export formats
  - Implement JSON export for machine-readable reports
  - Implement CSV export for spreadsheet analysis
  - Implement Markdown export for documentation
  - Install PDF generation library (Puppeteer or PDFKit)
  - Implement PDF export with formatting and charts
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 9.4 Create dashboard generator
  - Create HTML dashboard with interactive charts
  - Implement metrics visualization (Chart.js or D3.js)
  - Add filtering and sorting capabilities
  - Generate executive and technical views
  - _Requirements: 16.5_

- [ ] 9.5 Write report generator tests
  - Create test findings for report generation
  - Write unit tests for each export format
  - Test PDF generation with sample data
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 10. Implement notification service
- [ ] 10.1 Create notification channel interfaces
  - Define NotificationChannel interface and implementations
  - Implement severity-based filtering
  - Create notification templates
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

- [ ] 10.2 Implement Slack integration
  - Install Slack SDK (@slack/webhook)
  - Create SlackNotifier with webhook support
  - Format findings as Slack messages with blocks
  - Implement rate limiting and deduplication
  - _Requirements: 13.2, 13.3, 13.4_

- [ ] 10.3 Implement Jira integration
  - Install Jira client library (jira-client)
  - Create JiraNotifier for ticket creation
  - Map findings to Jira issue format
  - Support custom field mapping
  - _Requirements: 13.2, 13.3, 13.4_

- [ ] 10.4 Implement email and webhook notifications
  - Create EmailNotifier using nodemailer
  - Create WebhookNotifier for custom integrations
  - Support notification templates
  - _Requirements: 13.2, 13.3, 13.4_

- [ ] 10.5 Write notification service tests
  - Create mock notification endpoints
  - Write unit tests for each notifier
  - Test filtering and rate limiting
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

- [ ] 11. Implement findings database
- [ ] 11.1 Set up database layer
  - Choose database (SQLite for local, PostgreSQL for production)
  - Install database client library (better-sqlite3 or pg)
  - Create database schema for findings, resources, and trends
  - Implement database migrations
  - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 18.1_

- [ ] 11.2 Implement findings storage and retrieval
  - Create FindingsDatabase class with CRUD operations
  - Implement query interface with filtering
  - Add indexing for performance (resource ID, severity, timestamp)
  - Implement pagination for large result sets
  - _Requirements: 14.1, 14.2, 14.3, 18.1_

- [ ] 11.3 Implement trend analysis
  - Create trend calculation queries
  - Track metrics over time (policy drift, encryption coverage, etc.)
  - Generate time-series data points
  - Implement trend direction detection
  - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 11.4 Implement data retention and export
  - Create data retention policy implementation
  - Implement database backup functionality
  - Add export/import capabilities for findings
  - _Requirements: 18.1_

- [ ] 11.5 Write database tests
  - Write unit tests for CRUD operations
  - Test query filtering and pagination
  - Test trend calculation accuracy
  - _Requirements: 14.1, 14.2, 14.3_

- [ ] 12. Implement CLI interface
- [ ] 12.1 Set up CLI framework
  - Install CLI framework (Commander.js or Yargs)
  - Create main CLI entry point
  - Implement command structure (scan, audit, compliance, report)
  - Add global options (--config, --verbose, --output)
  - _Requirements: All_

- [ ] 12.2 Implement scan command
  - Create 'scan' command for IaC analysis
  - Add options for IaC path, format, and output
  - Integrate with IaC parser and rules engine
  - Display progress and results
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 12.3 Implement audit command
  - Create 'audit' command for live AWS environment scanning
  - Add options for AWS profile, regions, and accounts
  - Integrate with AWS auditor and rules engine
  - Display progress and results
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.2, 7.3, 7.4, 7.5_

- [ ] 12.4 Implement compliance command
  - Create 'compliance' command for compliance reporting
  - Add options for framework selection and output format
  - Integrate with compliance mapper
  - Generate and export compliance reports
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 12.5 Implement report command
  - Create 'report' command for generating reports from stored findings
  - Add options for report format and time range
  - Integrate with report generator
  - Support trend analysis
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 12.6 Implement remediate command
  - Create 'remediate' command for generating fixes
  - Add options for auto-PR creation
  - Integrate with remediation engine
  - Display remediation plan and apply fixes
  - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

- [ ] 12.7 Write CLI tests
  - Write integration tests for each CLI command
  - Test command options and error handling
  - Test end-to-end workflows
  - _Requirements: All_

- [ ] 13. Implement configuration management
- [ ] 13.1 Create configuration loader
  - Implement YAML configuration file parser
  - Support .infra-agent.yml in project root and home directory
  - Implement configuration merging (defaults → user → project)
  - Add environment variable substitution
  - _Requirements: All_

- [ ] 13.2 Implement configuration validation
  - Validate configuration schema
  - Check required fields and valid values
  - Provide helpful error messages for invalid config
  - _Requirements: All_

- [ ] 13.3 Create default configuration
  - Define default rule sets and severity levels
  - Set default output formats and destinations
  - Configure default notification thresholds
  - _Requirements: All_

- [ ] 13.4 Write configuration tests
  - Write unit tests for config loading and merging
  - Test environment variable substitution
  - Test validation with invalid configs
  - _Requirements: All_

- [ ] 14. Implement error handling and logging
- [ ] 14.1 Create error handling framework
  - Define SecurityAgentError class hierarchy
  - Implement error codes and categories
  - Create error handler with retry logic
  - Add exponential backoff for API rate limiting
  - _Requirements: All_

- [ ] 14.2 Implement logging system
  - Install logging library (Winston or Pino)
  - Configure log levels (debug, info, warn, error)
  - Implement structured logging with context
  - Add log file rotation
  - _Requirements: All_

- [ ] 14.3 Add graceful error recovery
  - Implement partial result handling
  - Continue analysis when individual resources fail
  - Aggregate errors in final report
  - _Requirements: All_

- [ ] 14.4 Write error handling tests
  - Write unit tests for error handling
  - Test retry logic with mock failures
  - Test graceful degradation
  - _Requirements: All_

- [ ] 15. Create documentation and examples
- [ ] 15.1 Write README with getting started guide
  - Document installation instructions
  - Provide quick start examples
  - List all CLI commands and options
  - Include configuration examples
  - _Requirements: All_

- [ ] 15.2 Create example configurations
  - Provide sample .infra-agent.yml files
  - Create example custom rules
  - Include integration examples (GitHub Actions, GitLab CI)
  - _Requirements: All_

- [ ] 15.3 Write API documentation
  - Document all public interfaces and classes
  - Generate API docs using TypeDoc
  - Include usage examples for each module
  - _Requirements: All_

- [ ] 15.4 Create tutorial and guides
  - Write tutorial for IaC scanning
  - Write tutorial for AWS environment auditing
  - Write guide for custom rule development
  - Write guide for CI/CD integration
  - _Requirements: All_

- [ ] 16. Package and publish
- [ ] 16.1 Configure package for npm
  - Set up package.json with proper metadata
  - Configure build scripts and entry points
  - Add npm ignore file
  - Test local installation
  - _Requirements: All_

- [ ] 16.2 Create Docker image
  - Write Dockerfile for containerized deployment
  - Optimize image size with multi-stage build
  - Test Docker image locally
  - Document Docker usage
  - _Requirements: All_

- [ ] 16.3 Set up CI/CD pipeline
  - Create GitHub Actions workflow for testing
  - Add automated linting and type checking
  - Configure automated npm publishing
  - Add Docker image publishing
  - _Requirements: All_

- [ ] 16.4 Publish initial release
  - Tag version 1.0.0
  - Publish to npm registry
  - Publish Docker image to registry
  - Create GitHub release with changelog
  - _Requirements: All_
