# Cyber Orchestration Agent — Project Memory

## Purpose
CLI security tool that performs static IaC analysis (Terraform, CloudFormation, CDK), live AWS environment auditing, threat log correlation, compliance mapping, and AI-driven remediation — all from a single `infra-agent` command.

## Folder Responsibility Map
```
src/
├── types/          Core TypeScript interfaces — Finding is the canonical data contract
├── parsers/        IaC parsers: TerraformParser, CloudFormationParser, CDKParser
├── auditors/       Live AWS auditors: IAM, S3, EKS, EC2, RDS, Lambda, CloudTrail
├── analyzers/      Threat intelligence: CloudTrail, VPC Flow, GuardDuty, SecurityHub
├── rules/          Security rules engine + YAML rule definitions
├── compliance/     Framework mappings (CIS, NIST, PCI-DSS) + mappings.json
├── ai/             AI remediation engine (Anthropic SDK) + risk narrator
├── remediation/    Fix generation, PR creation (stubbed)
├── reports/        Markdown, JSON, PDF report generators
├── notifications/  Slack, Jira, email integrations (stubbed)
├── database/       Findings storage (stubbed)
└── cli/            Commander.js CLI entry point
```

## Implementation Status

### Phase 0 — Foundation (IN PROGRESS)
- [x] CLAUDE.md created
- [ ] Core types updated to match spec (Finding, Severity, etc.)
- [ ] mappings.json created with rule→framework→MITRE mappings
- [ ] Dependencies installed
- [ ] Build passes with zero errors

### Phase 1 — Terraform Static Analysis
- [ ] TerraformParser rewritten with @cdktf/hcl2json
- [ ] 10 security rules implemented
- [ ] Test fixtures created
- [ ] Vitest suite passing

### Phase 2 — AI Remediation Engine
- [ ] remediation-engine.ts with Anthropic SDK
- [ ] risk-narrator.ts for executive summaries
- [ ] Response caching with SHA256 keys
- [ ] Tests with mocked SDK

### Phase 3 — Live AWS Auditors
- [ ] IAM auditor: root MFA, unused keys, inline policies
- [ ] S3 auditor: public access, encryption, versioning
- [ ] EKS auditor: public endpoint, audit logging
- [ ] CloudTrail auditor: enabled, multi-region, validation
- [ ] Auditor orchestrator

### Phase 4 — CloudFormation + CDK Parsers
- [ ] CloudFormation parser with same rule set
- [ ] CDK parser delegating to CFN parser

### Phase 5 — Report Generation
- [ ] Markdown reporter
- [ ] JSON reporter
- [ ] PDF reporter with pdfkit

### Phase 6 — CLI Polish
- [ ] Commander.js commands: scan, audit, full
- [ ] Terminal UI with chalk + ora
- [ ] --fail-on flag for CI/CD
- [ ] Config file loading

### Phase 7 — Demo Assets
- [ ] Demo fixtures with intentional vulns
- [ ] Sample reports committed
- [ ] README rewrite
- [ ] GitHub Actions CI

## CLI Commands
```bash
# Scan IaC files
infra-agent scan --iac <path> [--provider terraform|cloudformation|cdk]
                 [--output <basename>] [--format markdown,json,pdf]
                 [--severity CRITICAL|HIGH|MEDIUM|LOW]
                 [--framework CIS_AWS|NIST_800_53|PCI_DSS]
                 [--no-ai] [--fail-on <severity>]

# Audit live AWS environment
infra-agent audit --profile <name> --regions <list>
                  [--output <basename>] [--format markdown,json,pdf]
                  [--no-ai]

# Full scan + audit
infra-agent full --iac <path> --profile <name>
                 [--output <basename>] [--format markdown,json,pdf]
```

## Conventions

### Naming
- Rule IDs: `SERVICE_RULE_NAME` (e.g., `S3_PUBLIC_ACL`, `IAM_WILDCARD_ACTION`)
- Finding IDs: UUID v4
- File naming: kebab-case for files, PascalCase for classes

### Error Handling
- AWS credential errors: print actionable message with `aws configure` hint
- Missing ANTHROPIC_API_KEY: warn and continue with `--no-ai` behavior
- Unreadable IaC files: skip with warning, continue with rest
- Network timeout: retry once, then skip with warning
- All errors logged to `infra-agent.log`

### Testing
- AWS SDK calls: always mocked with `aws-sdk-client-mock`
- Anthropic SDK: always mocked in tests
- Test fixtures in `tests/fixtures/`
- Target: >80% coverage on parsers and auditors

## The Finding Interface (Canonical Data Contract)
```typescript
interface Finding {
  id: string;                        // UUID v4
  title: string;
  description: string;
  severity: Severity;                // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  resource: {
    type: string;                    // e.g. "aws_s3_bucket"
    id: string;                      // resource name or ARN
    region?: string;
    account?: string;
  };
  source: 'static' | 'live' | 'log';
  provider: IaCProvider | 'aws_live' | 'cloudtrail';
  rawBlock?: string;                 // original HCL/JSON/YAML block
  frameworks: FrameworkMapping[];
  mitre?: MitreMapping;
  remediation?: RemediationSuggestion;
  detectedAt: Date;
  falsePositiveLikelihood?: 'LOW' | 'MEDIUM' | 'HIGH';
}
```

## Environment Variables
```bash
# Required for AI remediation
ANTHROPIC_API_KEY=sk-ant-...

# AWS credentials (uses standard credential chain)
AWS_PROFILE=default
AWS_REGION=us-east-1

# Optional
LOG_LEVEL=info
CACHE_DIR=.remediation-cache
```

## Known Issues / Tech Debt
1. TerraformParser uses regex instead of @cdktf/hcl2json — needs rewrite
2. Existing Severity enum uses lowercase — needs migration to uppercase
3. Finding interface in src/types doesn't match spec — needs overhaul
4. No src/reports/ directory — needs creation
5. CLI is a console.log stub — needs Commander.js implementation
6. AI module is empty — needs Anthropic SDK integration
7. Compliance mapper is empty — only framework YAML files exist
