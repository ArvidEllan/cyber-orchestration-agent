# infra-agent

A CLI security tool for Infrastructure-as-Code (IaC) analysis, AWS environment auditing, and AI-driven remediation recommendations.

## Features

- **Static IaC Analysis**: Parse and analyze Terraform, CloudFormation, and AWS CDK files for security misconfigurations
- **11 Security Rules**: Detects S3 public access, IAM wildcard policies, open security groups, unencrypted RDS/EBS, EKS public endpoints, CloudTrail issues
- **Compliance Mapping**: Maps findings to CIS AWS, NIST 800-53, PCI-DSS, ISO 27001, and SOC2 frameworks
- **MITRE ATT&CK Integration**: Links findings to MITRE ATT&CK techniques
- **AI Remediation**: AI-powered fix suggestions via Claude API
- **Multi-Format Reports**: Export reports in text, JSON, Markdown, and PDF
- **CI/CD Integration**: `--fail-on` flag for security gates in pipelines

## Installation

```bash
# Clone and build
git clone https://github.com/your-org/cyber-orchestration-agent.git
cd cyber-orchestration-agent
npm install
npm run build

# Link globally (optional)
npm link
```

## Quick Start

```bash
# Scan Terraform files
infra-agent scan --iac ./terraform

# Scan CloudFormation templates
infra-agent scan --iac ./cloudformation --provider cloudformation

# Scan with severity filter
infra-agent scan --iac ./terraform --severity HIGH

# Generate reports in multiple formats
infra-agent scan --iac ./terraform --format json,markdown,pdf --output security-report

# CI/CD security gate (fails if CRITICAL findings exist)
infra-agent scan --iac ./terraform --fail-on CRITICAL
```

## CLI Commands

### scan

Scan IaC files for security misconfigurations.

```bash
infra-agent scan --iac <path> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--iac <path>` | Path to IaC files or directory (required) | - |
| `--provider <type>` | IaC provider: terraform, cloudformation, cdk | terraform |
| `--severity <level>` | Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO | LOW |
| `--format <types>` | Output formats (comma-separated): text, json, markdown, pdf | text |
| `--output <basename>` | Output file basename (for non-text formats) | - |
| `--fail-on <level>` | Exit with code 1 if findings at or above this severity | - |
| `--no-ai` | Disable AI-powered remediation suggestions | - |

### audit (Phase 3)

Audit live AWS environment.

```bash
infra-agent audit --profile <name> --regions <list>
```

### full (Phase 6)

Run both IaC scan and AWS audit.

```bash
infra-agent full --iac <path> --profile <name>
```

## Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| S3_PUBLIC_ACL | CRITICAL | S3 bucket allows public access via ACL |
| S3_NO_ENCRYPTION | HIGH | S3 bucket missing server-side encryption |
| S3_NO_VERSIONING | MEDIUM | S3 bucket versioning not enabled |
| IAM_WILDCARD_ACTION | CRITICAL | IAM policy contains wildcard actions |
| EC2_SG_OPEN_SSH | CRITICAL | Security group allows SSH from 0.0.0.0/0 |
| EC2_SG_OPEN_RDP | CRITICAL | Security group allows RDP from 0.0.0.0/0 |
| EC2_UNENCRYPTED_EBS | HIGH | EBS volume not encrypted |
| RDS_PUBLICLY_ACCESSIBLE | CRITICAL | RDS instance is publicly accessible |
| RDS_NO_ENCRYPTION | HIGH | RDS instance storage not encrypted |
| EKS_PUBLIC_ENDPOINT | HIGH | EKS cluster API endpoint publicly accessible |
| CLOUDTRAIL_NOT_ENABLED | CRITICAL | CloudTrail logging is disabled |

## Compliance Frameworks

Findings are automatically mapped to:
- **CIS AWS Foundations Benchmark**
- **NIST 800-53**
- **PCI-DSS**
- **ISO 27001**
- **SOC 2**

## Sample Output

```
$ infra-agent scan --iac ./demo/terraform

✔ Scanned 1 files, 10 resources

Found 13 security issue(s):

 CRITICAL  (5)

  aws_s3_bucket.public_data
    S3 bucket allows public ACL
    Frameworks: CIS_AWS, NIST_800_53, PCI_DSS, SOC2
    MITRE: T1530 - Data from Cloud Storage

  aws_security_group.web_server
    Security group allows SSH from 0.0.0.0/0
    Frameworks: CIS_AWS, NIST_800_53, PCI_DSS, SOC2
    MITRE: T1021.004 - Remote Services: SSH

Summary:
  CRITICAL: 5
  HIGH: 6
  MEDIUM: 2
  LOW: 0
  INFO: 0
```

## Project Structure

```
src/
├── cli/            Commander.js CLI entry point
├── parsers/        IaC parsers (Terraform, CloudFormation, CDK)
├── auditors/       Live AWS auditors (IAM, S3, EKS, CloudTrail)
├── rules/          Security rules engine + YAML definitions
├── compliance/     Framework mappings (mappings.json)
├── ai/             AI remediation engine (Anthropic SDK)
├── reports/        Markdown, JSON, PDF report generators
├── types/          Core TypeScript interfaces
└── analyzers/      Threat intelligence modules

demo/
├── terraform/      Terraform demo fixtures
├── cloudformation/ CloudFormation demo fixtures
├── cdk/            CDK demo fixtures
└── reports/        Sample generated reports
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

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint
npm run lint

# Format
npm run format
```

## Demo

Run the scanner against intentionally vulnerable demo fixtures:

```bash
# Text output
npm run build && node dist/cli/index.js scan --iac demo/terraform

# Generate all report formats
node dist/cli/index.js scan --iac demo/terraform --format json,markdown,pdf --output demo/reports/scan
```

## CI/CD Integration

Use the `--fail-on` flag to fail builds when security issues are found:

```yaml
# GitHub Actions example
- name: Security scan
  run: infra-agent scan --iac ./terraform --fail-on HIGH
```

See `.github/workflows/ci.yml` for a complete CI workflow example.

## License

MIT
