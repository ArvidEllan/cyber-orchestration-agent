# Infrastructure Security Review Agent


A comprehensive security analysis system for AWS cloud infrastructure that evaluates Infrastructure-as-Code (IaC), audits live AWS environments, detects threats, generates compliance reports, and provides AI-driven remediation recommendations.


## Features

- **Static IaC Analysis**: Parse and analyze Terraform, CloudFormation, and AWS CDK files
- **Live Environment Auditing**: Connect to AWS accounts and audit runtime configurations
- **Threat Intelligence**: Analyze security logs and correlate events
- **Compliance Mapping**: Map findings to CIS, ISO 27001, NIST 800-53, and other frameworks
- **AI-Driven Remediation**: Generate actionable fixes and automated pull requests
- **Multi-Format Reports**: Export reports in PDF, JSON, CSV, and Markdown


## Installation

```bash
npm install -g @security/infra-agent
```

## Quick Start

```bash
# Scan IaC files
infra-agent scan --iac ./terraform --output report.pdf

# Audit live AWS environment
infra-agent audit --profile prod --regions us-east-1,us-west-2

# Generate compliance report
infra-agent compliance --framework cis --format json
```

## Project Structure
src/
├── types/          # Core TypeScript interfaces and types
├── parsers/        # IaC parsers (Terraform, CloudFormation, CDK)
├── auditors/       # AWS environment auditors
├── analyzers/      # Threat intelligence analyzers
├── rules/          # Security rules engine
├── compliance/     # Compliance framework mapping
├── remediation/    # Remediation engine and fix generation
├── reports/        # Report generation and export
├── notifications/  # Notification service integrations
├── database/       # Findings storage and retrieval
├── ai/            # AI reasoning engine
└── utils/         # Utility functions

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run linting
npm run lint

# Format code
npm run format
```

## Configuration

Create a `.infra-agent.yml` file in your project root:

```yaml
aws:
  profiles:
    - name: production
      regions: [us-east-1, us-west-2]

rules:
  enabled_rulesets:
    - cis-aws-foundations
    - aws-well-architected

compliance:
  frameworks:
    - cis_aws_foundations
    - nist_800_53

output:
  formats: [pdf, json]
  destination: ./reports
```## Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for details on how to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
