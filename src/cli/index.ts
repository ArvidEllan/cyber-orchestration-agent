#!/usr/bin/env node

/**
 * CLI Entry Point
 * Command-line interface for the Infrastructure Security Review Agent
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import * as path from 'path';
import * as fs from 'fs/promises';
import { TerraformParser } from '../parsers/terraform-parser';
import { CloudFormationParser } from '../parsers/cloudformation-parser';
import { CDKParser } from '../parsers/cdk-parser';
import { IaCSecurityScanner } from '../parsers/iac-security-scanner';
import { Finding, Severity, IaCProvider } from '../types/core';
import { IaCFormat } from '../types';
import { MarkdownReporter } from '../reports/markdown-reporter';
import { JSONReporter } from '../reports/json-reporter';
import { PDFReporter } from '../reports/pdf-reporter';

const VERSION = '1.0.0';

const program = new Command();

program
  .name('infra-agent')
  .description('CLI security tool for IaC analysis, AWS auditing, and AI-driven remediation')
  .version(VERSION);

// ============================================================================
// Scan Command
// ============================================================================

program
  .command('scan')
  .description('Scan IaC files for security misconfigurations')
  .requiredOption('--iac <path>', 'Path to IaC files or directory')
  .option('--provider <type>', 'IaC provider: terraform, cloudformation, cdk', 'terraform')
  .option('--severity <level>', 'Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO', 'LOW')
  .option('--format <types>', 'Output formats (comma-separated): text, json, markdown, pdf', 'text')
  .option('--output <basename>', 'Output file basename (for non-text formats)')
  .option('--fail-on <level>', 'Exit with code 1 if findings at or above this severity')
  .option('--no-ai', 'Disable AI-powered remediation suggestions')
  .action(async (options) => {
    await runScan(options);
  });

// ============================================================================
// Audit Command (placeholder)
// ============================================================================

program
  .command('audit')
  .description('Audit live AWS environment')
  .option('--profile <name>', 'AWS profile to use', 'default')
  .option('--regions <list>', 'Comma-separated list of regions', 'us-east-1')
  .action(async (_options) => {
    console.log(chalk.yellow('AWS audit functionality coming in Phase 3...'));
  });

// ============================================================================
// Full Command (placeholder)
// ============================================================================

program
  .command('full')
  .description('Run both IaC scan and AWS audit')
  .requiredOption('--iac <path>', 'Path to IaC files or directory')
  .option('--profile <name>', 'AWS profile to use', 'default')
  .action(async (_options) => {
    console.log(chalk.yellow('Full scan functionality coming in Phase 6...'));
  });

// ============================================================================
// Scan Implementation
// ============================================================================

interface ScanOptions {
  iac: string;
  provider: string;
  severity: string;
  format: string;
  failOn?: string;
}

async function runScan(options: ScanOptions): Promise<void> {
  const spinner = ora('Scanning IaC files...').start();

  try {
    const iacPath = path.resolve(options.iac);

    if (options.provider !== 'terraform') {
      spinner.fail(`Provider "${options.provider}" not yet implemented`);
      console.log(chalk.yellow('Currently supported: terraform'));
      process.exit(1);
    }

    const parser = new TerraformParser();
    const result = await parser.scanDirectory(iacPath);

    spinner.succeed(`Scanned ${result.fileCount} files, ${result.resourceCount} resources`);

    // Filter by severity
    const minSeverity = parseSeverity(options.severity);
    const filteredFindings = result.findings.filter(
      (f) => severityToNumber(f.severity) >= severityToNumber(minSeverity)
    );

    // Handle errors
    if (result.errors.length > 0) {
      console.log();
      console.log(chalk.yellow(`Warnings: ${result.errors.length} file(s) could not be parsed`));
      for (const err of result.errors) {
        console.log(chalk.gray(`  - ${err.file}: ${err.error}`));
      }
    }

    // Output findings
    if (options.format === 'json') {
      console.log(JSON.stringify({ findings: filteredFindings, summary: getSummary(filteredFindings) }, null, 2));
    } else {
      printTextReport(filteredFindings);
    }

    // Handle --fail-on
    if (options.failOn) {
      const failThreshold = parseSeverity(options.failOn);
      const failingFindings = filteredFindings.filter(
        (f) => severityToNumber(f.severity) >= severityToNumber(failThreshold)
      );
      if (failingFindings.length > 0) {
        console.log();
        console.log(chalk.red(`Failing due to ${failingFindings.length} finding(s) at or above ${options.failOn} severity`));
        process.exit(1);
      }
    }
  } catch (error) {
    spinner.fail('Scan failed');
    console.error(chalk.red(error instanceof Error ? error.message : String(error)));
    process.exit(1);
  }
}

// ============================================================================
// Output Formatting
// ============================================================================

function printTextReport(findings: Finding[]): void {
  console.log();

  if (findings.length === 0) {
    console.log(chalk.green('No security findings detected.'));
    return;
  }

  console.log(chalk.bold(`Found ${findings.length} security issue(s):\n`));

  // Group by severity
  const grouped = groupBySeverity(findings);

  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]) {
    const group = grouped[severity];
    if (group && group.length > 0) {
      console.log(severityBadge(severity) + chalk.bold(` (${group.length})`));
      console.log();

      for (const finding of group) {
        printFinding(finding);
      }
    }
  }

  // Summary
  const summary = getSummary(findings);
  console.log(chalk.bold('\nSummary:'));
  console.log(`  ${chalk.red('CRITICAL')}: ${summary.critical}`);
  console.log(`  ${chalk.magenta('HIGH')}: ${summary.high}`);
  console.log(`  ${chalk.yellow('MEDIUM')}: ${summary.medium}`);
  console.log(`  ${chalk.blue('LOW')}: ${summary.low}`);
  console.log(`  ${chalk.gray('INFO')}: ${summary.info}`);
}

function printFinding(finding: Finding): void {
  const location = finding.resource.location?.file
    ? chalk.gray(`${finding.resource.location.file}`)
    : '';

  console.log(`  ${chalk.cyan(finding.resource.id)}`);
  console.log(`    ${finding.title}`);
  console.log(`    ${chalk.gray(finding.description.substring(0, 100))}${finding.description.length > 100 ? '...' : ''}`);

  if (finding.frameworks && finding.frameworks.length > 0) {
    const frameworks = finding.frameworks.map((f) => f.framework).join(', ');
    console.log(`    ${chalk.gray('Frameworks:')} ${frameworks}`);
  }

  if (finding.mitre) {
    console.log(`    ${chalk.gray('MITRE:')} ${finding.mitre.techniqueId} - ${finding.mitre.techniqueName}`);
  }

  if (location) {
    console.log(`    ${chalk.gray('File:')} ${location}`);
  }

  console.log();
}

function severityBadge(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.bgRed.white.bold(' CRITICAL ');
    case 'HIGH':
      return chalk.bgMagenta.white.bold('   HIGH   ');
    case 'MEDIUM':
      return chalk.bgYellow.black.bold('  MEDIUM  ');
    case 'LOW':
      return chalk.bgBlue.white.bold('   LOW    ');
    case 'INFO':
      return chalk.bgGray.white.bold('   INFO   ');
    default:
      return chalk.bgGray.white.bold(' UNKNOWN  ');
  }
}

function groupBySeverity(findings: Finding[]): Record<Severity, Finding[]> {
  const grouped: Record<Severity, Finding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

function getSummary(findings: Finding[]): { critical: number; high: number; medium: number; low: number; info: number; total: number } {
  const grouped = groupBySeverity(findings);
  return {
    critical: grouped.CRITICAL.length,
    high: grouped.HIGH.length,
    medium: grouped.MEDIUM.length,
    low: grouped.LOW.length,
    info: grouped.INFO.length,
    total: findings.length,
  };
}

// ============================================================================
// Utility Functions
// ============================================================================

function parseSeverity(s: string): Severity {
  const upper = s.toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(upper)) {
    return upper as Severity;
  }
  return 'LOW';
}

function severityToNumber(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL':
      return 5;
    case 'HIGH':
      return 4;
    case 'MEDIUM':
      return 3;
    case 'LOW':
      return 2;
    case 'INFO':
      return 1;
    default:
      return 0;
  }
}

// Run CLI
program.parse();
