#!/usr/bin/env bun

import { Command } from 'commander';
import ora from 'ora';
import { runScan } from '../core/engine';
import { generateReport, generateJsonReport, generateCsvReport } from '../modules/reporting';
import chalk from 'chalk';
import { writeFileSync } from 'fs';

const program = new Command();

program
  .name('omniwaf')
  .description('Comprehensive WAF Fingerprinting & Evasion Framework')
  .version('1.0.1');

program
  .option('-u, --url <url>', 'Target URL to scan')
  .option('-o, --output <file>', 'Output file (json or csv)')
  .option('--json', 'Output as JSON')
  .option('--csv', 'Output as CSV')
  .option('--no-colors', 'Disable colored output')
  .action(async (options) => {
    const target = options.url;

    if (!target) {
      console.error(chalk.red('Error: Please provide a target URL with -u or --url'));
      process.exit(1);
    }

    let url: string;
    try {
      url = new URL(target).toString();
    } catch {
      console.error(chalk.red('Error: Invalid URL provided'));
      process.exit(1);
    }

    if (options.noColors) {
      chalk.level = 0;
    }

    const spinner = ora({
      text: 'Initializing OmniWaf scan...',
      color: 'cyan',
    }).start();

    try {
      spinner.text = 'Running Phase 1: Passive Reconnaissance...';
      const result = await runScan(url);

      spinner.succeed('Scan completed!');

      if (options.json || options.output?.endsWith('.json')) {
        const jsonOutput = generateJsonReport(result);
        if (options.output) {
          writeFileSync(options.output, jsonOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(jsonOutput);
        }
      } else if (options.csv || options.output?.endsWith('.csv')) {
        const csvOutput = generateCsvReport(result);
        if (options.output) {
          writeFileSync(options.output, csvOutput);
          console.log(chalk.green(`Results written to ${options.output}`));
        } else {
          console.log(csvOutput);
        }
      } else {
        generateReport(result);
      }
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      process.exit(1);
    }
  });

program.parse();
