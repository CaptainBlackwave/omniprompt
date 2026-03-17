#!/usr/bin/env bun

import { Command } from 'commander';
import ora from 'ora';
import { runScan } from '../core/engine';
import { generateReport, generateJsonReport, generateCsvReport } from '../modules/reporting';
import chalk from 'chalk';
import { writeFileSync } from 'fs';
import { getAllTechniques, getTechniquesByCategory, techniqueCategories } from '../utils/evasion';

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
  
  .option('--skip-phase1', 'Skip Phase 1 (Passive Reconnaissance)')
  .option('--skip-phase2', 'Skip Phase 2 (Heuristic Inference)')
  .option('--skip-phase3', 'Skip Phase 3 (Evasion Testing)')
  
  .option('--no-protocol', 'Disable Protocol evasion techniques')
  .option('--no-parsing', 'Disable Parsing evasion techniques')
  .option('--no-size', 'Disable Size evasion techniques')
  .option('--no-ml', 'Disable ML evasion techniques')
  .option('--no-encoding', 'Disable Encoding evasion techniques')
  
  .option('--padding-size <bytes>', 'Garbage padding size in bytes', '8192')
  .option('--proxies <urls>', 'Comma-separated proxy URLs')
  .option('--max-rpm <number>', 'Max requests per minute', '10')
  
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
      console.log(chalk.cyan('\n=== OmniWaf Advanced Evasion Framework ===\n'));
      
      const techniques = getAllTechniques();
      console.log(chalk.gray(`Loaded ${techniques.length} evasion techniques`));
      
      if (options.protocol !== false && options.parsing !== false && options.size !== false && options.ml !== false && options.encoding !== false) {
        for (const cat of techniqueCategories) {
          const count = getTechniquesByCategory(cat).length;
          console.log(chalk.gray(`  - ${cat}: ${count} techniques`));
        }
      }
      console.log('');

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
