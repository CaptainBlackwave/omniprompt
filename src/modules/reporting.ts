import type { ScanResult } from '../core/types';
import chalk from 'chalk';

export function generateReport(result: ScanResult): void {
  console.log('\n' + '='.repeat(60));
  console.log(chalk.bold.cyan('  OmniWaf - WAF Fingerprinting & Evasion Report'));
  console.log('='.repeat(60));

  console.log(chalk.bold('\n📌 Target:') + ` ${result.target}`);

  console.log(chalk.bold('\n🛡️  WAF Detection:'));
  if (result.wafDetected) {
    console.log(chalk.green(`   Detected: ${result.wafDetected}`));
    console.log(chalk.gray(`   Confidence: ${(result.confidence * 100).toFixed(1)}%`));
    console.log(chalk.gray(`   Method: ${result.identificationMethod}`));
  } else {
    console.log(chalk.yellow('   No WAF detected with high confidence'));
  }

  console.log(chalk.bold('\n🔒 Hardening Score:'));
  const scoreColor = result.hardeningScore >= 70 ? 'red' : result.hardeningScore >= 40 ? 'yellow' : 'green';
  console.log(chalk[scoreColor](`   Score: ${result.hardeningScore}/100`));
  
  if (result.phase2Result?.wafArchetype) {
    console.log(chalk.gray(`   Profile: ${result.phase2Result.wafArchetype}`));
  }

  if (result.successfulBypasses.length > 0) {
    console.log(chalk.bold('\n⚠️  Successful Bypasses:'));
    result.successfulBypasses.forEach(bp => {
      console.log(chalk.red(`   ✗ ${bp}`));
    });
  } else {
    console.log(chalk.bold('\n✅ Bypass Results:'));
    console.log(chalk.green('   No bypasses detected'));
  }

  if (result.phase1Result?.matchedIndicators?.length) {
    console.log(chalk.bold('\n📊 Detection Indicators:'));
    result.phase1Result.matchedIndicators.forEach(ind => {
      console.log(chalk.gray(`   • ${ind}`));
    });
  }

  console.log('\n' + '='.repeat(60) + '\n');
}

export function generateJsonReport(result: ScanResult): string {
  const output = {
    target: result.target,
    waf_detected: result.wafDetected,
    confidence: result.confidence,
    identification_method: result.identificationMethod,
    hardening_score: result.hardeningScore,
    successful_bypasses: result.successfulBypasses,
    phase1: result.phase1Result ? {
      matched: result.phase1Result.matched,
      waf_name: result.phase1Result.wafName,
      matched_indicators: result.phase1Result.matchedIndicators,
    } : undefined,
    phase2: result.phase2Result ? {
      security_hardening_score: result.phase2Result.securityHardeningScore,
      waf_archetype: result.phase2Result.wafArchetype,
      blocked_payloads: result.phase2Result.blockedPayloads,
      total_payloads: result.phase2Result.totalPayloads,
    } : undefined,
    phase3: result.phase3Result ? {
      bypasses_found: result.phase3Result.bypassesFound,
      verified_bypasses: result.phase3Result.verifiedBypasses,
      failed_bypasses: result.phase3Result.failedBypasses,
    } : undefined,
  };

  return JSON.stringify(output, null, 2);
}

export function generateCsvReport(result: ScanResult): string {
  const headers = ['Target', 'WAF Detected', 'Confidence', 'Method', 'Hardening Score', 'Bypasses'];
  const row = [
    result.target,
    result.wafDetected || 'None',
    (result.confidence * 100).toFixed(1) + '%',
    result.identificationMethod,
    result.hardeningScore.toString(),
    result.successfulBypasses.join('; ') || 'None',
  ];

  return [headers.join(','), row.join(',')].join('\n');
}
