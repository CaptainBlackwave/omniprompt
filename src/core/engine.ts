import type { ScanResult } from '../core/types';
import { runPassiveScan } from '../modules/passive';
import { runHeuristicScan } from '../modules/heuristic';
import { runBypassScan } from '../modules/bypass';

export async function runScan(target: string): Promise<ScanResult> {
  const result: ScanResult = {
    target,
    wafDetected: null,
    confidence: 0,
    identificationMethod: 'Not started',
    hardeningScore: 0,
    successfulBypasses: [],
  };

  const passiveResult = await runPassiveScan(target);
  result.phase1Result = passiveResult;

  if (passiveResult.matched && passiveResult.confidence >= 0.9) {
    result.wafDetected = passiveResult.wafName;
    result.confidence = passiveResult.confidence;
    result.identificationMethod = 'Passive (Signature match)';
    result.hardeningScore = 50;
    result.successfulBypasses = [];
    return result;
  }

  const heuristicResult = await runHeuristicScan(target);
  result.phase2Result = heuristicResult;

  if (passiveResult.matched && passiveResult.wafName) {
    result.wafDetected = passiveResult.wafName;
    result.confidence = Math.max(passiveResult.confidence, heuristicResult.securityHardeningScore / 100);
    result.identificationMethod = 'Passive + Heuristic';
  } else {
    result.wafDetected = heuristicResult.wafArchetype;
    result.confidence = heuristicResult.securityHardeningScore / 100;
    result.identificationMethod = 'Heuristic (Behavioral analysis)';
  }

  result.hardeningScore = heuristicResult.securityHardeningScore;

  if (heuristicResult.securityHardeningScore < 100) {
    const bypassResult = await runBypassScan(
      target,
      result.wafDetected,
      heuristicResult.securityHardeningScore
    );
    result.phase3Result = bypassResult;
    result.successfulBypasses = bypassResult.verifiedBypasses;
  }

  return result;
}
