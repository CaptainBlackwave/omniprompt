import { sendRequest, HttpResponse } from '../utils/http';
import type { Payload, HeuristicResult } from '../core/types';
import payloadsData from '../data/payloads.json';

const payloads: Payload[] = payloadsData.payloads as Payload[];

const wafArchetypes: Record<string, { patterns: string[]; score: number }> = {
  'AWS WAF Core Rule Set': {
    patterns: ['aws', 'waf', 'requestid'],
    score: 85,
  },
  'Cloudflare Ruleset': {
    patterns: ['cloudflare', 'ray', 'cf'],
    score: 80,
  },
  'ModSecurity Core Rule Set': {
    patterns: ['mod_security', 'modsecurity'],
    score: 75,
  },
  'Generic WAF': {
    patterns: ['blocked', 'forbidden', 'security'],
    score: 60,
  },
};

export async function runHeuristicScan(target: string): Promise<HeuristicResult> {
  const result: HeuristicResult = {
    securityHardeningScore: 0,
    wafArchetype: null,
    blockedPayloads: 0,
    totalPayloads: payloads.length,
    behaviorProfile: {},
  };

  const baselineResponse = await sendRequest(target);
  const baselineStatus = baselineResponse.status;
  const baselineBody = baselineResponse.body;

  let totalWeight = 0;
  let blockedWeight = 0;

  for (const payload of payloads) {
    totalWeight += payload.weight;

    try {
      const testUrl = buildTestUrl(target, payload);
      const response = await sendRequest(testUrl);

      const blocked = detectBlocking(response, baselineResponse, payload);

      if (blocked) {
        blockedWeight += payload.weight;
        result.blockedPayloads++;
        result.behaviorProfile[`${payload.type}:${payload.vector}`] = 'blocked';
      } else {
        result.behaviorProfile[`${payload.type}:${payload.vector}`] = 'allowed';
      }
    } catch {
      result.behaviorProfile[`${payload.type}:${payload.vector}`] = 'error';
    }
  }

  result.securityHardeningScore = totalWeight > 0 
    ? Math.round((blockedWeight / totalWeight) * 100) 
    : 0;

  result.wafArchetype = determineArchetype(result.behaviorProfile, baselineResponse);

  return result;
}

function buildTestUrl(target: string, payload: Payload): string {
  const url = new URL(target);
  url.searchParams.set('test', payload.payload);
  url.searchParams.set('vector', payload.vector);
  return url.toString();
}

function detectBlocking(response: HttpResponse, baseline: HttpResponse, payload: Payload): boolean {
  if (response.status === 403 || response.status === 406 || response.status === 419) {
    return true;
  }

  if (response.status === baseline.status && 
      response.body !== baseline.body &&
      (response.body.toLowerCase().includes('blocked') ||
       response.body.toLowerCase().includes('forbidden') ||
       response.body.toLowerCase().includes('denied'))) {
    return true;
  }

  if (response.status === 200 && baseline.status === 200) {
    const bodyDiff = Math.abs(response.body.length - baseline.body.length);
    if (bodyDiff > 1000) {
      return true;
    }
  }

  return false;
}

function determineArchetype(profile: Record<string, string>, baseline: HttpResponse): string | null {
  const bodyLower = baseline.body.toLowerCase();
  
  for (const [archetype, data] of Object.entries(wafArchetypes)) {
    for (const pattern of data.patterns) {
      if (bodyLower.includes(pattern)) {
        return archetype;
      }
    }
  }

  const blockedCount = Object.values(profile).filter(v => v === 'blocked').length;
  if (blockedCount === 0) {
    return 'No WAF Detected (Permissive)';
  } else if (blockedCount < Object.keys(profile).length * 0.3) {
    return 'Weak WAF / Learning Mode';
  } else if (blockedCount < Object.keys(profile).length * 0.7) {
    return 'Standard WAF';
  } else {
    return 'Strong WAF / Strict Mode';
  }
}
