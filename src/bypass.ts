import { sendEvasionRequest, isBlocked, isRateLimited, sendRequest, HttpResponse } from '../utils/http';
import { evasionTechniques, getAllTechniques, getTechniquesByCategory } from '../utils/evasion';
import { RateLimiter, ProxyRotator, delay, randomJitter } from '../utils/ratelimit';
import type { Payload, BypassResult } from '../core/types';
import payloadsData from '../data/payloads.json';

const payloads: Payload[] = payloadsData.payloads as Payload[];
const testPayloads = payloads.slice(0, 3);

export interface AdvancedBypassOptions {
  enableProtocol?: boolean;
  enableParsing?: boolean;
  enableSize?: boolean;
  enableML?: boolean;
  enableEncoding?: boolean;
  paddingSize?: number;
  proxies?: string[];
  maxRequestsPerMinute?: number;
}

export async function runAdvancedBypassScan(
  target: string,
  detectedWaf: string | null,
  hardeningScore: number,
  options: AdvancedBypassOptions = {}
): Promise<BypassResult> {
  const result: BypassResult = {
    bypassesFound: [],
    verifiedBypasses: [],
    failedBypasses: [],
  };

  const rateLimiter = new RateLimiter({
    maxRequests: options.maxRequestsPerMinute || 10,
    windowMs: 60000,
    backoffMs: 5000,
    jitterMs: 2000,
  });

  const proxyRotator = options.proxies && options.proxies.length > 0
    ? new ProxyRotator(options.proxies)
    : null;

  const baseline = await sendRequest(target);

  const categories: string[] = [];
  if (options.enableProtocol !== false) categories.push('Protocol');
  if (options.enableParsing !== false) categories.push('Parsing');
  if (options.enableSize !== false) categories.push('Size');
  if (options.enableML !== false) categories.push('ML');
  if (options.enableEncoding !== false) categories.push('Encoding');

  for (const category of categories) {
    const techniques = getTechniquesByCategory(category);
    
    for (const technique of techniques) {
      result.bypassesFound.push(technique.name);

      await rateLimiter.waitIfNeeded();

      const bypassed = await testEvasionTechnique(
        target,
        technique.name,
        technique.apply,
        baseline,
        rateLimiter,
        proxyRotator,
        options.paddingSize
      );

      if (bypassed) {
        result.verifiedBypasses.push(technique.name);
        console.log(`[+] Bypass found: ${technique.name}`);
      } else {
        result.failedBypasses.push(technique.name);
      }

      await delay(randomJitter(500, 500));
    }
  }

  if (hardeningScore < 30 && result.verifiedBypasses.length === 0) {
    const quickTests = ['hpp', 'headerSpoofing', 'mlJunkPadding', 'paddingMode'];
    for (const techName of quickTests) {
      const technique = evasionTechniques[techName];
      if (!technique) continue;

      const bypassed = await testEvasionTechnique(
        target,
        technique.name,
        technique.apply,
        baseline,
        rateLimiter,
        proxyRotator,
        options.paddingSize
      );

      if (bypassed && !result.verifiedBypasses.includes(technique.name)) {
        result.verifiedBypasses.push(technique.name);
      }
    }
  }

  return result;
}

async function testEvasionTechnique(
  target: string,
  techniqueName: string,
  applyFn: (payload: string, options?: { paddingSize?: number }) => { modifiedPayload?: string; modifiedHeaders?: Record<string, string>; modifiedBody?: string; contentType?: string; method?: string; },
  baseline: HttpResponse,
  rateLimiter: RateLimiter,
  proxyRotator: ProxyRotator | null,
  paddingSize?: number
): Promise<boolean> {
  for (const payload of testPayloads) {
    try {
      const evasionResult = applyFn(payload.payload, { paddingSize });
      const proxyUrl = proxyRotator?.getCurrentProxy()?.url;

      const response = await sendEvasionRequest(target, evasionResult, proxyUrl);

      if (isRateLimited(response)) {
        rateLimiter.handleRateLimitResponse(response.status);
        await delay(randomJitter(2000, 1000));
        continue;
      }

      const blocked = isBlocked(response);

      if (!blocked && response.status !== baseline.status) {
        return true;
      }

      if (!blocked && response.status === baseline.status && response.body !== baseline.body) {
        return true;
      }

    } catch (error) {
      if (proxyRotator) {
        proxyRotator.markFailed();
      }
      console.log(`[-] Error testing ${techniqueName}: ${error instanceof Error ? error.message : 'Unknown'}`);
    }
  }

  return false;
}

export async function runBypassScan(
  target: string,
  detectedWaf: string | null,
  hardeningScore: number
): Promise<BypassResult> {
  return runAdvancedBypassScan(target, detectedWaf, hardeningScore);
}
