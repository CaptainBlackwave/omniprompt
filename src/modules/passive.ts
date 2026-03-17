import { sendRequest, HttpResponse } from '../utils/http';
import type { WafSignature, PassiveResult } from '../core/types';
import signaturesData from '../data/signatures.json';

const signatures: WafSignature[] = signaturesData.signatures as WafSignature[];

export async function runPassiveScan(target: string): Promise<PassiveResult> {
  const result: PassiveResult = {
    matched: false,
    wafName: null,
    confidence: 0,
    matchedIndicators: [],
  };

  try {
    const response = await sendRequest(target);

    for (const sig of signatures) {
      let matchCount = 0;
      const totalIndicators = countIndicators(sig.indicators);
      const matched: string[] = [];

      if (sig.indicators.headers) {
        for (const [header, pattern] of Object.entries(sig.indicators.headers)) {
          const headerValue = response.headers[header.toLowerCase()];
          if (headerValue && new RegExp(pattern, 'i').test(headerValue)) {
            matchCount++;
            matched.push(`Header: ${header}`);
          }
        }
      }

      if (sig.indicators.cookies) {
        for (const cookie of sig.indicators.cookies) {
          if (response.cookies[cookie]) {
            matchCount++;
            matched.push(`Cookie: ${cookie}`);
          }
        }
      }

      if (sig.indicators.statusCodes) {
        for (const code of sig.indicators.statusCodes) {
          if (response.status === code) {
            matchCount++;
            matched.push(`Status: ${code}`);
          }
        }
      }

      if (sig.indicators.bodyPatterns) {
        for (const pattern of sig.indicators.bodyPatterns) {
          if (response.body.toLowerCase().includes(pattern.toLowerCase())) {
            matchCount++;
            matched.push(`Body: ${pattern}`);
          }
        }
      }

      const confidence = totalIndicators > 0 ? matchCount / totalIndicators : 0;

      if (confidence >= 0.5 && confidence > result.confidence) {
        result.matched = true;
        result.wafName = sig.name;
        result.confidence = Math.min(confidence * sig.confidence, 1);
        result.matchedIndicators = matched;
      }
    }

    if (!result.matched && response.status === 403) {
      result.matchedIndicators.push('Received 403 Forbidden (potential WAF)');
    }

  } catch (error) {
    result.matchedIndicators.push(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return result;
}

function countIndicators(indicators: WafSignature['indicators']): number {
  let count = 0;
  if (indicators.headers) count += Object.keys(indicators.headers).length;
  if (indicators.cookies) count += indicators.cookies.length;
  if (indicators.statusCodes) count += indicators.statusCodes.length;
  if (indicators.bodyPatterns) count += indicators.bodyPatterns.length;
  return count || 1;
}
