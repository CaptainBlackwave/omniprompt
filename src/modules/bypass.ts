import { sendRequest, HttpResponse } from '../utils/http';
import type { BypassResult, Payload } from '../core/types';
import { tamperFunctions } from '../utils/encoder';
import tampersData from '../data/tampers.json';
import payloadsData from '../data/payloads.json';

const tampers = tampersData.tampers;
const payloads: Payload[] = payloadsData.payloads as Payload[];

const testPayloads = payloads.slice(0, 5);

export async function runBypassScan(
  target: string,
  detectedWaf: string | null,
  hardeningScore: number
): Promise<BypassResult> {
  const result: BypassResult = {
    bypassesFound: [],
    verifiedBypasses: [],
    failedBypasses: [],
  };

  const baseline = await sendRequest(target);

  for (const tamper of tampers) {
    result.bypassesFound.push(tamper.name);

    const tamperFn = tamperFunctions[tamper.apply];
    if (!tamperFn) {
      result.failedBypasses.push(tamper.name);
      continue;
    }

    const bypassed = await testTamper(target, tamperFn, baseline);

    if (bypassed) {
      result.verifiedBypasses.push(tamper.name);
    } else {
      result.failedBypasses.push(tamper.name);
    }
  }

  if (hardeningScore < 30) {
    const simpleBypassNames = ['Case_Insensitive', 'URL_Encoding'];
    for (const bp of simpleBypassNames) {
      if (!result.verifiedBypasses.includes(bp)) {
        const tamperEntry = tampers.find(t => t.name === bp);
        const tamperFn = tamperEntry ? tamperFunctions[tamperEntry.apply] : undefined;
        if (tamperFn) {
          const testPayload = testPayloads[0].payload;
          const encoded = tamperFn(testPayload);
          try {
            const url = new URL(target);
            url.searchParams.set('q', encoded);
            const response = await sendRequest(url.toString());
            if (response.status !== 403 && !response.body.toLowerCase().includes('blocked')) {
              result.verifiedBypasses.push(bp + '_potential');
            }
          } catch {
            // Ignore
          }
        }
      }
    }
  }

  return result;
}

async function testTamper(
  target: string,
  tamperFn: (p: string) => string,
  baseline: HttpResponse
): Promise<boolean> {
  for (const payload of testPayloads) {
    const encodedPayload = tamperFn(payload.payload);

    try {
      const url = new URL(target);
      url.searchParams.set('q', encodedPayload);
      
      const response = await sendRequest(url.toString());

      const isBlocked = 
        response.status === 403 ||
        response.status === 406 ||
        response.body.toLowerCase().includes('blocked') ||
        response.body.toLowerCase().includes('forbidden');

      if (!isBlocked && response.status !== baseline.status) {
        continue;
      }

      if (!isBlocked) {
        return true;
      }
    } catch {
      return false;
    }
  }

  return false;
}
