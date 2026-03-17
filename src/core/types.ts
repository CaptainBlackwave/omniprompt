export interface WafSignature {
  name: string;
  confidence: number;
  indicators: {
    headers?: Record<string, string>;
    cookies?: string[];
    statusCodes?: number[];
    bodyPatterns?: string[];
  };
}

export interface ScanResult {
  target: string;
  wafDetected: string | null;
  confidence: number;
  identificationMethod: string;
  hardeningScore: number;
  successfulBypasses: string[];
  phase1Result?: PassiveResult;
  phase2Result?: HeuristicResult;
  phase3Result?: BypassResult;
}

export interface PassiveResult {
  matched: boolean;
  wafName: string | null;
  confidence: number;
  matchedIndicators: string[];
}

export interface HeuristicResult {
  securityHardeningScore: number;
  wafArchetype: string | null;
  blockedPayloads: number;
  totalPayloads: number;
  behaviorProfile: Record<string, string>;
}

export interface BypassResult {
  bypassesFound: string[];
  verifiedBypasses: string[];
  failedBypasses: string[];
}

export interface Payload {
  type: string;
  vector: string;
  payload: string;
  weight: number;
}

export interface TamperScript {
  name: string;
  description: string;
  encoding: string;
  wafTypes: string[];
  apply: (payload: string) => string;
}
