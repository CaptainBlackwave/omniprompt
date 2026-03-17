export interface RateLimitState {
  requestCount: number;
  windowStart: number;
  isRateLimited: boolean;
  backoffUntil: number;
  currentProxyIndex: number;
}

export interface ProxyConfig {
  url: string;
  auth?: { username: string; password: string };
}

export interface ProxyRotationConfig {
  proxies: ProxyConfig[];
  maxRetries: number;
  retryDelay: number;
}

const defaultRateLimitConfig = {
  maxRequests: 10,
  windowMs: 60000,
  backoffMs: 5000,
  jitterMs: 2000,
};

export class RateLimiter {
  private config: typeof defaultRateLimitConfig;
  private state: RateLimitState;

  constructor(config?: Partial<typeof defaultRateLimitConfig>) {
    this.config = { ...defaultRateLimitConfig, ...config };
    this.state = {
      requestCount: 0,
      windowStart: Date.now(),
      isRateLimited: false,
      backoffUntil: 0,
      currentProxyIndex: 0,
    };
  }

  async waitIfNeeded(): Promise<void> {
    if (this.state.isRateLimited && Date.now() < this.state.backoffUntil) {
      const waitTime = this.state.backoffUntil - Date.now();
      console.log(`Rate limited. Waiting ${waitTime}ms...`);
      await this.sleep(waitTime);
    }

    const now = Date.now();
    if (now - this.state.windowStart > this.config.windowMs) {
      this.state.requestCount = 0;
      this.state.windowStart = now;
    }

    this.state.requestCount++;

    if (this.state.requestCount > this.config.maxRequests) {
      const backoffTime = this.config.backoffMs + Math.random() * this.config.jitterMs;
      this.state.isRateLimited = true;
      this.state.backoffUntil = Date.now() + backoffTime;
      console.log(`Rate limit reached. Backing off for ${backoffTime}ms...`);
      await this.sleep(backoffTime);
      this.state.isRateLimited = false;
      this.state.requestCount = 0;
      this.state.windowStart = Date.now();
    }
  }

  handleRateLimitResponse(status: number): boolean {
    if (status === 429) {
      const backoffTime = this.config.backoffMs * 2 + Math.random() * this.config.jitterMs;
      this.state.isRateLimited = true;
      this.state.backoffUntil = Date.now() + backoffTime;
      console.log(`Received 429. Backing off for ${backoffTime}ms...`);
      return true;
    }
    return false;
  }

  handleBlockResponse(status: number, body?: string): boolean {
    if (status === 403 || status === 406 || status === 419) {
      return true;
    }
    if (body?.toLowerCase().includes('blocked') || body?.toLowerCase().includes('forbidden')) {
      return true;
    }
    return false;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  reset(): void {
    this.state = {
      requestCount: 0,
      windowStart: Date.now(),
      isRateLimited: false,
      backoffUntil: 0,
      currentProxyIndex: 0,
    };
  }

  getState(): RateLimitState {
    return { ...this.state };
  }
}

export class ProxyRotator {
  private proxies: ProxyConfig[];
  private currentIndex: number;
  private failedIndices: Set<number>;
  private maxRetries: number;

  constructor(proxies: string[], maxRetries: number = 3) {
    this.proxies = proxies.map(url => ({ url }));
    this.currentIndex = 0;
    this.failedIndices = new Set();
    this.maxRetries = maxRetries;
  }

  getCurrentProxy(): ProxyConfig | null {
    if (this.proxies.length === 0) return null;
    
    let attempts = 0;
    while (attempts < this.proxies.length) {
      if (!this.failedIndices.has(this.currentIndex)) {
        return this.proxies[this.currentIndex];
      }
      this.rotate();
      attempts++;
    }
    
    return this.proxies[this.currentIndex];
  }

  rotate(): void {
    this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
  }

  markFailed(): void {
    this.failedIndices.add(this.currentIndex);
    this.rotate();
  }

  markSuccess(): void {
    this.failedIndices.delete(this.currentIndex);
  }

  reset(): void {
    this.currentIndex = 0;
    this.failedIndices.clear();
  }

  hasProxies(): boolean {
    return this.proxies.length > 0;
  }

  getProxyCount(): number {
    return this.proxies.length;
  }
}

export async function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function randomJitter(baseMs: number, jitterMs: number): number {
  return baseMs + Math.random() * jitterMs;
}
