// Collateral Fetcher HTTP Client with Retry Logic
// Implements subtask 4.1: HTTP client for PCCS/Intel PCS endpoints with timeout and retry

import { QuoteVerificationError } from './quote-types';

export interface FetchWithRetryOptions {
  timeout?: number; // ms
  retries?: number;
}

/**
 * Fetch a URL with retry and timeout logic (using AbortController).
 * Retries on network errors and HTTP errors (>=500). Exponential backoff.
 * @param url URL to fetch
 * @param options { timeout, retries }
 * @returns Response text if successful
 * @throws Error if all retries fail
 */
export async function fetchWithRetry(
  url: string,
  options: FetchWithRetryOptions = {},
): Promise<string> {
  const timeout = options.timeout ?? 30000;
  const retries = options.retries ?? 3;
  let lastError: unknown;

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (!response.ok) {
        // Retry on server errors (5xx)
        if (response.status >= 500 && response.status < 600) {
          throw new QuoteVerificationError(
            'CertificateError',
            `HTTP error ${response.status}: ${response.statusText}`,
          );
        }
        // For 4xx, do not retry
        throw new QuoteVerificationError(
          'CertificateError',
          `HTTP error ${response.status}: ${response.statusText}`,
        );
      }
      return await response.text();
    } catch (error: unknown) {
      lastError = error;
      // AbortError or network error: retry
      if (attempt < retries - 1) {
        // Exponential backoff
        await new Promise((res) => setTimeout(res, 1000 * Math.pow(2, attempt)));
      }
    }
  }
  let message = 'Unknown error';
  if (lastError instanceof Error) {
    message = lastError.message;
  } else if (typeof lastError === 'string') {
    message = lastError;
  }
  throw new QuoteVerificationError(
    'UnknownError',
    `Failed to fetch after ${retries} attempts: ${message}`,
  );
}

export interface CollateralFetchOptions {
  pccsUrl?: string;
  useIntelPCS?: boolean;
  timeout?: number;
  retries?: number;
  cacheResults?: boolean;
  isTdx?: boolean; // Add this if you want to support TDX
}

function normalizePccsUrl(url: string | undefined, isTdx: boolean = false): string {
  if (!url) {
    return isTdx
      ? 'https://api.trustedservices.intel.com/tdx/certification/v4'
      : 'https://api.trustedservices.intel.com/sgx/certification/v4';
  }
  let trimmed = url.trim().replace(/\/+$/, '');
  const sgxPath = '/sgx/certification/v4';
  const tdxPath = '/tdx/certification/v4';
  const path = isTdx ? tdxPath : sgxPath;
  if (trimmed.endsWith(sgxPath) || trimmed.endsWith(tdxPath)) {
    return trimmed;
  }
  // Remove any trailing /sgx/certification/v4 or /tdx/certification/v4
  trimmed = trimmed.replace(/\/(sgx|tdx)\/certification\/v4$/, '');
  return trimmed + path;
}

export class CollateralFetcher {
  private options: CollateralFetchOptions;
  private cache: Map<string, unknown>;
  private baseUrl: string;

  constructor(options: CollateralFetchOptions = {}) {
    this.options = {
      pccsUrl: options.isTdx
        ? 'https://localhost:8081/tdx/certification/v4'
        : 'https://localhost:8081/sgx/certification/v4',
      useIntelPCS: true,
      timeout: 30000,
      retries: 3,
      cacheResults: true,
      isTdx: true,
      ...options,
    };
    this.cache = new Map();
    this.baseUrl = this.getBaseUrl();
  }

  /**
   * Clear the internal cache of fetched collateral data.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Check if a cache entry exists for a given key.
   */
  hasCache(key: string): boolean {
    return this.cache.has(key);
  }

  /**
   * Get a cached value by key, or undefined if not present.
   */
  getCache<T = unknown>(key: string): T | undefined {
    return this.cache.get(key) as T | undefined;
  }

  /**
   * Set a cache value by key.
   */
  setCache<T = unknown>(key: string, value: T): void {
    this.cache.set(key, value);
  }

  /**
   * Get the number of cached entries.
   */
  cacheSize(): number {
    return this.cache.size;
  }

  /**
   * Returns the current service provider ('PCCS' or 'IntelPCS').
   */
  getServiceProvider(): 'PCCS' | 'IntelPCS' {
    return this.options.useIntelPCS ? 'IntelPCS' : 'PCCS';
  }

  /**
   * Returns the base URL for the current provider.
   */
  getBaseUrl(): string {
    if (this.options.useIntelPCS) {
      // Default to SGX PCS endpoint; add logic for TDX if needed
      return this.options.isTdx
        ? 'https://api.trustedservices.intel.com/tdx/certification/v4'
        : 'https://api.trustedservices.intel.com/sgx/certification/v4';
    }
    return normalizePccsUrl(this.options.pccsUrl, !!this.options.isTdx);
  }

  /**
   * Switch service provider at runtime.
   * @param useIntelPCS true for Intel PCS, false for PCCS
   */
  setServiceProvider(useIntelPCS: boolean): void {
    this.options.useIntelPCS = useIntelPCS;
    this.baseUrl = this.getBaseUrl();
  }

  /**
   * Update PCCS URL at runtime.
   * @param url New PCCS URL
   */
  setPccsUrl(url: string): void {
    this.options.pccsUrl = url;
    this.baseUrl = this.getBaseUrl();
  }

  /**
   * Fetch TCB Info from PCCS or Intel PCS, using cache if enabled.
   * @param fmspc FMSPC identifier (hex string)
   * @returns TCB Info as string (JSON)
   */
  async fetchTcbInfo(fmspc: string): Promise<string> {
    const cacheKey = `tcb_${fmspc}`;
    if (this.options.cacheResults && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string;
    }
    const endpoint = `${this.baseUrl}/tcb?fmspc=${encodeURIComponent(fmspc)}`;
    console.log('[DEBUG] fetchTcbInfo endpoint:', endpoint);
    try {
      const result = await fetchWithRetry(endpoint, {
        timeout: this.options.timeout,
        retries: this.options.retries,
      });
      console.log('[DEBUG] fetchTcbInfo result (truncated):', result.slice(0, 200));
      if (this.options.cacheResults) {
        this.cache.set(cacheKey, result);
      }
      return result;
    } catch (err) {
      console.log('[DEBUG] fetchTcbInfo error:', err);
      throw err;
    }
  }

  /**
   * Fetch QE Identity from PCCS or Intel PCS, using cache if enabled.
   * @param qeid QE Identity identifier (string, may be empty for all)
   * @returns QE Identity as string (JSON)
   */
  async fetchQeIdentity(qeid: string = ''): Promise<string> {
    const cacheKey = `qeid_${qeid}`;
    if (this.options.cacheResults && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string;
    }
    const endpoint = `${this.baseUrl}/qe/identity${qeid ? `?qeid=${encodeURIComponent(qeid)}` : ''}`;
    const result = await fetchWithRetry(endpoint, {
      timeout: this.options.timeout,
      retries: this.options.retries,
    });
    if (this.options.cacheResults) {
      this.cache.set(cacheKey, result);
    }
    return result;
  }

  /**
   * Fetch PCK Certificate Chain from PCCS or Intel PCS.
   * @param encPceId Encoded PCE ID (hex string)
   * @param cpuSvn CPU SVN (hex string)
   * @param pceSvn PCE SVN (hex string)
   * @returns PCK Certificate Chain as string (PEM or JSON)
   */
  async fetchPckCertificateChain(
    encPceId: string,
    cpuSvn: string,
    pceSvn: string,
  ): Promise<string> {
    const cacheKey = `pckcert_${encPceId}_${cpuSvn}_${pceSvn}`;
    if (this.options.cacheResults && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string;
    }
    const endpoint = `${this.baseUrl}/pckcert?encPceId=${encodeURIComponent(encPceId)}&cpuSvn=${encodeURIComponent(cpuSvn)}&pceSvn=${encodeURIComponent(pceSvn)}`;
    const result = await fetchWithRetry(endpoint, {
      timeout: this.options.timeout,
      retries: this.options.retries,
    });
    if (this.options.cacheResults) {
      this.cache.set(cacheKey, result);
    }
    return result;
  }

  /**
   * Fetch PCK CRL from PCCS or Intel PCS.
   * @param ca CA type (string, e.g., 'processor' or 'platform')
   * @returns PCK CRL as string (PEM)
   */
  async fetchPckCrl(ca: string): Promise<string> {
    const cacheKey = `pckcrl_${ca}`;
    if (this.options.cacheResults && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string;
    }
    const endpoint = `${this.baseUrl}/pckcrl?ca=${encodeURIComponent(ca)}`;
    const result = await fetchWithRetry(endpoint, {
      timeout: this.options.timeout,
      retries: this.options.retries,
    });
    if (this.options.cacheResults) {
      this.cache.set(cacheKey, result);
    }
    return result;
  }

  /**
   * Fetch Root CA CRL from PCCS or Intel PCS.
   * @returns Root CA CRL as string (PEM)
   */
  async fetchRootCaCrl(): Promise<string> {
    const cacheKey = `rootcacrl`;
    if (this.options.cacheResults && this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as string;
    }
    const endpoint = `${this.baseUrl}/rootcacrl`;
    const result = await fetchWithRetry(endpoint, {
      timeout: this.options.timeout,
      retries: this.options.retries,
    });
    if (this.options.cacheResults) {
      this.cache.set(cacheKey, result);
    }
    return result;
  }
}

// --- Integration Test Structure (Outline) ---
//
// import { CollateralFetcher } from './collateral-fetcher';
//
// describe('CollateralFetcher Integration', () => {
//   it('fetches TCB info from PCCS', async () => {
//     const fetcher = new CollateralFetcher({ useIntelPCS: false, pccsUrl: 'http://localhost:8081/sgx/certification/v3/' });
//     const tcb = await fetcher.fetchTcbInfo('001122334455');
//     expect(tcb).toContain('tcbInfo');
//   });
//
//   it('fetches TCB info from Intel PCS', async () => {
//     const fetcher = new CollateralFetcher({ useIntelPCS: true });
//     const tcb = await fetcher.fetchTcbInfo('001122334455');
//     expect(tcb).toContain('tcbInfo');
//   });
//
//   it('switches provider at runtime', async () => {
//     const fetcher = new CollateralFetcher({ useIntelPCS: false });
//     fetcher.setServiceProvider(true);
//     expect(fetcher.getServiceProvider()).toBe('IntelPCS');
//   });
//
//   it('handles failover if one service is unavailable', async () => {
//     const fetcher = new CollateralFetcher({ useIntelPCS: false, pccsUrl: 'http://bad-url/' });
//     try {
//       await fetcher.fetchTcbInfo('001122334455');
//     } catch (e) {
//       fetcher.setServiceProvider(true);
//       const tcb = await fetcher.fetchTcbInfo('001122334455');
//       expect(tcb).toContain('tcbInfo');
//     }
//   });
//
//   // Add more tests for error mapping, caching, and all fetch methods
// });
