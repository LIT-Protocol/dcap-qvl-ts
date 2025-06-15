import { CollateralFetcher } from '../src/collateral-fetcher';
import { QuoteVerifier } from '../src/quote-verifier';
import { QuoteCollateralV3 } from '../src/quote-types';
import forge from 'node-forge';

describe('CollateralFetcher Integration (Real Endpoints)', () => {
  // WARNING: These tests make real network requests to Intel PCS endpoints.
  // They may fail if the endpoints are unavailable, rate-limited, or if network access is restricted.

  it('fetches TCB info from Intel PCS', async () => {
    const fetcher = new CollateralFetcher({ useIntelPCS: true });
    // Use the real FMSPC from tdx_quote_collateral.json
    const tcb = await fetcher.fetchTcbInfo('b0c06f000000');
    expect(typeof tcb).toBe('string');
    expect(tcb.length).toBeGreaterThan(0);
  });

  it('fetches QE Identity from Intel PCS', async () => {
    const fetcher = new CollateralFetcher({ useIntelPCS: true });
    const qe = await fetcher.fetchQeIdentity();
    expect(typeof qe).toBe('string');
    expect(qe.length).toBeGreaterThan(0);
  });

  it('fetches PCK Certificate Chain from Intel PCS', async () => {
    const fetcher = new CollateralFetcher({ useIntelPCS: true });
    // Values from dcap-qvl-rust/sample/tdx_quote_collateral.json
    // encPceId: "0000"
    // cpuSvn: 16 zero bytes (as hex)
    // pceSvn: 11 (from first tcbLevel)
    const encPceId = '0000';
    const cpuSvn = '00000000000000000000000000000000';
    const pceSvn = '11'; // Convert to string to match function signature
    try {
      const pck = await fetcher.fetchPckCertificateChain(encPceId, cpuSvn, pceSvn);
      expect(typeof pck).toBe('string');
      expect(pck.length).toBeGreaterThan(0);
    } catch (e) {
      if (e instanceof Error) {
        // Intel PCS may return 400 if the combination is not valid, but this is a real request
        expect(e.message).toMatch(/HTTP/);
      } else {
        // Fail the test if the error is not an instance of Error
        fail(e);
      }
    }
  });

  it('fetches PCK CRL from Intel PCS', async () => {
    const fetcher = new CollateralFetcher({ useIntelPCS: true });
    const crl = await fetcher.fetchPckCrl('processor');
    expect(typeof crl).toBe('string');
  });
});
