import { CollateralFetcher } from '../src/collateral-fetcher';
import { QuoteVerifier } from '../src/quote-verifier';
import { QuoteCollateralV3 } from '../src/quote-types';
import fs from 'fs';
import path from 'path';

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

  it('verifies a real SGX quote end-to-end (matches Rust reference)', async () => {
    // Read binary quote
    const quotePath = path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote');
    const quoteBytes = fs.readFileSync(quotePath);
    // Read collateral JSON
    const collateralPath = path.join(
      __dirname,
      '../dcap-qvl-rust/sample/sgx_quote_collateral.json',
    );
    const collateralJson = fs.readFileSync(collateralPath, 'utf8');
    const rawCollateral = JSON.parse(collateralJson);
    // Map snake_case to camelCase for JS
    const collateral: QuoteCollateralV3 = {
      tcbInfoIssuerChain: rawCollateral.tcb_info_issuer_chain,
      tcbInfo: rawCollateral.tcb_info,
      tcbInfoSignature: Buffer.from(rawCollateral.tcb_info_signature, 'hex'),
      qeIdentityIssuerChain: rawCollateral.qe_identity_issuer_chain,
      qeIdentity: rawCollateral.qe_identity,
      qeIdentitySignature: Buffer.from(rawCollateral.qe_identity_signature, 'hex'),
    };
    const fetcher = new CollateralFetcher({});
    const verifier = new QuoteVerifier(fetcher);
    // Use a fixed date for 'now' to match Rust test (before nextUpdate in collateral)
    const fixedNow = Date.parse('2023-12-01T00:00:00Z');
    const result = await verifier.verify(quoteBytes, collateral, fixedNow);
    // Expected from Rust: status: 'ConfigurationAndSWHardeningNeeded', advisoryIds: ['INTEL-SA-00289', 'INTEL-SA-00615']
    try {
      expect(result.status).toBe('ConfigurationAndSWHardeningNeeded');
      expect(result.advisoryIds).toEqual(
        expect.arrayContaining(['INTEL-SA-00289', 'INTEL-SA-00615']),
      );
    } catch (e) {
      // Print the full report for manual inspection
      // eslint-disable-next-line no-console
      console.error('Verification result:', result);
      throw e;
    }
  });
});
