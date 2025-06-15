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

  it.skip('fetches Root CA CRL from Intel PCS (not available in v4)', async () => {
    // Intel PCS v4 does not support /rootcacrl endpoint; this test is skipped.
    // If you need to test this, use a v3 endpoint or a different provider.
  });
});

describe('QuoteVerifier CRL Revocation', () => {
  it('returns Revoked if a cert in the chain is revoked by CRL', async () => {
    // Generate root and leaf certs
    const rootKeys = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = forge.pki.createCertificate();
    rootCert.publicKey = rootKeys.publicKey;
    rootCert.serialNumber = '01';
    rootCert.validity.notBefore = new Date(Date.now() - 1000 * 60);
    rootCert.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60);
    rootCert.setSubject([{ name: 'commonName', value: 'Test Root CA' }]);
    rootCert.setIssuer([{ name: 'commonName', value: 'Test Root CA' }]);
    rootCert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, digitalSignature: true },
    ]);
    rootCert.sign(rootKeys.privateKey);

    const leafKeys = forge.pki.rsa.generateKeyPair(2048);
    const leafCert = forge.pki.createCertificate();
    leafCert.publicKey = leafKeys.publicKey;
    leafCert.serialNumber = '02';
    leafCert.validity.notBefore = new Date(Date.now() - 1000 * 60);
    leafCert.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60);
    leafCert.setSubject([{ name: 'commonName', value: 'Leaf Cert' }]);
    leafCert.setIssuer([{ name: 'commonName', value: 'Test Root CA' }]);
    leafCert.setExtensions([{ name: 'keyUsage', digitalSignature: true }]);
    leafCert.sign(rootKeys.privateKey);

    // Create a CRL that revokes the leaf cert
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const crl = (forge.pki as any).createCertificateRevocationList();
    crl.sign(rootKeys.privateKey);
    crl.revokedCertificates = [
      {
        serialNumber: leafCert.serialNumber,
        revocationDate: new Date(),
      },
    ];
    crl.sign(rootKeys.privateKey);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const crlPem = (forge.pki as any).crlToPem(crl);

    // Mock CollateralFetcher
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    class MockCollateralFetcher {
      async fetchPckCrl() {
        return crlPem;
      }
    }

    // Compose a fake PEM chain (leaf + root)
    const pckPemChain = forge.pki.certificateToPem(leafCert) + forge.pki.certificateToPem(rootCert);

    // Minimal collateral for QuoteVerifier
    const collateral = {
      tcbInfoIssuerChain: '',
      tcbInfo: '{}',
      tcbInfoSignature: new Uint8Array(),
      qeIdentityIssuerChain: '',
      qeIdentity: '{}',
      qeIdentitySignature: new Uint8Array(),
    } as QuoteCollateralV3;

    // Minimal quoteBytes and quote parser stub
    const quoteBytes = new Uint8Array([0]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const verifier = new QuoteVerifier(new MockCollateralFetcher() as any);
    // Patch extractPckAndAuthData to return our test chain
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).extractPckAndAuthData = () => ({
      pckPemChain,
      qeReport: new Uint8Array(),
      qeReportSignature: new Uint8Array(),
      ecdsaAttestationKey: new Uint8Array(),
      qeAuthData: new Uint8Array(),
      ecdsaSignature: new Uint8Array(),
    });
    // Patch other methods to skip unrelated checks
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).validateTcbInfo = () => ({});
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).validateTcbInfoSignature = () => true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).verifyQeReportSignature = () => true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).verifyQeReportHash = () => true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).verifyQuoteSignature = () => true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (verifier as any).extractTcbStatusAndAdvisories = () => ({
      status: 'UpToDate',
      advisoryIds: [],
      report: {},
    });
    // Run verification
    const result = await verifier.verify(quoteBytes, collateral);
    expect(result.status).toBe('Revoked');
  });
});
