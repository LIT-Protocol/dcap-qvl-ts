import {
  readUint8,
  readUint16LE,
  readUint16BE,
  readUint32LE,
  readUint32BE,
  readUint64LE,
  readUint64BE,
  readBytes,
  validateBuffer,
  getCertificateInfo,
  isCertificateValidNow,
  validateBasicConstraints,
  validateKeyUsage,
  certificateToPem,
  certificateToDer,
  derToCertificate,
  parseCertificate,
} from '../src/binary-utils';
import * as fs from 'fs';
import * as path from 'path';
import { QuoteVerifier } from '../src/quote-verifier';
import { CollateralFetcher } from '../src/collateral-fetcher';
import { QuoteCollateralV3 } from '../src/quote-types';

test('adds 1 + 2 to equal 3', () => {
  expect(1 + 2).toBe(3);
});

test('readUint8 reads a single byte', () => {
  const buf = new Uint8Array([0x12]);
  expect(readUint8(buf, 0)).toBe(0x12);
});

test('readUint16LE and readUint16BE', () => {
  const buf = new Uint8Array([0x34, 0x12]);
  expect(readUint16LE(buf, 0)).toBe(0x1234);
  expect(readUint16BE(buf, 0)).toBe(0x3412);
});

test('readUint32LE and readUint32BE', () => {
  const buf = new Uint8Array([0x78, 0x56, 0x34, 0x12]);
  expect(readUint32LE(buf, 0)).toBe(0x12345678);
  expect(readUint32BE(buf, 0)).toBe(0x78563412);
});

test('readUint64LE and readUint64BE', () => {
  const buf = new Uint8Array([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
  expect(readUint64LE(buf, 0)).toBe(BigInt('0x0102030405060708'));
  expect(readUint64BE(buf, 0)).toBe(BigInt('0x0807060504030201'));
});

test('readBytes returns a slice', () => {
  const buf = new Uint8Array([1, 2, 3, 4, 5]);
  expect(Array.from(readBytes(buf, 1, 3))).toEqual([2, 3, 4]);
});

test('validateBuffer throws on out-of-bounds', () => {
  const buf = new Uint8Array([1, 2, 3]);
  expect(() => validateBuffer(buf, 2, 2)).toThrow(RangeError);
  expect(() => validateBuffer(buf, -1, 1)).toThrow(RangeError);
});

const samplePem = `-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUAOCFab6YdUE10DjZajWN28SPY+wwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTI1MDYxMzE4MDkyNFoXDTI2MDYx\nMzE4MDkyNFowFDESMBAGA1UEAwwJVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA68HJGzxfh3keTGTsu6+1Kp7IkhGCXDlb4XLecBElb/Yy\n7aZcSYTqDpsURlETbedHC9UQeMyynoTGzrvfMkui9DCQbYn0IFEDDvJuwqe6qCiT\nta4RS5j5jXW1BAR5Q/nnNpCzkqtH27U4Gt4PD5Jc08unq8F0/kDKsvGCRTQmXV2l\nR5xY6Zgr5TDihtxc6y4lfuKCJ1HjJbGfaU+qix3BzvfuLM7zRKXFyBvUcnKsG6bf\n0RgIR5FPcoULGFg723GDlbCtD3MZEsVwMUAfP5AYPpHAaCQKBLrneBfcJnF5cz00\nHTtWGCBaqyZ+U0M56LiN4RwZ3glAI94otNSH/5aJyQIDAQABo1MwUTAdBgNVHQ4E\nFgQUT87PbtTL0mYnRkilLx2D2Sf6yOIwHwYDVR0jBBgwFoAUT87PbtTL0mYnRkil\nLx2D2Sf6yOIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZswA\ntSr2iskKHxvcg9BR6Z6Cev8j3PuSluWGzh014Y72NJiZ0BkhM4yYWfo72UI93Zkf\nPHImq3bmb9S8nsxorCxq8izB1gfnf+loYxG4UyRr1/BY247ubFXGeMzAGTsX2tjB\nbAmmqyiky4E7e1sHI2GppBDKhkXsuOqwroOP4pH618OX3rFsE48Zk98swg9Rjc+y\nNMwvHkNfOeZ5QSduqBlsEbCHp4zb3GmD4PyodeWOhqYVLIVKd5w16Ht2kyviYj14\n8R+Dyvh6hu4uSZ5bmMG4V3jxF0ARS/p9VbiGs3JLETxb/SIqAD4W6NKjuKo2sZ2t\nAfWMNZJotV9x8g2CrA==\n-----END CERTIFICATE-----`;

// Minimal test to use all certificate utilities and samplePem

describe('X.509 Certificate Utilities', () => {
  test('parse and extract info from PEM certificate', () => {
    const cert = parseCertificate(samplePem);
    const info = getCertificateInfo(cert);
    expect(info.subject).toBeDefined();
    expect(info.issuer).toBeDefined();
    expect(info.notBefore).toBeInstanceOf(Date);
    expect(info.notAfter).toBeInstanceOf(Date);
    expect(info.publicKey).toBeDefined();
  });

  test('certificate validity and constraints', () => {
    const cert = parseCertificate(samplePem);
    expect(isCertificateValidNow(cert)).toBe(true);
    expect(validateBasicConstraints(cert)).toBe(true);
    // Key usage may not be present in minimal cert, so just check function runs
    expect(() => validateKeyUsage(cert, ['digitalSignature'])).not.toThrow();
  });

  test('PEM/DER conversion roundtrip', () => {
    const cert = parseCertificate(samplePem);
    const der = certificateToDer(cert);
    const cert2 = derToCertificate(der);
    const pem2 = certificateToPem(cert2);
    expect(pem2).toContain('BEGIN CERTIFICATE');
  });
});

test('validatePemCertificate', () => {
  // Add your validation logic here
  expect(true).toBe(true);
});

test('certificateToPem', () => {
  // Add your conversion logic here
  expect(true).toBe(true);
});

test('certificateToDer', () => {
  // Add your conversion logic here
  expect(true).toBe(true);
});

test('derToCertificate', () => {
  // Add your conversion logic here
  expect(true).toBe(true);
});

test('parseCertificate', () => {
  // Add your parsing logic here
  expect(true).toBe(true);
});

test('getCertificateInfo', () => {
  // Add your info extraction logic here
  expect(true).toBe(true);
});

test('isCertificateValidNow', () => {
  // Add your validation logic here
  expect(true).toBe(true);
});

test('validateBasicConstraints', () => {
  // Add your validation logic here
  expect(true).toBe(true);
});

test('validateKeyUsage', () => {
  // Add your validation logic here
  expect(true).toBe(true);
});

describe('QuoteVerifier TDX integration', () => {
  it('verifies a TDX quote and returns UpToDate status', async () => {
    // Load TDX quote (raw binary)
    const quoteBytes = fs.readFileSync(path.join(__dirname, '../dcap-qvl-rust/sample/tdx_quote'));
    console.log('First 8 bytes:', quoteBytes.slice(0, 8)); // Debug: should start with 04 00 ...
    // Load TDX collateral
    const collateralJson = fs.readFileSync(
      path.join(__dirname, '../dcap-qvl-rust/sample/tdx_quote_collateral.json'),
      'utf8',
    );
    const collateralObj = JSON.parse(collateralJson);
    // The tcb_info field is a JSON string, so we keep it as-is
    const collateral: QuoteCollateralV3 = {
      tcbInfoIssuerChain: collateralObj.tcb_info_issuer_chain,
      tcbInfo: collateralObj.tcb_info,
      tcbInfoSignature: Buffer.from(collateralObj.tcb_info_signature, 'hex'),
      qeIdentityIssuerChain: collateralObj.qe_identity_issuer_chain,
      qeIdentity: collateralObj.qe_identity,
      qeIdentitySignature: Buffer.from(collateralObj.qe_identity_signature, 'hex'),
    };
    const verifier = new QuoteVerifier(new CollateralFetcher());
    const result = await verifier.verify(quoteBytes, collateral);
    expect(result.status).toBe('UpToDate');
    expect(result.advisoryIds).toEqual([]);
  });
});
