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
  parseCertificate,
  parseCertificateChain,
} from '../src/binary-utils';
import * as fs from 'fs';
import * as path from 'path';
import { QuoteVerifier } from '../src/quote-verifier';
import { CollateralFetcher } from '../src/collateral-fetcher';
import { QuoteCollateralV3 } from '../src/quote-types';

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

describe('X.509 Certificate Utilities', () => {
  const certPem = fs.readFileSync(path.join(__dirname, 'ecdsa-cert.pem'), 'utf8');

  test('parse ECDSA PEM certificate and extract public key', () => {
    expect(() => parseCertificate(certPem)).not.toThrow();
    const cert = parseCertificate(certPem);
    expect(cert).toHaveProperty('publicKey');
    expect(cert.publicKey.length).toBe(65);
    expect(cert.publicKey[0]).toBe(0x04);
  });

  test('parseCertificateChain extracts all public keys', () => {
    // Use the same cert twice to simulate a chain
    const pemChain = certPem + '\n' + certPem;
    const certs = parseCertificateChain(pemChain);
    expect(Array.isArray(certs)).toBe(true);
    for (const cert of certs) {
      expect(cert).toHaveProperty('publicKey');
      expect(cert.publicKey.length).toBe(65);
      expect(cert.publicKey[0]).toBe(0x04);
    }
  });
});

describe('QuoteVerifier SGX integration', () => {
  it.skip('verifies an SGX quote and returns UpToDate status', async () => {
    // This is a sample SGX quote. We can add more tests with different quotes.
    const quoteBytes = fs.readFileSync(path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote'));
    const collateralJson = fs.readFileSync(
      path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote_collateral.json'),
      'utf-8',
    );
    const collateral: QuoteCollateralV3 = JSON.parse(collateralJson);
    const verifier = new QuoteVerifier(new CollateralFetcher());
    const result = await verifier.verify(quoteBytes, collateral);
    expect(result.status).toBe('ConfigurationAndSWHardeningNeeded');
    expect(result.advisoryIds).toEqual(['INTEL-SA-00289', 'INTEL-SA-00615']);
  });
});

describe('QuoteVerifier TDX integration', () => {
  it('verifies a TDX quote and returns UpToDate status', async () => {
    // This is a sample TDX quote. We can add more tests with different quotes.
    const quoteBytes = fs.readFileSync(path.join(__dirname, '../dcap-qvl-rust/sample/tdx_quote'));
    const collateralJson = fs.readFileSync(
      path.join(__dirname, '../dcap-qvl-rust/sample/tdx_quote_collateral.json'),
      'utf-8',
    );
    const collateralObj = JSON.parse(collateralJson);
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
