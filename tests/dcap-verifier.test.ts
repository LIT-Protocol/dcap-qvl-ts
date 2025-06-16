import { DcapVerifier } from '../src/index';
import { QuoteCollateralV3, QuoteVerificationError } from '../src/quote-types';
import { QuoteParser } from '../src/quote-parser';
import fs from 'fs';
import path from 'path';

describe('DcapVerifier Public API', () => {
  const sgxQuotePath = path.join(process.cwd(), 'dcap-qvl-rust/sample/sgx_quote');
  const sgxCollateralPath = path.join(
    process.cwd(),
    'dcap-qvl-rust/sample/sgx_quote_collateral.json',
  );
  let quoteBytes: Buffer;
  let collateral: QuoteCollateralV3;

  beforeAll(() => {
    quoteBytes = fs.readFileSync(sgxQuotePath);
    const rawCollateral = JSON.parse(fs.readFileSync(sgxCollateralPath, 'utf8'));
    collateral = {
      tcbInfoIssuerChain: rawCollateral.tcb_info_issuer_chain,
      tcbInfo: rawCollateral.tcb_info,
      tcbInfoSignature: Buffer.from(rawCollateral.tcb_info_signature, 'hex'),
      qeIdentityIssuerChain: rawCollateral.qe_identity_issuer_chain,
      qeIdentity: rawCollateral.qe_identity,
      qeIdentitySignature: Buffer.from(rawCollateral.qe_identity_signature, 'hex'),
    };
  });

  it('verifies a quote with provided collateral', async () => {
    const verifier = new DcapVerifier();
    const fixedNow = Date.parse('2023-12-01T00:00:00Z');
    const result = await verifier.verifyQuote(quoteBytes, collateral, fixedNow);
    expect(result.status).toBeDefined();
    expect(result.report).toBeDefined();
    expect(Array.isArray(result.advisoryIds)).toBe(true);
  });

  it('throws on malformed quote', async () => {
    const verifier = new DcapVerifier();
    const badQuote = Buffer.from([1, 2, 3, 4, 5]);
    await expect(verifier.verifyQuote(badQuote, collateral)).rejects.toThrow(
      QuoteVerificationError,
    );
    await expect(verifier.verifyQuote(badQuote, collateral)).rejects.toMatchObject({
      code: 'DecodeError',
    });
  });

  it('throws on missing FMSPC', async () => {
    const verifier = new DcapVerifier();
    const spy = jest.spyOn(QuoteParser, 'extractFMSPC').mockImplementation(() => {
      throw new QuoteVerificationError('MissingField', 'FMSPC not found');
    });
    await expect(verifier.verifyQuote(quoteBytes, undefined)).rejects.toThrow(
      QuoteVerificationError,
    );
    await expect(verifier.verifyQuote(quoteBytes, undefined)).rejects.toMatchObject({
      code: 'FieldMismatch',
    });
    spy.mockRestore();
  });

  it('throws on collateral fetch failure', async () => {
    const verifier = new DcapVerifier();
    // Mock extractFMSPC to return a valid value
    const spy = jest
      .spyOn(QuoteParser, 'extractFMSPC')
      .mockImplementation(() => Buffer.from('b0c06f000000', 'hex'));
    verifier['collateralFetcher'].fetchTcbInfo = async () => {
      throw new QuoteVerificationError('CertificateError', 'fetch failed');
    };
    await expect(verifier.verifyQuote(quoteBytes, undefined)).rejects.toThrow(
      QuoteVerificationError,
    );
    await expect(verifier.verifyQuote(quoteBytes, undefined)).rejects.toMatchObject({
      code: 'CertificateError',
    });
    spy.mockRestore();
  });

  it('parses a quote successfully', () => {
    const verifier = new DcapVerifier();
    const parsed = verifier.parseQuote(quoteBytes);
    expect(parsed.header).toBeDefined();
    expect(parsed.report).toBeDefined();
  });

  it('throws on parseQuote with bad input', () => {
    const verifier = new DcapVerifier();
    expect(() => verifier.parseQuote(Buffer.from([1, 2, 3]))).toThrow(QuoteVerificationError);
  });

  it('automatically fetches collateral (mocked)', async () => {
    const verifier = new DcapVerifier();
    // Mock extractFMSPC to return a valid value
    const spy = jest
      .spyOn(QuoteParser, 'extractFMSPC')
      .mockImplementation(() => Buffer.from('b0c06f000000', 'hex'));
    const mockTcbInfo = JSON.stringify({
      tcbInfo: {},
      signature: 'deadbeef',
      'TCB-Info-Issuer-Chain': 'chain',
    });
    const mockQeIdentity = JSON.stringify({
      enclaveIdentity: {},
      signature: 'deadbeef',
      'SGX-Enclave-Identity-Issuer-Chain': 'chain',
    });
    verifier['collateralFetcher'].fetchTcbInfo = async () => mockTcbInfo;
    verifier['collateralFetcher'].fetchQeIdentity = async () => mockQeIdentity;
    const origBufferFrom = Buffer.from;
    Buffer.from = ((value: unknown, encoding?: BufferEncoding) => {
      if (typeof value === 'string' && value === 'deadbeef' && encoding === 'hex') {
        return origBufferFrom([0xde, 0xad, 0xbe, 0xef]);
      }
      if (typeof value === 'string') {
        return origBufferFrom(value, encoding);
      }
      return origBufferFrom(value as ArrayLike<number>);
    }) as typeof Buffer.from;
    await expect(verifier.verifyQuote(quoteBytes, undefined)).rejects.toThrow(
      /Failed to assemble collateral: Cannot read properties of undefined/,
    );
    Buffer.from = origBufferFrom;
    spy.mockRestore();
  });

  it('throws on non-buffer/Uint8Array input to verifyQuote', async () => {
    const verifier = new DcapVerifier();
    // @ts-expect-error Testing input validation: should throw on non-buffer input
    await expect(verifier.verifyQuote('not a buffer', collateral)).rejects.toThrow(
      QuoteVerificationError,
    );
  });

  it('verifies a TDX quote with automatic collateral fetching', async () => {
    const tdxHexPath = path.join(process.cwd(), 'dcap-qvl-rust/sample/tdx-quote.hex');
    const hexString = fs.readFileSync(tdxHexPath, 'utf8').replace(/^0x/, '').replace(/\s+/g, '');
    const tdxQuoteBytes = Buffer.from(hexString, 'hex');
    const verifier = new DcapVerifier();
    const result = await verifier.verifyQuote(tdxQuoteBytes);
    expect(result.status).toBeDefined();
    expect(result.report).toBeDefined();
    expect(Array.isArray(result.advisoryIds)).toBe(true);
    expect(result.report.type).toBe('TD10');
  });
});
