import { QuoteParser } from '../src/quote-parser';
import { Quote } from '../src/quote-types';

// Example valid SGX v3 quote (structurally valid, not cryptographically valid)
const headerSize = 48;
const enclaveReportSize = 384;
const tdReport10Size = 584;
const authDataSize = 584; // Minimum required for all fields
const authDataSizeBytes = [
  authDataSize & 0xff,
  (authDataSize >> 8) & 0xff,
  (authDataSize >> 16) & 0xff,
  (authDataSize >> 24) & 0xff,
];
const validV3Quote = new Uint8Array([
  0x03,
  0x00, // version = 3 (u16 LE)
  0x00,
  0x00, // attestationKeyType
  0x00,
  0x00,
  0x00,
  0x00, // teeType
  // ... rest of header (48 bytes total)
  ...new Array(headerSize - 8).fill(0),
  // EnclaveReport (384 bytes)
  ...new Array(enclaveReportSize).fill(0),
  // AuthData size (4 bytes, little endian)
  ...authDataSizeBytes,
  // AuthData (584 bytes)
  // ECDSA signature (64)
  ...new Array(64).fill(0),
  // ECDSA attestation key (64)
  ...new Array(64).fill(0),
  // QE report (384)
  ...new Array(384).fill(0),
  // QE report signature (64)
  ...new Array(64).fill(0),
  // QE auth data length (2, set to 0)
  0x00,
  0x00,
  // QE auth data (0)
  // Certification data type (2)
  0x00,
  0x00,
  // Certification data length (4, set to 0)
  0x00,
  0x00,
  0x00,
  0x00,
  // Certification data (0)
]);

// Example valid SGX v4 quote (identical to v3, but version = 4)
const validV4Quote = new Uint8Array(validV3Quote);
validV4Quote[0] = 0x04; // version = 4
validV4Quote[1] = 0x00;

// Example valid TDX v4 quote (version = 4, teeType = 0x81)
const TEE_TYPE_TDX = 0x81;
// Build a minimal, structurally valid AuthData for TDX v4
const ecdsaSignature = new Array(64).fill(0);
const ecdsaAttestationKey = new Array(64).fill(0);
const certType = [0x00, 0x00];
// certBody (nested):
const qeReport = new Array(384).fill(0);
const qeReportSignature = new Array(64).fill(0);
const qeAuthDataLen = [0x00, 0x00]; // 0
const certType2 = [0x00, 0x00];
const certDataLen2 = [0x00, 0x00, 0x00, 0x00]; // 0
const certData2: number[] = [];
// certBody = qeReport + qeReportSignature + qeAuthDataLen + certType2 + certDataLen2 + certData2
const certBody = [
  ...qeReport,
  ...qeReportSignature,
  ...qeAuthDataLen,
  ...certType2,
  ...certDataLen2,
  ...certData2,
];
const certBodyLen = [
  certBody.length & 0xff,
  (certBody.length >> 8) & 0xff,
  (certBody.length >> 16) & 0xff,
  (certBody.length >> 24) & 0xff,
];
// AuthData = ecdsaSignature + ecdsaAttestationKey + certType + certBodyLen + certBody
const tdxAuthData = [
  ...ecdsaSignature,
  ...ecdsaAttestationKey,
  ...certType,
  ...certBodyLen,
  ...certBody,
];
const tdxAuthDataSize = tdxAuthData.length;
const tdxAuthDataSizeBytes = [
  tdxAuthDataSize & 0xff,
  (tdxAuthDataSize >> 8) & 0xff,
  (tdxAuthDataSize >> 16) & 0xff,
  (tdxAuthDataSize >> 24) & 0xff,
];
const validTDXv4Quote = new Uint8Array([
  // Header (48 bytes)
  0x04,
  0x00, // version = 4 (u16 LE)
  0x00,
  0x00, // attestationKeyType
  TEE_TYPE_TDX,
  0x00,
  0x00,
  0x00, // teeType = 0x81 (u32 LE)
  ...new Array(headerSize - 8).fill(0),
  // TDReport10 (584 bytes)
  ...new Array(tdReport10Size).fill(0),
  // AuthData size (4 bytes, little endian)
  ...tdxAuthDataSizeBytes,
  // AuthData (structurally valid)
  ...tdxAuthData,
]);

// Example invalid quote (too short)
const invalidQuote = new Uint8Array([0x03, 0x00, 0x00]);

describe('QuoteParser', () => {
  it('parses a valid SGX v3 quote', () => {
    expect(() => {
      const quote: Quote = QuoteParser.parse(validV3Quote);
      expect(quote.header.version).toBe(3);
    }).not.toThrow();
  });

  it('parses a valid SGX v4 quote', () => {
    expect(() => {
      const quote: Quote = QuoteParser.parse(validV4Quote);
      expect(quote.header.version).toBe(4);
    }).not.toThrow();
  });

  it('parses a valid TDX v4 quote', () => {
    expect(() => {
      const quote: Quote = QuoteParser.parse(validTDXv4Quote);
      expect(quote.header.version).toBe(4);
      expect(quote.header.teeType).toBe(TEE_TYPE_TDX);
      expect(quote.report.type).toBe('TD10');
    }).not.toThrow();
  });

  it('throws on invalid (too short) quote', () => {
    expect(() => {
      QuoteParser.parse(invalidQuote);
    }).toThrow(/buffer/i);
  });

  it('throws on unsupported version', () => {
    const unsupported = new Uint8Array(validV3Quote);
    unsupported[0] = 0x09; // version = 9
    expect(() => {
      QuoteParser.parse(unsupported);
    }).toThrow(/unsupported/i);
  });

  // Add more tests for TDX, v4, malformed data, etc. as needed
});
