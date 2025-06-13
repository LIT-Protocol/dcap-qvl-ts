import { Quote, Header, EnclaveReport, AuthData, AuthDataV3, TDReport10 } from './quote-types.js';
import { readUint16LE, readUint32LE, readBytes, validateBuffer } from './binary-utils';

const HEADER_BYTE_LEN = 48;
const ENCLAVE_REPORT_BYTE_LEN = 384;
const TD_REPORT10_BYTE_LEN = 584;
const AUTH_DATA_SIZE_BYTE_LEN = 4;
const ECDSA_SIGNATURE_BYTE_LEN = 64;
const ECDSA_PUBKEY_BYTE_LEN = 64;
const QE_REPORT_BYTE_LEN = 384;
const QE_REPORT_SIG_BYTE_LEN = 64;
const QE_AUTH_DATA_SIZE_BYTE_LEN = 2;
const QE_CERT_DATA_TYPE_BYTE_LEN = 2;
const QE_CERT_DATA_SIZE_BYTE_LEN = 4;
const TEE_TYPE_TDX = 0x81;

export class QuoteParser {
  /**
   * Parse a raw SGX or TDX quote from a Uint8Array buffer.
   * Detects version and TEE type, dispatches to the appropriate parser.
   */
  static parse(quoteBytes: Uint8Array): Quote {
    validateBuffer(quoteBytes, 0, HEADER_BYTE_LEN + AUTH_DATA_SIZE_BYTE_LEN);
    // Version is at offset 0, u16 LE
    const version = readUint16LE(quoteBytes, 0);
    const teeType = readUint32LE(quoteBytes, 4);
    if (version === 4 && teeType === TEE_TYPE_TDX) {
      return this.parseTDXQuoteV4(quoteBytes);
    }
    switch (version) {
      case 3:
        return this.parseV3Quote(quoteBytes);
      case 4:
        return this.parseV4Quote(quoteBytes);
      default:
        throw new Error(`Unsupported quote version: ${version}`);
    }
  }

  /**
   * Parse SGX quote version 3
   */
  private static parseV3Quote(quoteBytes: Uint8Array): Quote {
    let offset = 0;
    // Parse header
    const header: Header = {
      version: readUint16LE(quoteBytes, offset),
      attestationKeyType: readUint16LE(quoteBytes, offset + 2),
      teeType: readUint32LE(quoteBytes, offset + 4),
      qeSvn: readUint16LE(quoteBytes, offset + 8),
      pceSvn: readUint16LE(quoteBytes, offset + 10),
      qeVendorId: readBytes(quoteBytes, offset + 12, 16),
      userData: readBytes(quoteBytes, offset + 28, 20),
    };
    offset += HEADER_BYTE_LEN;

    // Parse EnclaveReport
    const enclaveReport: EnclaveReport = {
      cpuSvn: readBytes(quoteBytes, offset, 16),
      miscSelect: readUint32LE(quoteBytes, offset + 16),
      reserved1: readBytes(quoteBytes, offset + 20, 28),
      attributes: readBytes(quoteBytes, offset + 48, 16),
      mrEnclave: readBytes(quoteBytes, offset + 64, 32),
      reserved2: readBytes(quoteBytes, offset + 96, 32),
      mrSigner: readBytes(quoteBytes, offset + 128, 32),
      reserved3: readBytes(quoteBytes, offset + 160, 96),
      isvProdId: readUint16LE(quoteBytes, offset + 256),
      isvSvn: readUint16LE(quoteBytes, offset + 258),
      reserved4: readBytes(quoteBytes, offset + 260, 60),
      reportData: readBytes(quoteBytes, offset + 320, 64),
    };
    offset += ENCLAVE_REPORT_BYTE_LEN;

    // Parse AuthData size
    const authDataSize = readUint32LE(quoteBytes, offset);
    offset += AUTH_DATA_SIZE_BYTE_LEN;
    validateBuffer(quoteBytes, offset, authDataSize);
    let authOffset = offset;

    // Parse AuthDataV3
    const ecdsaSignature = readBytes(quoteBytes, authOffset, ECDSA_SIGNATURE_BYTE_LEN);
    authOffset += ECDSA_SIGNATURE_BYTE_LEN;
    const ecdsaAttestationKey = readBytes(quoteBytes, authOffset, ECDSA_PUBKEY_BYTE_LEN);
    authOffset += ECDSA_PUBKEY_BYTE_LEN;
    const qeReport = readBytes(quoteBytes, authOffset, QE_REPORT_BYTE_LEN);
    authOffset += QE_REPORT_BYTE_LEN;
    const qeReportSignature = readBytes(quoteBytes, authOffset, QE_REPORT_SIG_BYTE_LEN);
    authOffset += QE_REPORT_SIG_BYTE_LEN;
    // QE Auth Data (Data<u16>)
    const qeAuthDataLen = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_AUTH_DATA_SIZE_BYTE_LEN;
    const qeAuthData = readBytes(quoteBytes, authOffset, qeAuthDataLen);
    authOffset += qeAuthDataLen;
    // Certification Data
    const certType = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_TYPE_BYTE_LEN;
    const certDataLen = readUint32LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_SIZE_BYTE_LEN;
    const certData = readBytes(quoteBytes, authOffset, certDataLen);
    authOffset += certDataLen;

    const authDataV3: AuthDataV3 = {
      ecdsaSignature,
      ecdsaAttestationKey,
      qeReport,
      qeReportSignature,
      qeAuthData: { data: qeAuthData },
      certificationData: {
        certType,
        body: { data: certData },
      },
    };
    const authData: AuthData = { version: 3, data: authDataV3 };

    return {
      header,
      report: { type: 'SgxEnclave', report: enclaveReport },
      authData,
    };
  }

  /**
   * Parse TDX quote version 4 (TDReport10)
   */
  private static parseTDXQuoteV4(quoteBytes: Uint8Array): Quote {
    let offset = 0;
    // Parse header
    const header: Header = {
      version: readUint16LE(quoteBytes, offset),
      attestationKeyType: readUint16LE(quoteBytes, offset + 2),
      teeType: readUint32LE(quoteBytes, offset + 4),
      qeSvn: readUint16LE(quoteBytes, offset + 8),
      pceSvn: readUint16LE(quoteBytes, offset + 10),
      qeVendorId: readBytes(quoteBytes, offset + 12, 16),
      userData: readBytes(quoteBytes, offset + 28, 20),
    };
    offset += HEADER_BYTE_LEN;

    // Parse TDReport10
    const tdReport: TDReport10 = QuoteParser.parseTDReport10(quoteBytes, offset);
    offset += TD_REPORT10_BYTE_LEN;

    // Parse AuthData size
    const authDataSize = readUint32LE(quoteBytes, offset);
    offset += AUTH_DATA_SIZE_BYTE_LEN;
    validateBuffer(quoteBytes, offset, authDataSize);
    let authOffset = offset;

    // Parse AuthDataV3 (same as SGX)
    const ecdsaSignature = readBytes(quoteBytes, authOffset, ECDSA_SIGNATURE_BYTE_LEN);
    authOffset += ECDSA_SIGNATURE_BYTE_LEN;
    const ecdsaAttestationKey = readBytes(quoteBytes, authOffset, ECDSA_PUBKEY_BYTE_LEN);
    authOffset += ECDSA_PUBKEY_BYTE_LEN;
    const qeReport = readBytes(quoteBytes, authOffset, QE_REPORT_BYTE_LEN);
    authOffset += QE_REPORT_BYTE_LEN;
    const qeReportSignature = readBytes(quoteBytes, authOffset, QE_REPORT_SIG_BYTE_LEN);
    authOffset += QE_REPORT_SIG_BYTE_LEN;
    // QE Auth Data (Data<u16>)
    const qeAuthDataLen = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_AUTH_DATA_SIZE_BYTE_LEN;
    const qeAuthData = readBytes(quoteBytes, authOffset, qeAuthDataLen);
    authOffset += qeAuthDataLen;
    // Certification Data
    const certType = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_TYPE_BYTE_LEN;
    const certDataLen = readUint32LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_SIZE_BYTE_LEN;
    const certData = readBytes(quoteBytes, authOffset, certDataLen);
    authOffset += certDataLen;

    const authDataV3: AuthDataV3 = {
      ecdsaSignature,
      ecdsaAttestationKey,
      qeReport,
      qeReportSignature,
      qeAuthData: { data: qeAuthData },
      certificationData: {
        certType,
        body: { data: certData },
      },
    };
    const authData: AuthData = { version: 3, data: authDataV3 };

    return {
      header,
      report: { type: 'TD10', report: tdReport },
      authData,
    };
  }

  /**
   * Parse TDReport10 structure from buffer at given offset
   */
  private static parseTDReport10(buf: Uint8Array, offset: number): TDReport10 {
    return {
      teeTcbSvn: readBytes(buf, offset, 16),
      mrSeam: readBytes(buf, offset + 16, 48),
      mrSignerSeam: readBytes(buf, offset + 64, 48),
      seamAttributes: readBytes(buf, offset + 112, 8),
      tdAttributes: readBytes(buf, offset + 120, 8),
      xfam: readBytes(buf, offset + 128, 8),
      mrTd: readBytes(buf, offset + 136, 48),
      mrConfigId: readBytes(buf, offset + 184, 48),
      mrOwner: readBytes(buf, offset + 232, 48),
      mrOwnerConfig: readBytes(buf, offset + 280, 48),
      rtMr0: readBytes(buf, offset + 328, 48),
      rtMr1: readBytes(buf, offset + 376, 48),
      rtMr2: readBytes(buf, offset + 424, 48),
      rtMr3: readBytes(buf, offset + 472, 48),
      reportData: readBytes(buf, offset + 520, 64),
    };
  }

  /**
   * Parse SGX quote version 4 (same structure as v3 for now)
   */
  private static parseV4Quote(quoteBytes: Uint8Array): Quote {
    let offset = 0;
    // Parse header
    const header: Header = {
      version: readUint16LE(quoteBytes, offset),
      attestationKeyType: readUint16LE(quoteBytes, offset + 2),
      teeType: readUint32LE(quoteBytes, offset + 4),
      qeSvn: readUint16LE(quoteBytes, offset + 8),
      pceSvn: readUint16LE(quoteBytes, offset + 10),
      qeVendorId: readBytes(quoteBytes, offset + 12, 16),
      userData: readBytes(quoteBytes, offset + 28, 20),
    };
    offset += HEADER_BYTE_LEN;

    // Parse EnclaveReport
    const enclaveReport: EnclaveReport = {
      cpuSvn: readBytes(quoteBytes, offset, 16),
      miscSelect: readUint32LE(quoteBytes, offset + 16),
      reserved1: readBytes(quoteBytes, offset + 20, 28),
      attributes: readBytes(quoteBytes, offset + 48, 16),
      mrEnclave: readBytes(quoteBytes, offset + 64, 32),
      reserved2: readBytes(quoteBytes, offset + 96, 32),
      mrSigner: readBytes(quoteBytes, offset + 128, 32),
      reserved3: readBytes(quoteBytes, offset + 160, 96),
      isvProdId: readUint16LE(quoteBytes, offset + 256),
      isvSvn: readUint16LE(quoteBytes, offset + 258),
      reserved4: readBytes(quoteBytes, offset + 260, 60),
      reportData: readBytes(quoteBytes, offset + 320, 64),
    };
    offset += ENCLAVE_REPORT_BYTE_LEN;

    // Parse AuthData size
    const authDataSize = readUint32LE(quoteBytes, offset);
    offset += AUTH_DATA_SIZE_BYTE_LEN;
    validateBuffer(quoteBytes, offset, authDataSize);
    let authOffset = offset;

    // Parse AuthDataV3 (same as v3)
    const ecdsaSignature = readBytes(quoteBytes, authOffset, ECDSA_SIGNATURE_BYTE_LEN);
    authOffset += ECDSA_SIGNATURE_BYTE_LEN;
    const ecdsaAttestationKey = readBytes(quoteBytes, authOffset, ECDSA_PUBKEY_BYTE_LEN);
    authOffset += ECDSA_PUBKEY_BYTE_LEN;
    const qeReport = readBytes(quoteBytes, authOffset, QE_REPORT_BYTE_LEN);
    authOffset += QE_REPORT_BYTE_LEN;
    const qeReportSignature = readBytes(quoteBytes, authOffset, QE_REPORT_SIG_BYTE_LEN);
    authOffset += QE_REPORT_SIG_BYTE_LEN;
    // QE Auth Data (Data<u16>)
    const qeAuthDataLen = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_AUTH_DATA_SIZE_BYTE_LEN;
    const qeAuthData = readBytes(quoteBytes, authOffset, qeAuthDataLen);
    authOffset += qeAuthDataLen;
    // Certification Data
    const certType = readUint16LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_TYPE_BYTE_LEN;
    const certDataLen = readUint32LE(quoteBytes, authOffset);
    authOffset += QE_CERT_DATA_SIZE_BYTE_LEN;
    const certData = readBytes(quoteBytes, authOffset, certDataLen);
    authOffset += certDataLen;

    const authDataV3: AuthDataV3 = {
      ecdsaSignature,
      ecdsaAttestationKey,
      qeReport,
      qeReportSignature,
      qeAuthData: { data: qeAuthData },
      certificationData: {
        certType,
        body: { data: certData },
      },
    };
    const authData: AuthData = { version: 3, data: authDataV3 };

    return {
      header,
      report: { type: 'SgxEnclave', report: enclaveReport },
      authData,
    };
  }

  /**
   * Extract the reportData field from a parsed Quote (SGX or TDX)
   */
  static extractReportData(quote: Quote): Uint8Array | undefined {
    if (quote.report.type === 'SgxEnclave') {
      return quote.report.report.reportData;
    } else if (quote.report.type === 'TD10') {
      return quote.report.report.reportData;
    } else if (quote.report.type === 'TD15') {
      return quote.report.report.base.reportData;
    }
    return undefined;
  }

  /**
   * Extract the FMSPC from a parsed Quote (requires certificate parsing)
   * Not implemented: would require parsing the certificate chain in authData
   */
  static extractFMSPC(): Uint8Array {
    throw new Error('extractFMSPC not implemented: requires certificate parsing');
  }

  /**
   * Extract the TCB Info from a parsed Quote (requires certificate/collateral parsing)
   * Not implemented: would require parsing the collateral
   */
  static extractTCBInfo(): unknown {
    throw new Error('extractTCBInfo not implemented: requires collateral parsing');
  }

  /**
   * Extract the ECDSA signature from a parsed Quote's authData
   */
  static extractSignature(quote: Quote): Uint8Array | undefined {
    if (quote.authData.version === 3) {
      return quote.authData.data.ecdsaSignature;
    } else if (quote.authData.version === 4) {
      return quote.authData.data.ecdsaSignature;
    }
    return undefined;
  }
}
