import { Quote, Header, EnclaveReport, AuthData, AuthDataV3, TDReport10 } from './quote-types.js';
import { readUint16LE, readUint32LE, readBytes, validateBuffer } from './binary-utils';
import { X509Certificate } from '@peculiar/x509';

const HEADER_BYTE_LEN = 48;
const ENCLAVE_REPORT_BYTE_LEN = 384;
const AUTH_DATA_SIZE_BYTE_LEN = 4;
const ECDSA_SIGNATURE_BYTE_LEN = 64;
const ECDSA_PUBKEY_BYTE_LEN = 64;
const QE_REPORT_BYTE_LEN = 384;
const QE_REPORT_SIG_BYTE_LEN = 64;
const QE_AUTH_DATA_SIZE_BYTE_LEN = 2;
const QE_CERT_DATA_TYPE_BYTE_LEN = 2;
const QE_CERT_DATA_SIZE_BYTE_LEN = 4;
const TEE_TYPE_TDX = 0x81;
const TD_REPORT10_BYTE_LEN = 584;

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
    console.log(
      '[TDX DEBUG] Offset before AuthData length:',
      offset,
      'Buffer length:',
      quoteBytes.length,
    );
    console.log(
      '[TDX DEBUG] Bytes at AuthData length offset:',
      quoteBytes.slice(offset - 4, offset + 8),
    );
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
    // Parse header
    const header: Header = {
      version: readUint16LE(quoteBytes, 0),
      attestationKeyType: readUint16LE(quoteBytes, 2),
      teeType: readUint32LE(quoteBytes, 4),
      qeSvn: readUint16LE(quoteBytes, 8),
      pceSvn: readUint16LE(quoteBytes, 10),
      qeVendorId: readBytes(quoteBytes, 12, 16),
      userData: readBytes(quoteBytes, 28, 20),
    };
    // TDReport10 always follows header for TDX v4
    const tdReportOffset = HEADER_BYTE_LEN;
    const tdReport: TDReport10 = QuoteParser.parseTDReport10(quoteBytes, tdReportOffset);
    // AuthData length is immediately after TDReport10
    const authDataLenOffset = HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN;
    const authDataSize = readUint32LE(quoteBytes, authDataLenOffset);
    const authDataOffset = authDataLenOffset + 4;
    validateBuffer(quoteBytes, authDataOffset, authDataSize);
    const authDataBytes = quoteBytes.slice(authDataOffset, authDataOffset + authDataSize);
    let authOffset = 0;
    // Parse AuthDataV4 (nested structure)
    const ecdsaSignature = readBytes(authDataBytes, authOffset, ECDSA_SIGNATURE_BYTE_LEN);
    authOffset += ECDSA_SIGNATURE_BYTE_LEN;
    const ecdsaAttestationKey = readBytes(authDataBytes, authOffset, ECDSA_PUBKEY_BYTE_LEN);
    authOffset += ECDSA_PUBKEY_BYTE_LEN;
    // CertificationData (outer)
    const certType = readUint16LE(authDataBytes, authOffset);
    authOffset += QE_CERT_DATA_TYPE_BYTE_LEN;
    const certBodyLen = readUint32LE(authDataBytes, authOffset);
    authOffset += QE_CERT_DATA_SIZE_BYTE_LEN;
    const certBody = readBytes(authDataBytes, authOffset, certBodyLen);
    authOffset += certBodyLen;
    // Parse QEReportCertificationData from certBody
    let certBodyOffset = 0;
    const qeReport = readBytes(certBody, certBodyOffset, QE_REPORT_BYTE_LEN);
    certBodyOffset += QE_REPORT_BYTE_LEN;
    const qeReportSignature = readBytes(certBody, certBodyOffset, QE_REPORT_SIG_BYTE_LEN);
    certBodyOffset += QE_REPORT_SIG_BYTE_LEN;
    // QE Auth Data (Data<u16>)
    const qeAuthDataLen = readUint16LE(certBody, certBodyOffset);
    certBodyOffset += QE_AUTH_DATA_SIZE_BYTE_LEN;
    const qeAuthData = readBytes(certBody, certBodyOffset, qeAuthDataLen);
    certBodyOffset += qeAuthDataLen;
    // Certification Data (nested)
    const certType2 = readUint16LE(certBody, certBodyOffset);
    certBodyOffset += QE_CERT_DATA_TYPE_BYTE_LEN;
    const certDataLen2 = readUint32LE(certBody, certBodyOffset);
    certBodyOffset += QE_CERT_DATA_SIZE_BYTE_LEN;
    const certData2 = readBytes(certBody, certBodyOffset, certDataLen2);
    certBodyOffset += certDataLen2;
    // Compose nested CertificationData
    const nestedCertificationData = {
      certType: certType2,
      body: { data: certData2 },
    };
    // Compose QEReportCertificationData
    const qeReportData = {
      qeReport,
      qeReportSignature,
      qeAuthData: { data: qeAuthData },
      certificationData: nestedCertificationData,
    };
    // Compose outer CertificationData
    const certificationData = {
      certType,
      body: { data: certBody },
    };
    // Compose AuthDataV4
    const authDataV4 = {
      ecdsaSignature,
      ecdsaAttestationKey,
      certificationData,
      qeReportData,
    };
    const authData: AuthData = { version: 4, data: authDataV4 };
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
    console.log(
      '[TDX DEBUG] Offset before AuthData length:',
      offset,
      'Buffer length:',
      quoteBytes.length,
    );
    console.log(
      '[TDX DEBUG] Bytes at AuthData length offset:',
      quoteBytes.slice(offset - 4, offset + 8),
    );
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
   */
  static extractFMSPC(quote: Quote): Uint8Array {
    // Get the certificate chain from the quote's authData
    let certChainPem: string | undefined;
    if (quote.authData.version === 3) {
      certChainPem = Buffer.from(quote.authData.data.certificationData.body.data).toString('utf8');
    } else if (quote.authData.version === 4) {
      certChainPem = Buffer.from(
        quote.authData.data.qeReportData.certificationData.body.data,
      ).toString('utf8');
    } else {
      throw new Error('Unsupported quote version for FMSPC extraction');
    }
    // Parse the first certificate in the chain
    const pattern = /-+BEGIN CERTIFICATE-+[\s\S]*?-+END CERTIFICATE-+/g;
    const matches = (certChainPem || '').match(pattern) || [];
    if (matches.length === 0) {
      throw new Error('No certificates found in quote');
    }
    const firstCertPem = matches[0]!;
    // Use @peculiar/x509 to parse the certificate
    const cert = new X509Certificate(firstCertPem);
    const FMSPC_OID = '1.2.840.113741.1.13.1.4';
    // Debug: print all extension OIDs in the first certificate
    console.log(
      '[FMSPC DEBUG] All extension OIDs in first cert:',
      cert.extensions.map((e) => e.type),
    );
    let fmspcValue: Uint8Array | undefined;
    for (const ext of cert.extensions) {
      if (ext.type === FMSPC_OID) {
        // ext.value is an ArrayBuffer
        const value = new Uint8Array(ext.value);
        fmspcValue = value.slice(0, 6);
        console.log('[FMSPC DEBUG] FMSPC extension value:', Buffer.from(value).toString('hex'));
        break;
      }
    }
    if (!fmspcValue || fmspcValue.length !== 6) {
      throw new Error('FMSPC not found or invalid length');
    }
    return fmspcValue;
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
