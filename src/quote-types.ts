// TypeScript interfaces for SGX/TDX quote structures, ported from dcap-qvl Rust library
// See: dcap-qvl-rust/src/quote.rs

/** Quote header structure */
export interface Header {
  version: number; // u16
  attestationKeyType: number; // u16
  teeType: number; // u32
  qeSvn: number; // u16
  pceSvn: number; // u16
  qeVendorId: Uint8Array; // [u8; 16]
  userData: Uint8Array; // [u8; 20]
}

/** Quote body structure (for version 5+) */
export interface Body {
  bodyType: number; // u16
  size: number; // u32
}

/** SGX Enclave Report structure */
export interface EnclaveReport {
  cpuSvn: Uint8Array; // [u8; 16]
  miscSelect: number; // u32
  reserved1: Uint8Array; // [u8; 28]
  attributes: Uint8Array; // [u8; 16]
  mrEnclave: Uint8Array; // [u8; 32]
  reserved2: Uint8Array; // [u8; 32]
  mrSigner: Uint8Array; // [u8; 32]
  reserved3: Uint8Array; // [u8; 96]
  isvProdId: number; // u16
  isvSvn: number; // u16
  reserved4: Uint8Array; // [u8; 60]
  reportData: Uint8Array; // [u8; 64]
}

/** TDX TDReport10 structure */
export interface TDReport10 {
  teeTcbSvn: Uint8Array; // [u8; 16]
  mrSeam: Uint8Array; // [u8; 48]
  mrSignerSeam: Uint8Array; // [u8; 48]
  seamAttributes: Uint8Array; // [u8; 8]
  tdAttributes: Uint8Array; // [u8; 8]
  xfam: Uint8Array; // [u8; 8]
  mrTd: Uint8Array; // [u8; 48]
  mrConfigId: Uint8Array; // [u8; 48]
  mrOwner: Uint8Array; // [u8; 48]
  mrOwnerConfig: Uint8Array; // [u8; 48]
  rtMr0: Uint8Array; // [u8; 48]
  rtMr1: Uint8Array; // [u8; 48]
  rtMr2: Uint8Array; // [u8; 48]
  rtMr3: Uint8Array; // [u8; 48]
  reportData: Uint8Array; // [u8; 64]
}

/** TDX TDReport15 structure (extends TDReport10) */
export interface TDReport15 {
  base: TDReport10;
  teeTcbSvn2: Uint8Array; // [u8; 16]
  mrServiceTd: Uint8Array; // [u8; 48]
}

/** Generic data wrapper for certification data */
export interface Data {
  data: Uint8Array;
}

/** CertificationData structure */
export interface CertificationData {
  certType: number; // u16
  body: Data; // Data<u32> in Rust
}

/** QEReportCertificationData structure */
export interface QEReportCertificationData {
  qeReport: Uint8Array; // [u8; ENCLAVE_REPORT_BYTE_LEN]
  qeReportSignature: Uint8Array; // [u8; QE_REPORT_SIG_BYTE_LEN]
  qeAuthData: Data; // Data<u16> in Rust
  certificationData: CertificationData;
}

/** AuthDataV3 structure */
export interface AuthDataV3 {
  ecdsaSignature: Uint8Array; // [u8; ECDSA_SIGNATURE_BYTE_LEN]
  ecdsaAttestationKey: Uint8Array; // [u8; ECDSA_PUBKEY_BYTE_LEN]
  qeReport: Uint8Array; // [u8; ENCLAVE_REPORT_BYTE_LEN]
  qeReportSignature: Uint8Array; // [u8; QE_REPORT_SIG_BYTE_LEN]
  qeAuthData: Data; // Data<u16> in Rust
  certificationData: CertificationData;
}

/** AuthDataV4 structure */
export interface AuthDataV4 {
  ecdsaSignature: Uint8Array; // [u8; ECDSA_SIGNATURE_BYTE_LEN]
  ecdsaAttestationKey: Uint8Array; // [u8; ECDSA_PUBKEY_BYTE_LEN]
  certificationData: CertificationData;
  qeReportData: QEReportCertificationData;
}

/** AuthData union type */
export type AuthData = { version: 3; data: AuthDataV3 } | { version: 4; data: AuthDataV4 };

/** Report union type */
export type Report =
  | { type: 'SgxEnclave'; report: EnclaveReport }
  | { type: 'TD10'; report: TDReport10 }
  | { type: 'TD15'; report: TDReport15 };

/** Main Quote structure */
export interface Quote {
  header: Header;
  report: Report;
  authData: AuthData;
}

/** QuoteCollateralV3 structure (collateral data for quote verification) */
export interface QuoteCollateralV3 {
  tcbInfoIssuerChain: string;
  tcbInfo: string;
  tcbInfoSignature: Uint8Array;
  qeIdentityIssuerChain: string;
  qeIdentity: string;
  qeIdentitySignature: Uint8Array;
}

/**
 * Possible TCB status values for quote verification, per Intel SGX/TDX documentation.
 * See: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-platform-tcb.html
 */
export type VerificationStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

/**
 * VerifiedReport structure: result of quote verification.
 * - status: TCB status string (see VerificationStatus)
 * - advisoryIds: array of Intel Security Advisory IDs (e.g., INTEL-SA-XXXX)
 * - report: the parsed quote report (SGX/TDX)
 */
export interface VerifiedReport {
  status: VerificationStatus;
  advisoryIds: string[];
  report: Report;
}

/**
 * Error codes for quote verification, mapped from Rust anyhow!/bail! error messages.
 * These represent the main categories of errors that can occur during quote verification.
 */
export type QuoteVerificationErrorCode =
  | 'DecodeError' // Failed to decode quote or fields
  | 'SignatureError' // Signature verification failed
  | 'UnsupportedVersion' // Unsupported quote or cert version/type
  | 'CertificateError' // Certificate chain or format error
  | 'HashMismatch' // Hash mismatch (e.g., QE report hash)
  | 'FieldMismatch' // FMSPC, TEE type, or other field mismatch
  | 'TCBExpired' // TCBInfo expired
  | 'DebugNotAllowed' // Debug mode not allowed
  | 'MissingField' // Required field missing
  | 'UnknownError'; // Any other error

/**
 * Error type for quote verification failures.
 * - code: error code (see QuoteVerificationErrorCode)
 * - message: human-readable error message
 */
export interface QuoteVerificationError {
  code: QuoteVerificationErrorCode;
  message: string;
}
