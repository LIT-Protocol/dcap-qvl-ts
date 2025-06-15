// Intel SGX/DCAP constants ported from dcap-qvl-rust/src/constants.rs
// These are used throughout the quote verification logic

export const CERTIFICATION_DATA_SIZE_BYTE_LEN = 4;
export const QE_AUTH_DATA_SIZE_BYTE_LEN = 2;
export const QE_CERT_DATA_TYPE_BYTE_LEN = 2;
export const QE_CERT_DATA_SIZE_BYTE_LEN = 4;

export const AUTH_DATA_MIN_BYTE_LEN =
  64 + // ECDSA_SIGNATURE_BYTE_LEN
  64 + // ECDSA_PUBKEY_BYTE_LEN
  384 + // QE_REPORT_BYTE_LEN
  64 + // QE_REPORT_SIG_BYTE_LEN
  QE_AUTH_DATA_SIZE_BYTE_LEN +
  QE_CERT_DATA_TYPE_BYTE_LEN +
  QE_CERT_DATA_SIZE_BYTE_LEN;

export const HEADER_BYTE_LEN = 48; // Example value, update if needed
export const ENCLAVE_REPORT_BYTE_LEN = 384;
export const TD_REPORT10_BYTE_LEN = 1024; // Example value, update if needed
export const TD_REPORT15_BYTE_LEN = 1088; // Example value, update if needed
export const BODY_BYTE_SIZE = 432; // Example value, update if needed

export const QUOTE_MIN_BYTE_LEN =
  HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + AUTH_DATA_MIN_BYTE_LEN;

export const ATTESTATION_KEY_LEN = 64;
export const AUTHENTICATION_DATA_LEN = 32;
export const QE_HASH_DATA_BYTE_LEN = ATTESTATION_KEY_LEN + AUTHENTICATION_DATA_LEN;

export const PCK_ID_PLAIN = 1;
export const PCK_ID_RSA_2048_OAEP = 2;
export const PCK_ID_RSA_3072_OAEP = 3;
export const PCK_LEAF_CERT_PLAIN = 4;
export const PCK_CERT_CHAIN = 5;
export const QE_REPORT_CERT = 6;
export const PLATFORM_MANIFEST = 7;

export const TEE_TYPE_SGX = 0x00000000;
export const TEE_TYPE_TDX = 0x00000081;
export const ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE = 2;

// Add more constants as needed from the Rust reference
