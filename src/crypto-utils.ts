// CryptoUtils: Cryptographic utility functions for SGX quote verification and general use
//
// Example usage:
// import { CryptoUtils } from './crypto-utils';
// const pubkey = CryptoUtils.pemToRawP256PublicKey(pem);
// const valid = CryptoUtils.verifyEcdsaSignature({ publicKey: pubkey, message, signature });
// const hash = CryptoUtils.sha256(data);

import forge from 'node-forge';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Convert a PEM-encoded P-256 public key to raw uncompressed key bytes (Uint8Array, 65 bytes).
 * Throws if the PEM is not a valid SPKI EC public key.
 */
export function pemToRawP256PublicKey(pem: string): Uint8Array {
  // Remove PEM header/footer and decode base64
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  // ASN.1 parse: skip the SPKI header, extract the public key BIT STRING
  // SPKI: SEQUENCE { ..., BIT STRING pubkey }
  // node-forge can parse this
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(der));
  // asn1.value[1] is the BIT STRING (public key)
  if (!Array.isArray(asn1.value) || asn1.value.length < 2)
    throw new Error('Invalid SPKI structure');
  const bitString = asn1.value[1];
  // bitString.value is a string, first byte is unused bits count, rest is key
  if (typeof bitString.value !== 'string') throw new Error('Invalid BIT STRING');
  const bytes = Buffer.from(bitString.value, 'binary');
  // First byte is unused bits count (should be 0)
  if (bytes[0] !== 0x00) throw new Error('Unexpected unused bits in BIT STRING');
  const pubkey = bytes.slice(1); // 65 bytes for uncompressed P-256
  if (pubkey.length !== 65 || pubkey[0] !== 0x04)
    throw new Error('Not an uncompressed P-256 public key');
  return new Uint8Array(pubkey);
}

/**
 * Verify an ECDSA signature (P-256, r||s format) over a message.
 * @param publicKey Public key (PEM string or Uint8Array, uncompressed)
 * @param message Message (Uint8Array)
 * @param signature Signature (Uint8Array, r||s, 64 bytes)
 * @returns true if valid, false otherwise
 */
export function verifyEcdsaSignature({
  publicKey,
  message,
  signature,
  isRaw = true,
}: {
  publicKey: string | Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
  isRaw?: boolean;
}): boolean {
  let pubkeyBytes: Uint8Array;
  if (typeof publicKey === 'string') {
    pubkeyBytes = pemToRawP256PublicKey(publicKey);
  } else {
    pubkeyBytes = publicKey;
  }

  let sigToVerify = signature;
  if (isRaw) {
    if (signature.length !== 64) {
      // A raw P-256 signature must be 64 bytes (32-byte r + 32-byte s)
      return false;
    }
    // noble/curves' p256.verify expects a DER-encoded signature.
    // We must convert the raw r||s signature to DER format first.
    sigToVerify = rawEcdsaSigToDer(signature);
  }

  // p256.verify expects a DER-encoded signature, a message hash, and a public key
  try {
    // The message must be hashed with SHA256 before verification.
    const msgHash = sha256(message);
    return p256.verify(sigToVerify, msgHash, pubkeyBytes);
  } catch {
    // If verification fails due to an invalid signature format or other errors,
    // catch the exception and return false.
    return false;
  }
}

/**
 * Convert a raw ECDSA signature (r||s, 64 bytes) to DER encoding.
 * @param rawSig Raw signature (Uint8Array, 64 bytes)
 * @returns DER-encoded signature (Uint8Array)
 */
export function rawEcdsaSigToDer(rawSig: Uint8Array): Uint8Array {
  if (rawSig.length !== 64) throw new Error('Raw ECDSA signature must be 64 bytes');
  // Use @noble/curves helper: toDERHex returns a hex string, so convert to Uint8Array
  const derHex = p256.Signature.fromCompact(rawSig).toDERHex();
  return new Uint8Array(Buffer.from(derHex, 'hex'));
}

/**
 * Verify an RSA signature (PKCS#1 v1.5 or PSS) over a message or hash.
 * @param publicKey Public key (PEM string or Uint8Array)
 * @param message Message or hash (Uint8Array)
 * @param signature Signature (Uint8Array)
 * @param scheme 'pkcs1' | 'pss' (default: 'pkcs1')
 * @param hashAlg 'sha256' | 'sha384' (default: 'sha256')
 * @returns true if valid, false otherwise
 */
export function verifyRsaSignature({
  publicKey,
  message,
  signature,
  scheme = 'pkcs1',
  hashAlg = 'sha256',
}: {
  publicKey: string | Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
  scheme?: 'pkcs1' | 'pss';
  hashAlg?: 'sha256' | 'sha384';
}): boolean {
  let pubKeyObj: forge.pki.PublicKey;
  if (typeof publicKey === 'string') {
    pubKeyObj = forge.pki.publicKeyFromPem(publicKey);
  } else {
    // Assume DER-encoded SubjectPublicKeyInfo
    const der = Buffer.from(publicKey).toString('binary');
    pubKeyObj = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(der));
  }
  const md = hashAlg === 'sha384' ? forge.md.sha384.create() : forge.md.sha256.create();
  md.update(Buffer.from(message).toString('binary'));
  try {
    if (scheme === 'pss') {
      return pubKeyObj.verify(
        md.digest().bytes(),
        Buffer.from(signature).toString('binary'),
        forge.pss.create({
          md,
          mgf: forge.mgf.mgf1.create(
            hashAlg === 'sha384' ? forge.md.sha384.create() : forge.md.sha256.create(),
          ),
          saltLength: md.digest().length,
        }),
      );
    } else {
      return pubKeyObj.verify(md.digest().bytes(), Buffer.from(signature).toString('binary'));
    }
  } catch {
    return false;
  }
}

/**
 * Validate a certificate chain (leaf first, root last).
 * @param certs Array of forge.pki.Certificate (leaf first, root last)
 * @param options Optional: { trustedRoots?: forge.pki.Certificate[] | string[]; date?: Date }
 * @returns true if valid, throws otherwise
 */
export function validateCertificateChain(
  certs: forge.pki.Certificate[],
  options?: { trustedRoots?: Array<forge.pki.Certificate | string>; date?: Date },
): boolean {
  if (!Array.isArray(certs) || certs.length < 2) {
    throw new Error('Certificate chain must have at least leaf and root');
  }
  const date = options?.date || new Date();
  // Check validity periods
  for (const cert of certs) {
    if (!cert.validity.notBefore || !cert.validity.notAfter) {
      throw new Error('Certificate missing validity period');
    }
    if (date < cert.validity.notBefore || date > cert.validity.notAfter) {
      throw new Error(
        `Certificate expired or not yet valid: ${cert.subject.getField('CN')?.value}`,
      );
    }
  }
  // Use node-forge's CA store and verifyCertificateChain for robust validation
  if (options?.trustedRoots && options.trustedRoots.length > 0) {
    const caStore = forge.pki.createCaStore(
      options.trustedRoots.map((t) => (typeof t === 'string' ? t : forge.pki.certificateToPem(t))),
    );
    try {
      forge.pki.verifyCertificateChain(caStore, certs, {
        validityCheckDate: date,
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.message) {
        throw err;
      } else {
        throw new Error('Certificate chain validation failed');
      }
    }
    return true;
  } else {
    // No trusted roots: just check signatures up the chain
    for (let i = 0; i < certs.length - 1; i++) {
      const child = certs[i];
      const parent = certs[i + 1];
      if (!child.verify(parent)) {
        throw new Error(`Certificate signature invalid at position ${i}`);
      }
    }
    return true;
  }
}

export class CryptoUtils {
  /**
   * Compute SHA-256 hash of data (Uint8Array or string). Returns Uint8Array.
   */
  static sha256(data: Uint8Array | string): Uint8Array {
    const md = forge.md.sha256.create();
    if (typeof data === 'string') {
      md.update(data, 'utf8');
    } else {
      md.update(Buffer.from(data).toString('binary'));
    }
    return new Uint8Array(Buffer.from(md.digest().getBytes(), 'binary'));
  }

  /**
   * Compute SHA-384 hash of data (Uint8Array or string). Returns Uint8Array.
   */
  static sha384(data: Uint8Array | string): Uint8Array {
    const md = forge.md.sha384.create();
    if (typeof data === 'string') {
      md.update(data, 'utf8');
    } else {
      md.update(Buffer.from(data).toString('binary'));
    }
    return new Uint8Array(Buffer.from(md.digest().getBytes(), 'binary'));
  }
}
