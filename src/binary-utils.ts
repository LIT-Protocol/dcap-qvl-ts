// Binary parsing utilities for Uint8Array buffers
// Handles little-endian and big-endian formats

// @ts-expect-error asn1.js has no types and uses dynamic 'this' context
import asn1 from 'asn1.js';

/** Validates that the buffer has enough bytes from the given offset. */
export function validateBuffer(buffer: Uint8Array, offset: number, length: number): void {
  if (offset < 0 || offset + length > buffer.length) {
    throw new RangeError(
      `Buffer too small: need ${length} bytes at offset ${offset}, but buffer length is ${buffer.length}`,
    );
  }
}

/** Read an unsigned 8-bit integer from buffer at offset. */
export function readUint8(buffer: Uint8Array, offset: number): number {
  validateBuffer(buffer, offset, 1);
  return buffer[offset];
}

/** Read an unsigned 16-bit integer (little-endian) from buffer at offset. */
export function readUint16LE(buffer: Uint8Array, offset: number): number {
  validateBuffer(buffer, offset, 2);
  return buffer[offset] | (buffer[offset + 1] << 8);
}

/** Read an unsigned 16-bit integer (big-endian) from buffer at offset. */
export function readUint16BE(buffer: Uint8Array, offset: number): number {
  validateBuffer(buffer, offset, 2);
  return (buffer[offset] << 8) | buffer[offset + 1];
}

/** Read an unsigned 32-bit integer (little-endian) from buffer at offset. */
export function readUint32LE(buffer: Uint8Array, offset: number): number {
  validateBuffer(buffer, offset, 4);
  return (
    (buffer[offset] |
      (buffer[offset + 1] << 8) |
      (buffer[offset + 2] << 16) |
      (buffer[offset + 3] << 24)) >>>
    0
  );
}

/** Read an unsigned 32-bit integer (big-endian) from buffer at offset. */
export function readUint32BE(buffer: Uint8Array, offset: number): number {
  validateBuffer(buffer, offset, 4);
  return (
    ((buffer[offset] << 24) |
      (buffer[offset + 1] << 16) |
      (buffer[offset + 2] << 8) |
      buffer[offset + 3]) >>>
    0
  );
}

/** Read an unsigned 64-bit integer (little-endian) from buffer at offset. Returns BigInt. */
export function readUint64LE(buffer: Uint8Array, offset: number): bigint {
  validateBuffer(buffer, offset, 8);
  return (
    BigInt(buffer[offset]) |
    (BigInt(buffer[offset + 1]) << 8n) |
    (BigInt(buffer[offset + 2]) << 16n) |
    (BigInt(buffer[offset + 3]) << 24n) |
    (BigInt(buffer[offset + 4]) << 32n) |
    (BigInt(buffer[offset + 5]) << 40n) |
    (BigInt(buffer[offset + 6]) << 48n) |
    (BigInt(buffer[offset + 7]) << 56n)
  );
}

/** Read an unsigned 64-bit integer (big-endian) from buffer at offset. Returns BigInt. */
export function readUint64BE(buffer: Uint8Array, offset: number): bigint {
  validateBuffer(buffer, offset, 8);
  return (
    (BigInt(buffer[offset]) << 56n) |
    (BigInt(buffer[offset + 1]) << 48n) |
    (BigInt(buffer[offset + 2]) << 40n) |
    (BigInt(buffer[offset + 3]) << 32n) |
    (BigInt(buffer[offset + 4]) << 24n) |
    (BigInt(buffer[offset + 5]) << 16n) |
    (BigInt(buffer[offset + 6]) << 8n) |
    BigInt(buffer[offset + 7])
  );
}

/** Read a slice of bytes from buffer at offset. */
export function readBytes(buffer: Uint8Array, offset: number, length: number): Uint8Array {
  validateBuffer(buffer, offset, length);
  return buffer.slice(offset, offset + length);
}

export interface MinimalEcdsaCert {
  publicKey: Uint8Array;
  // TODO: Add subject, issuer, extensions if needed
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

const Certificate = asn1.define('Certificate', function () {
  // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
  this.seq().obj(
    // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
    this.key('tbsCertificate')
      .seq()
      .obj(
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('version').explicit(0).int().optional(),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('serialNumber').int(),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('signature').seq().obj(
          // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
          this.key('algorithm').objid(),
          // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
          this.key('parameters').optional(),
        ),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('issuer').any(),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('validity').any(),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('subject').any(),
        // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
        this.key('subjectPublicKeyInfo')
          .seq()
          .obj(
            // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
            this.key('algorithm').seq().obj(
              // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
              this.key('algorithm').objid(),
              // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
              this.key('parameters').optional(),
            ),
            // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
            this.key('subjectPublicKey').bitstr(),
          ),
      ),
    // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
    this.key('signatureAlgorithm').seq().obj(
      // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
      this.key('algorithm').objid(),
      // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
      this.key('parameters').optional(),
    ),
    // @ts-expect-error asn1.js uses dynamic 'this' context and is not typed
    this.key('signatureValue').bitstr(),
  );
});

export function parseCertificate(cert: Uint8Array | string): MinimalEcdsaCert {
  let der: Uint8Array;
  if (typeof cert === 'string') {
    if (cert.includes('-----BEGIN CERTIFICATE-----')) {
      der = pemToDer(cert);
    } else {
      der = Buffer.from(cert, 'binary');
    }
  } else {
    der = cert;
  }
  // Parse the certificate ASN.1 structure
  const decoded = Certificate.decode(der, 'der');
  const spki = decoded.tbsCertificate.subjectPublicKeyInfo;
  const pubkeyBitStr: Buffer = spki.subjectPublicKey.data;
  if (pubkeyBitStr.length !== 65 || pubkeyBitStr[0] !== 0x04) {
    throw new Error('Invalid ECDSA public key');
  }
  return { publicKey: new Uint8Array(pubkeyBitStr) };
}

export function parseCertificateChain(pemChain: string): MinimalEcdsaCert[] {
  const pattern = /-+BEGIN CERTIFICATE-+[\s\S]*?-+END CERTIFICATE-+/g;
  const matches = pemChain.match(pattern) || [];
  return matches.map((pem) => parseCertificate(pem));
}
