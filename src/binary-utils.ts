// Binary parsing utilities for Uint8Array buffers
// Handles little-endian and big-endian formats

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

// ASN.1/DER and certificate parsing utilities using node-forge
import forge from 'node-forge';

/**
 * Parse a PEM or DER encoded certificate and return a forge.pki.Certificate object.
 * Accepts Uint8Array (DER) or string (PEM).
 */
export function parseCertificate(cert: Uint8Array | string): forge.pki.Certificate {
  try {
    if (typeof cert === 'string') {
      // PEM format
      return forge.pki.certificateFromPem(cert);
    } else {
      // DER format (Uint8Array)
      const derBytes =
        typeof Buffer !== 'undefined'
          ? Buffer.from(cert).toString('binary')
          : String.fromCharCode(...cert);
      return forge.pki.certificateFromAsn1(forge.asn1.fromDer(derBytes));
    }
  } catch (err) {
    throw new Error(`Failed to parse certificate: ${err}`);
  }
}

/**
 * Parse a PEM chain (string) and return an array of forge.pki.Certificate objects.
 */
export function parseCertificateChain(pemChain: string): forge.pki.Certificate[] {
  const pattern = /-+BEGIN CERTIFICATE-+[\s\S]*?-+END CERTIFICATE-+/g;
  const matches = pemChain.match(pattern) || [];
  return matches.map((pem) => forge.pki.certificateFromPem(pem));
}

/**
 * Extract a specific extension value from a certificate by OID.
 * Returns the extension value as a Buffer, or undefined if not found.
 */
export function getExtensionByOID(
  cert: forge.pki.Certificate,
  oid: string,
): Uint8Array | undefined {
  const ext = cert.extensions.find((e) => e.id === oid || e.oid === oid);
  if (!ext) return undefined;
  // The value is a DER-encoded ASN.1 Octet String
  if (typeof ext.value === 'string') {
    // node-forge returns hex string for some extensions
    return Uint8Array.from(Buffer.from(ext.value, 'hex'));
  } else if (ext.value instanceof Uint8Array) {
    return ext.value;
  } else if (ext.value && ext.value.bytes) {
    // ASN.1 object
    return Uint8Array.from(Buffer.from(ext.value.bytes(), 'binary'));
  }
  return undefined;
}

/**
 * Parse a DER-encoded ASN.1 structure from a Uint8Array.
 * Returns a forge.asn1 object.
 */
export function parseASN1(der: Uint8Array): forge.asn1.Asn1 {
  try {
    const derBytes =
      typeof Buffer !== 'undefined'
        ? Buffer.from(der).toString('binary')
        : String.fromCharCode(...der);
    return forge.asn1.fromDer(derBytes);
  } catch (err) {
    throw new Error(`Failed to parse ASN.1 DER: ${err}`);
  }
}

/**
 * Extract a field from an ASN.1 sequence by index.
 */
export function getASN1Field(seq: forge.asn1.Asn1, index: number): forge.asn1.Asn1 | undefined {
  if (seq && seq.value && Array.isArray(seq.value) && seq.value.length > index) {
    return seq.value[index];
  }
  return undefined;
}
