import forge from 'node-forge';

/**
 * Compute SHA-256 hash of input (string or Uint8Array). Returns Uint8Array.
 */
export function sha256(data: string | Uint8Array): Uint8Array {
  const md = forge.md.sha256.create();
  if (typeof data === 'string') {
    md.update(data, 'utf8');
  } else {
    md.update(Buffer.from(data).toString('binary'));
  }
  return Uint8Array.from(Buffer.from(md.digest().getBytes(), 'binary'));
}

/**
 * Compute SHA-384 hash of input (string or Uint8Array). Returns Uint8Array.
 */
export function sha384(data: string | Uint8Array): Uint8Array {
  const md = forge.md.sha384.create();
  if (typeof data === 'string') {
    md.update(data, 'utf8');
  } else {
    md.update(Buffer.from(data).toString('binary'));
  }
  return Uint8Array.from(Buffer.from(md.digest().getBytes(), 'binary'));
}

/**
 * Create an incremental SHA-256 hasher. Supports update() and digest().
 */
export function createSha256Incremental() {
  const md = forge.md.sha256.create();
  return {
    update(data: string | Uint8Array) {
      if (typeof data === 'string') {
        md.update(data, 'utf8');
      } else {
        md.update(Buffer.from(data).toString('binary'));
      }
    },
    digest(): Uint8Array {
      return Uint8Array.from(Buffer.from(md.digest().getBytes(), 'binary'));
    },
  };
}

/**
 * Create an incremental SHA-384 hasher. Supports update() and digest().
 */
export function createSha384Incremental() {
  const md = forge.md.sha384.create();
  return {
    update(data: string | Uint8Array) {
      if (typeof data === 'string') {
        md.update(data, 'utf8');
      } else {
        md.update(Buffer.from(data).toString('binary'));
      }
    },
    digest(): Uint8Array {
      return Uint8Array.from(Buffer.from(md.digest().getBytes(), 'binary'));
    },
  };
}

/**
 * Securely compare two hash values (Uint8Array). Returns true if equal.
 * Uses constant-time comparison to prevent timing attacks.
 */
export function hashesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
