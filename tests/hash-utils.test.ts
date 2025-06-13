import {
  sha256,
  sha384,
  createSha256Incremental,
  createSha384Incremental,
  hashesEqual,
} from '../src/hash-utils';

// NIST SHA-256 test vector
const sha256Vectors = [
  { input: '', expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { input: 'abc', expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
  {
    input: 'The quick brown fox jumps over the lazy dog',
    expected: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
  },
];

// NIST SHA-384 test vector
const sha384Vectors = [
  {
    input: '',
    expected:
      '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
  },
  {
    input: 'abc',
    expected:
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
  },
  {
    input: 'The quick brown fox jumps over the lazy dog',
    expected:
      'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
  },
];

describe('sha256', () => {
  for (const { input, expected } of sha256Vectors) {
    it(`computes SHA-256 for "${input}"`, () => {
      const hash = sha256(input);
      expect(Buffer.from(hash).toString('hex')).toBe(expected);
    });
  }

  it('computes SHA-256 for Uint8Array', () => {
    const hash = sha256(new Uint8Array([0x61, 0x62, 0x63])); // 'abc'
    expect(Buffer.from(hash).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('matches incremental SHA-256', () => {
    const inc = createSha256Incremental();
    inc.update('The quick ');
    inc.update('brown fox jumps over the lazy dog');
    const hash = inc.digest();
    expect(Buffer.from(hash).toString('hex')).toBe(
      'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
    );
  });
});

describe('sha384', () => {
  for (const { input, expected } of sha384Vectors) {
    it(`computes SHA-384 for "${input}"`, () => {
      const hash = sha384(input);
      expect(Buffer.from(hash).toString('hex')).toBe(expected);
    });
  }

  it('computes SHA-384 for Uint8Array', () => {
    const hash = sha384(new Uint8Array([0x61, 0x62, 0x63])); // 'abc'
    expect(Buffer.from(hash).toString('hex')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    );
  });

  it('matches incremental SHA-384', () => {
    const inc = createSha384Incremental();
    inc.update('The quick ');
    inc.update('brown fox jumps over the lazy dog');
    const hash = inc.digest();
    expect(Buffer.from(hash).toString('hex')).toBe(
      'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
    );
  });
});

describe('hashesEqual', () => {
  it('returns true for equal hashes', () => {
    const a = sha256('abc');
    const b = sha256('abc');
    expect(hashesEqual(a, b)).toBe(true);
  });
  it('returns false for different hashes', () => {
    const a = sha256('abc');
    const b = sha256('def');
    expect(hashesEqual(a, b)).toBe(false);
  });
  it('returns false for different lengths', () => {
    const a = sha256('abc');
    const b = sha384('abc');
    expect(hashesEqual(a, b)).toBe(false);
  });
});
