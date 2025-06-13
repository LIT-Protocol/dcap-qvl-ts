import {
  readUint8,
  readUint16LE,
  readUint16BE,
  readUint32LE,
  readUint32BE,
  readUint64LE,
  readUint64BE,
  readBytes,
  validateBuffer,
} from '../src/binary-utils';

test('adds 1 + 2 to equal 3', () => {
  expect(1 + 2).toBe(3);
});

test('readUint8 reads a single byte', () => {
  const buf = new Uint8Array([0x12]);
  expect(readUint8(buf, 0)).toBe(0x12);
});

test('readUint16LE and readUint16BE', () => {
  const buf = new Uint8Array([0x34, 0x12]);
  expect(readUint16LE(buf, 0)).toBe(0x1234);
  expect(readUint16BE(buf, 0)).toBe(0x3412);
});

test('readUint32LE and readUint32BE', () => {
  const buf = new Uint8Array([0x78, 0x56, 0x34, 0x12]);
  expect(readUint32LE(buf, 0)).toBe(0x12345678);
  expect(readUint32BE(buf, 0)).toBe(0x78563412);
});

test('readUint64LE and readUint64BE', () => {
  const buf = new Uint8Array([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
  expect(readUint64LE(buf, 0)).toBe(BigInt('0x0102030405060708'));
  expect(readUint64BE(buf, 0)).toBe(BigInt('0x0807060504030201'));
});

test('readBytes returns a slice', () => {
  const buf = new Uint8Array([1, 2, 3, 4, 5]);
  expect(Array.from(readBytes(buf, 1, 3))).toEqual([2, 3, 4]);
});

test('validateBuffer throws on out-of-bounds', () => {
  const buf = new Uint8Array([1, 2, 3]);
  expect(() => validateBuffer(buf, 2, 2)).toThrow(RangeError);
  expect(() => validateBuffer(buf, -1, 1)).toThrow(RangeError);
});
