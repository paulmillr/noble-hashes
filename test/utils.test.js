const { deepStrictEqual, throws } = require('assert');
const { describe, should } = require('micro-should');
const { optional, integer, gen } = require('./generator');
const { TYPE_TEST } = require('./utils');
const { byteSwap, byteSwapIfBE, byteSwap32, isLE, hexToBytes, bytesToHex } = require('../utils');

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex), v.bytes);
    for (let v of TYPE_TEST.hex) {
      throws(() => hexToBytes(v));
    }
  });
  should('bytesToHex', () => {
    for (let v of staticHexVectors) deepStrictEqual(bytesToHex(v.bytes), v.hex);
    for (let v of TYPE_TEST.bytes) {
      throws(() => bytesToHex(v));
    }
  });
});

describe('utils etc', () => {
  // Here goes test for tests...
  should(`Test generator`, () => {
    deepStrictEqual(
      gen({
        N: integer(0, 5),
        b: integer(2, 7),
        c: optional(integer(5, 10)),
      }),
      [
        { N: 0, b: 2, c: undefined },
        { N: 4, b: 3, c: 9 },
        { N: 3, b: 4, c: 8 },
        { N: 2, b: 5, c: 7 },
        { N: 1, b: 6, c: 6 },
        { N: 0, b: 2, c: 5 },
      ]
    );
  });

  // Byte swapping
  const BYTESWAP_TEST_CASES = [
    { in: 0x11223344 | 0, out: 0x44332211 | 0 },
    { in: 0xffeeddcc | 0, out: 0xccddeeff | 0 },
    { in: 0xccddeeff | 0, out: 0xffeeddcc | 0 },
  ];

  should('byteSwap', () => {
    BYTESWAP_TEST_CASES.forEach((test) => {
      deepStrictEqual(test.out, byteSwap(test.in));
    });
  });

  should('byteSwapIfBE', () => {
    BYTESWAP_TEST_CASES.forEach((test) => {
      if (isLE) {
        deepStrictEqual(test.in, byteSwapIfBE(test.in));
      } else {
        deepStrictEqual(test.out, byteSwapIfBE(test.in));
      }
    });
  });

  should('byteSwap32', () => {
    const input = Uint32Array.of([0x11223344, 0xffeeddcc, 0xccddeeff]);
    const expected = Uint32Array.of([0x44332211, 0xccddeeff, 0xffeeddcc]);
    byteSwap32(input);
    deepStrictEqual(expected, input);
  });
});

if (require.main === module) should.run();
