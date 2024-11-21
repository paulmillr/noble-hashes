const { deepStrictEqual, throws } = require('assert');
const fc = require('fast-check');
const { describe, should } = require('micro-should');
const { optional, integer, gen } = require('./generator');
const { TYPE_TEST } = require('./utils');
const { byteSwap, byteSwapIfBE, byteSwap32, isLE, bytesToHex, concatBytes, hexToBytes } = require('../utils');

describe('utils', () => {
  const staticHexVectors = [
    { bytes: Uint8Array.from([]), hex: '' },
    { bytes: Uint8Array.from([0xbe]), hex: 'be' },
    { bytes: Uint8Array.from([0xca, 0xfe]), hex: 'cafe' },
    { bytes: Uint8Array.from(new Array(1024).fill(0x69)), hex: '69'.repeat(1024) },
  ];
  should('hexToBytes', () => {
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex), v.bytes);
    for (let v of staticHexVectors) deepStrictEqual(hexToBytes(v.hex.toUpperCase()), v.bytes);
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
  should('hexToBytes <=> bytesToHex roundtrip', () =>
    fc.assert(
      fc.property(fc.hexaString({ minLength: 2, maxLength: 64 }), (hex) => {
        if (hex.length % 2 !== 0) return;
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex)));
        deepStrictEqual(hex, bytesToHex(hexToBytes(hex.toUpperCase())));
        deepStrictEqual(hexToBytes(hex), Uint8Array.from(Buffer.from(hex, 'hex')));
      })
    )
  );
  should('concatBytes', () => {
    const a = 1;
    const b = 2;
    const c = 0xff;
    const aa = Uint8Array.from([a]);
    const bb = Uint8Array.from([b]);
    const cc = Uint8Array.from([c]);
    deepStrictEqual(concatBytes(), new Uint8Array());
    deepStrictEqual(concatBytes(aa, bb), Uint8Array.from([a, b]));
    deepStrictEqual(concatBytes(aa, bb, cc), Uint8Array.from([a, b, c]));
    for (let v of TYPE_TEST.bytes)
      throws(() => {
        concatBytes(v);
      });
  });
  should('concatBytes random', () =>
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), fc.uint8Array(), (a, b, c) => {
        const expected = Uint8Array.from(Buffer.concat([a, b, c]));
        deepStrictEqual(concatBytes(a.slice(), b.slice(), c.slice()), expected);
      })
    )
  );
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
