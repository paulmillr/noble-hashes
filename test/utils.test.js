import fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import { setBigUint64 } from '../esm/_md.js';
import { sha256 } from '../esm/sha256.js';
import * as u from '../esm/utils.js';
import {
  byteSwap,
  byteSwap32,
  byteSwapIfBE,
  bytesToHex,
  concatBytes,
  createView,
  hexToBytes,
  isBytes,
  isLE,
  randomBytes,
} from '../esm/utils.js';
import { gen, integer, optional } from './generator.js';
import { TYPE_TEST, pattern } from './utils.js';

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
        if (typeof Buffer !== 'undefined')
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
        const expected = Uint8Array.from([...a, ...b, ...c]);
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

  should('pattern', () => {
    const fromHex = (hex) => hexToBytes(hex.replace(/ |\n/gm, ''));

    deepStrictEqual(
      pattern(0xfa, 17),
      fromHex(`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10`)
    );
    deepStrictEqual(
      pattern(0xfa, 17 ** 2),
      fromHex(`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
            20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
            30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
            40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
            50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
            60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
            70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
            80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
            90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
            A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
            B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
            C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF
            D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF
            E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF
            F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA
            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
            20 21 22 23 24 25`)
    );
  });
  should('setBigUint64', () => {
    const t = new Uint8Array(20);
    const v = createView(t);
    const VECTORS = [
      {
        n: 123n,
        le: false,
        hex: '000000000000007b000000000000000000000000',
      },
      {
        n: 123n,
        le: true,
        hex: '7b00000000000000000000000000000000000000',
      },
      {
        n: 2n ** 64n - 1n,
        le: true,
        hex: 'ffffffffffffffff000000000000000000000000',
      },
      {
        n: 2n ** 64n - 1n,
        le: true,
        hex: '000000ffffffffffffffff000000000000000000',
        pos: 3,
      },
      {
        n: 0x123456789abcdef0n,
        le: true,
        hex: 'f0debc9a78563412000000000000000000000000',
      },
      {
        n: 0x123456789abcdef0n,
        le: false,
        hex: '123456789abcdef0000000000000000000000000',
      },
    ];
    const createViewMock = (u8) => {
      const v = createView(u8);
      return {
        setUint32: (o, wh, isLE) => v.setUint32(o, wh, isLE),
      };
    };

    for (const cv of [createView, createViewMock]) {
      for (const t of VECTORS) {
        const b = new Uint8Array(20);
        const v = cv(b);
        setBigUint64(v, t.pos || 0, t.n, t.le);
        deepStrictEqual(bytesToHex(b), t.hex);
      }
    }
  });
  should('randomBytes', () => {
    if (typeof crypto === 'undefined') return;
    const t = randomBytes(32);
    deepStrictEqual(t instanceof Uint8Array, true);
    deepStrictEqual(t.length, 32);
    const t2 = randomBytes(12);
    deepStrictEqual(t2 instanceof Uint8Array, true);
    deepStrictEqual(t2.length, 12);
  });
  should('isBytes', () => {
    deepStrictEqual(isBytes(new Uint8Array(0)), true);
    if (typeof Buffer !== 'undefined') deepStrictEqual(isBytes(Buffer.alloc(10)), true);
    deepStrictEqual(isBytes(''), false);
    deepStrictEqual(isBytes([1, 2, 3]), false);
  });
});

describe('assert', () => {
  should('anumber', () => {
    deepStrictEqual(u.anumber(10), undefined);
    throws(() => u.anumber(1.2));
    throws(() => u.anumber('1'));
    throws(() => u.anumber(true));
    throws(() => u.anumber(NaN));
  });
  should('abytes', () => {
    deepStrictEqual(u.abytes(new Uint8Array(0)), undefined);
    if (typeof Buffer !== 'undefined') deepStrictEqual(u.abytes(Buffer.alloc(10)), undefined);
    deepStrictEqual(u.abytes(new Uint8Array(10)), undefined);
    u.abytes(new Uint8Array(11), 11, 12);
    u.abytes(new Uint8Array(12), 12, 12);
    throws(() => u.abytes('test'));
    throws(() => u.abytes(new Uint8Array(10), 11, 12));
    throws(() => u.abytes(new Uint8Array(10), 11, 12));
  });
  should('ahash', () => {
    deepStrictEqual(u.ahash(sha256), undefined);
    throws(() => u.ahash({}));
    throws(() => u.ahash({ blockLen: 1, outputLen: 1, create: () => {} }));
  });
  should('aexists', () => {
    deepStrictEqual(u.aexists({}), undefined);
    throws(() => u.aexists({ destroyed: true }));
  });
  should('aoutput', () => {
    deepStrictEqual(u.aoutput(new Uint8Array(10), { outputLen: 5 }), undefined);
    throws(() => u.aoutput(new Uint8Array(1), { outputLen: 5 }));
  });
});

should.runWhen(import.meta.url);
