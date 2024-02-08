const assert = require('assert');
const { should } = require('micro-should');
const { optional, integer, gen } = require('./generator');
const { byteSwap, byteSwapIfBE, byteSwap32, isLE } = require('../utils.js');

// Here goes test for tests...
should(`Test generator`, () => {
  assert.deepStrictEqual(
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
    assert.deepStrictEqual(test.out, byteSwap(test.in));
  });
});

should('byteSwapIfBE', () => {
  BYTESWAP_TEST_CASES.forEach((test) => {
    if (isLE) {
      assert.deepStrictEqual(test.in, byteSwapIfBE(test.in));
    } else {
      assert.deepStrictEqual(test.out, byteSwapIfBE(test.in));
    }
  });
});

should('byteSwap32', () => {
  const input = Uint32Array.of([0x11223344, 0xffeeddcc, 0xccddeeff]);
  const expected = Uint32Array.of([0x44332211, 0xccddeeff, 0xffeeddcc]);
  byteSwap32(input);
  assert.deepStrictEqual(expected, input);
});

if (require.main === module) should.run();
