const assert = require('assert');
const { should } = require('micro-should');
const u64 = require('../_u64');

const U64_MASK = 2n ** 64n - 1n;
const U32_MASK = (2 ** 32 - 1) | 0;
// Convert [u32, u32] to BigInt(u64)
const rotate_right = (word, shift) => ((word >> shift) | (word << (64n - shift))) & U64_MASK;
const rotate_left = (word, shift) => ((word >> (64n - shift)) + (word << shift)) % (1n << 64n);

// Convert BigInt(u64) -> [u32, u32]
const big = (n) => {
  return { h: Number((n >> 32n) & BigInt(U32_MASK)) | 0, l: Number(n & BigInt(U32_MASK)) | 0 };
};

should('shr_small', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  for (let i = 0; i < 32; i++) {
    const h = u64.shrSH(val[0], val[1], i);
    const l = u64.shrSL(val[0], val[1], i);
    assert.deepStrictEqual((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
  }
});

// should('shr_big', () => {
//   const val = [0x01234567, 0x89abcdef];
//   const big = u64.toBig(...val);
//   for (let i = 32; i < 64; i++) {
//     const h = u64.shrBH(val[0], val[1], i);
//     const l = u64.shrBL(val[0], val[1], i);
//     assert.deepStrictEqual((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
//   }
// });

should('rotr_small', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  for (let i = 1; i < 32; i++) {
    const h = u64.rotrSH(val[0], val[1], i);
    const l = u64.rotrSL(val[0], val[1], i);
    assert.deepStrictEqual(rotate_right(big, BigInt(i)), u64.toBig(h, l));
  }
});

should('rotr32', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  const h = u64.rotr32H(val[0], val[1], 32);
  const l = u64.rotr32L(val[0], val[1], 32);
  assert.deepStrictEqual(rotate_right(big, BigInt(32)), u64.toBig(h, l));
});

should('rotr_big', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  for (let i = 33; i < 64; i++) {
    const h = u64.rotrBH(val[0], val[1], i);
    const l = u64.rotrBL(val[0], val[1], i);
    assert.deepStrictEqual(rotate_right(big, BigInt(i)), u64.toBig(h, l));
  }
});

should('rotl small', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  for (let i = 1; i < 32; i++) {
    const h = u64.rotlSH(val[0], val[1], i);
    const l = u64.rotlSL(val[0], val[1], i);
    assert.deepStrictEqual(rotate_left(big, BigInt(i)), u64.toBig(h, l), `rotl_big(${i})`);
  }
});

should('rotl big', () => {
  const val = [0x01234567, 0x89abcdef];
  const big = u64.toBig(...val);
  for (let i = 33; i < 64; i++) {
    const h = u64.rotlBH(val[0], val[1], i);
    const l = u64.rotlBL(val[0], val[1], i);
    assert.deepStrictEqual(rotate_left(big, BigInt(i)), u64.toBig(h, l), `rotl_big(${i})`);
  }
});

if (require.main === module) should.run();
