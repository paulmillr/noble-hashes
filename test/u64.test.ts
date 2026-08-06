import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import * as u64 from '../src/_u64.ts';

const U64_MASK = 2n ** 64n - 1n;
const U32_MASK = (2 ** 32 - 1) | 0;
// Convert [u32, u32] to BigInt(u64)
const rotate_right = (word, shift) => ((word >> shift) | (word << (64n - shift))) & U64_MASK;

// Convert BigInt(u64) -> [u32, u32]
const big = (n) => {
  return { h: Number((n >> 32n) & BigInt(U32_MASK)) | 0, l: Number(n & BigInt(U32_MASK)) | 0 };
};

describe('u64', () => {
  it('shr_small', () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(...val);
    for (let i = 0; i < 32; i++) {
      const h = u64.shrSH(val[0], val[1], i);
      const l = u64.shrSL(val[0], val[1], i);
      eql((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
    }
  });

  // it('shr_big', () => {
  //   const val = [0x01234567, 0x89abcdef];
  //   const big = u64.toBig(...val);
  //   for (let i = 32; i < 64; i++) {
  //     const h = u64.shrBH(val[0], val[1], i);
  //     const l = u64.shrBL(val[0], val[1], i);
  //     deepStrictEqual((big >> BigInt(i)) & U64_MASK, u64.toBig(h, l));
  //   }
  // });

  it('rotr_small', () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(...val);
    for (let i = 1; i < 32; i++) {
      const h = u64.rotrSH(val[0], val[1], i);
      const l = u64.rotrSL(val[0], val[1], i);
      eql(rotate_right(big, BigInt(i)), u64.toBig(h, l));
    }
  });

  it('rotr32', () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(...val);
    const h = u64.rotr32H(val[0], val[1], 32);
    const l = u64.rotr32L(val[0], val[1], 32);
    eql(rotate_right(big, BigInt(32)), u64.toBig(h, l));
  });

  it('rotr_big', () => {
    const val = [0x01234567, 0x89abcdef];
    const big = u64.toBig(...val);
    for (let i = 33; i < 64; i++) {
      const h = u64.rotrBH(val[0], val[1], i);
      const l = u64.rotrBL(val[0], val[1], i);
      eql(rotate_right(big, BigInt(i)), u64.toBig(h, l));
    }
  });

  // rotl* live as local copies in sha3.ts (their only consumer, for inlining) and are
  // covered there by keccak vectors; no importable definitions remain to unit-test.
});

it.runWhen(import.meta.url);
