/**
 * blake2b (64-bit) & blake2s (8 to 32-bit) hash functions.
 * b could have been faster, but there is no fast u64 in js, so s is 1.5x faster.
 * @module
 */
import { abytes } from './_assert.ts';
import { BLAKE, type BlakeOpts, G1s, G2s, SIGMA } from './_blake.ts';
import { SHA256_IV } from './_md.ts';
import * as u64 from './_u64.ts';
import {
  byteSwapIfBE,
  type CHashO,
  clean,
  createOptHasher as createHashWithOpts,
  toBytes,
  u32,
} from './utils.ts';

// Same as SHA512_IV, but swapped endianness: LE instead of BE. iv[1] is iv[0], etc.
const B2B_IV = /* @__PURE__ */ Uint32Array.from([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
// Temporary buffer
const BBUF = /* @__PURE__ */ new Uint32Array(32);

// Mixing function G splitted in two halfs
function G1b(a: number, b: number, c: number, d: number, msg: Uint32Array, x: number) {
  // NOTE: V is LE here
  const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
  let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1]; // prettier-ignore
  let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1]; // prettier-ignore
  let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1]; // prettier-ignore
  let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1]; // prettier-ignore
  // v[a] = (v[a] + v[b] + x) | 0;
  let ll = u64.add3L(Al, Bl, Xl);
  Ah = u64.add3H(ll, Ah, Bh, Xh);
  Al = ll | 0;
  // v[d] = rotr(v[d] ^ v[a], 32)
  ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
  ({ Dh, Dl } = { Dh: u64.rotr32H(Dh, Dl), Dl: u64.rotr32L(Dh, Dl) });
  // v[c] = (v[c] + v[d]) | 0;
  ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
  // v[b] = rotr(v[b] ^ v[c], 24)
  ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
  ({ Bh, Bl } = { Bh: u64.rotrSH(Bh, Bl, 24), Bl: u64.rotrSL(Bh, Bl, 24) });
  (BBUF[2 * a] = Al), (BBUF[2 * a + 1] = Ah);
  (BBUF[2 * b] = Bl), (BBUF[2 * b + 1] = Bh);
  (BBUF[2 * c] = Cl), (BBUF[2 * c + 1] = Ch);
  (BBUF[2 * d] = Dl), (BBUF[2 * d + 1] = Dh);
}

function G2b(a: number, b: number, c: number, d: number, msg: Uint32Array, x: number) {
  // NOTE: V is LE here
  const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
  let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1]; // prettier-ignore
  let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1]; // prettier-ignore
  let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1]; // prettier-ignore
  let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1]; // prettier-ignore
  // v[a] = (v[a] + v[b] + x) | 0;
  let ll = u64.add3L(Al, Bl, Xl);
  Ah = u64.add3H(ll, Ah, Bh, Xh);
  Al = ll | 0;
  // v[d] = rotr(v[d] ^ v[a], 16)
  ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
  ({ Dh, Dl } = { Dh: u64.rotrSH(Dh, Dl, 16), Dl: u64.rotrSL(Dh, Dl, 16) });
  // v[c] = (v[c] + v[d]) | 0;
  ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
  // v[b] = rotr(v[b] ^ v[c], 63)
  ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
  ({ Bh, Bl } = { Bh: u64.rotrBH(Bh, Bl, 63), Bl: u64.rotrBL(Bh, Bl, 63) });
  (BBUF[2 * a] = Al), (BBUF[2 * a + 1] = Ah);
  (BBUF[2 * b] = Bl), (BBUF[2 * b + 1] = Bh);
  (BBUF[2 * c] = Cl), (BBUF[2 * c + 1] = Ch);
  (BBUF[2 * d] = Dl), (BBUF[2 * d + 1] = Dh);
}

const keyLenB = 64;
const saltLenB = 16;
const persLenB = 16;
export class BLAKE2b extends BLAKE<BLAKE2b> {
  // Same as SHA-512, but LE
  private v0l = B2B_IV[0] | 0;
  private v0h = B2B_IV[1] | 0;
  private v1l = B2B_IV[2] | 0;
  private v1h = B2B_IV[3] | 0;
  private v2l = B2B_IV[4] | 0;
  private v2h = B2B_IV[5] | 0;
  private v3l = B2B_IV[6] | 0;
  private v3h = B2B_IV[7] | 0;
  private v4l = B2B_IV[8] | 0;
  private v4h = B2B_IV[9] | 0;
  private v5l = B2B_IV[10] | 0;
  private v5h = B2B_IV[11] | 0;
  private v6l = B2B_IV[12] | 0;
  private v6h = B2B_IV[13] | 0;
  private v7l = B2B_IV[14] | 0;
  private v7h = B2B_IV[15] | 0;

  constructor(opts: BlakeOpts = {}) {
    super(128, opts.dkLen === undefined ? 64 : opts.dkLen, opts, keyLenB, saltLenB, persLenB);
    const { key, personalization, salt } = opts;
    const keyLength = key ? key.length : 0;
    this.v0l ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
    if (salt) {
      const slt = u32(toBytes(salt));
      this.v4l ^= byteSwapIfBE(slt[0]);
      this.v4h ^= byteSwapIfBE(slt[1]);
      this.v5l ^= byteSwapIfBE(slt[2]);
      this.v5h ^= byteSwapIfBE(slt[3]);
    }
    if (personalization) {
      const pers = u32(toBytes(personalization));
      this.v6l ^= byteSwapIfBE(pers[0]);
      this.v6h ^= byteSwapIfBE(pers[1]);
      this.v7l ^= byteSwapIfBE(pers[2]);
      this.v7h ^= byteSwapIfBE(pers[3]);
    }
    if (key) {
      // Pad to blockLen and update
      let k = key;
      k = toBytes(k);
      abytes(k);
      const tmp = new Uint8Array(this.blockLen);
      tmp.set(k);
      this.update(tmp);
    }
  }
  // prettier-ignore
  protected get(): [
    number, number, number, number, number, number, number, number,
    number, number, number, number, number, number, number, number
  ] {
    let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
    return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
  }
  // prettier-ignore
  protected set(
    v0l: number, v0h: number, v1l: number, v1h: number,
    v2l: number, v2h: number, v3l: number, v3h: number,
    v4l: number, v4h: number, v5l: number, v5h: number,
    v6l: number, v6h: number, v7l: number, v7h: number
  ): void {
    this.v0l = v0l | 0;
    this.v0h = v0h | 0;
    this.v1l = v1l | 0;
    this.v1h = v1h | 0;
    this.v2l = v2l | 0;
    this.v2h = v2h | 0;
    this.v3l = v3l | 0;
    this.v3h = v3h | 0;
    this.v4l = v4l | 0;
    this.v4h = v4h | 0;
    this.v5l = v5l | 0;
    this.v5h = v5h | 0;
    this.v6l = v6l | 0;
    this.v6h = v6h | 0;
    this.v7l = v7l | 0;
    this.v7h = v7h | 0;
  }
  protected compress(msg: Uint32Array, offset: number, isLast: boolean): void {
    this.get().forEach((v, i) => (BBUF[i] = v)); // First half from state.
    BBUF.set(B2B_IV, 16); // Second half from IV.
    let { h, l } = u64.fromBig(BigInt(this.length));
    BBUF[24] = B2B_IV[8] ^ l; // Low word of the offset.
    BBUF[25] = B2B_IV[9] ^ h; // High word.
    // Invert all bits for last block
    if (isLast) {
      BBUF[28] = ~BBUF[28];
      BBUF[29] = ~BBUF[29];
    }
    let j = 0;
    const s = SIGMA;
    for (let i = 0; i < 12; i++) {
      G1b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
      G2b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
      G1b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
      G2b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
      G1b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
      G2b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
      G1b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
      G2b(3, 7, 11, 15, msg, offset + 2 * s[j++]);

      G1b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
      G2b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
      G1b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
      G2b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
      G1b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
      G2b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
      G1b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
      G2b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
    }
    this.v0l ^= BBUF[0] ^ BBUF[16];
    this.v0h ^= BBUF[1] ^ BBUF[17];
    this.v1l ^= BBUF[2] ^ BBUF[18];
    this.v1h ^= BBUF[3] ^ BBUF[19];
    this.v2l ^= BBUF[4] ^ BBUF[20];
    this.v2h ^= BBUF[5] ^ BBUF[21];
    this.v3l ^= BBUF[6] ^ BBUF[22];
    this.v3h ^= BBUF[7] ^ BBUF[23];
    this.v4l ^= BBUF[8] ^ BBUF[24];
    this.v4h ^= BBUF[9] ^ BBUF[25];
    this.v5l ^= BBUF[10] ^ BBUF[26];
    this.v5h ^= BBUF[11] ^ BBUF[27];
    this.v6l ^= BBUF[12] ^ BBUF[28];
    this.v6h ^= BBUF[13] ^ BBUF[29];
    this.v7l ^= BBUF[14] ^ BBUF[30];
    this.v7h ^= BBUF[15] ^ BBUF[31];
    clean(BBUF);
  }
  destroy(): void {
    this.destroyed = true;
    clean(this.buffer32);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
}

/**
 * Blake2b hash function. 64-bit. 1.5x slower than blake2s in JS.
 * @param msg - message that would be hashed
 * @param opts - dkLen output length, key for MAC mode, salt, personalization
 */
export const blake2b: CHashO = /* @__PURE__ */ createHashWithOpts<BLAKE2b, BlakeOpts>(
  (opts) => new BLAKE2b(opts)
);

// prettier-ignore
export type Num16 = {
  v0: number; v1: number; v2: number; v3: number;
  v4: number; v5: number; v6: number; v7: number;
  v8: number; v9: number; v10: number; v11: number;
  v12: number; v13: number; v14: number; v15: number;
};

// prettier-ignore
export function compress(s: Uint8Array, offset: number, msg: Uint32Array, rounds: number,
  v0: number, v1: number, v2: number, v3: number, v4: number, v5: number, v6: number, v7: number,
  v8: number, v9: number, v10: number, v11: number, v12: number, v13: number, v14: number, v15: number,
): Num16 {
  let j = 0;
  for (let i = 0; i < rounds; i++) {
    ({ a: v0, b: v4, c: v8, d: v12 } = G1s(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v0, b: v4, c: v8, d: v12 } = G2s(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G1s(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G2s(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G1s(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G2s(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G1s(v3, v7, v11, v15, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G2s(v3, v7, v11, v15, msg[offset + s[j++]]));

    ({ a: v0, b: v5, c: v10, d: v15 } = G1s(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v0, b: v5, c: v10, d: v15 } = G2s(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G1s(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G2s(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G1s(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G2s(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G1s(v3, v4, v9, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G2s(v3, v4, v9, v14, msg[offset + s[j++]]));
  }
  return { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 };
}

const keyLenS = 32;
const saltLenS = 8;
const persLenS = 8;
const B2S_IV = SHA256_IV;
export class BLAKE2s extends BLAKE<BLAKE2s> {
  // Internal state, same as SHA-256
  private v0 = B2S_IV[0] | 0;
  private v1 = B2S_IV[1] | 0;
  private v2 = B2S_IV[2] | 0;
  private v3 = B2S_IV[3] | 0;
  private v4 = B2S_IV[4] | 0;
  private v5 = B2S_IV[5] | 0;
  private v6 = B2S_IV[6] | 0;
  private v7 = B2S_IV[7] | 0;

  constructor(opts: BlakeOpts = {}) {
    super(64, opts.dkLen === undefined ? 32 : opts.dkLen, opts, keyLenS, saltLenS, persLenS);
    const { key, personalization, salt } = opts;
    const keyLength = key ? key.length : 0;
    this.v0 ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
    if (salt) {
      const slt = u32(toBytes(salt));
      this.v4 ^= byteSwapIfBE(slt[0]);
      this.v5 ^= byteSwapIfBE(slt[1]);
    }
    if (personalization) {
      const pers = u32(toBytes(personalization));
      this.v6 ^= byteSwapIfBE(pers[0]);
      this.v7 ^= byteSwapIfBE(pers[1]);
    }
    if (key) {
      // Pad to blockLen and update
      const k = toBytes(key);
      const tmp = new Uint8Array(this.blockLen);
      abytes(k);
      tmp.set(k);
      this.update(tmp);
    }
  }
  protected get(): [number, number, number, number, number, number, number, number] {
    const { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
    return [v0, v1, v2, v3, v4, v5, v6, v7];
  }
  // prettier-ignore
  protected set(
    v0: number, v1: number, v2: number, v3: number, v4: number, v5: number, v6: number, v7: number
  ): void {
    this.v0 = v0 | 0;
    this.v1 = v1 | 0;
    this.v2 = v2 | 0;
    this.v3 = v3 | 0;
    this.v4 = v4 | 0;
    this.v5 = v5 | 0;
    this.v6 = v6 | 0;
    this.v7 = v7 | 0;
  }
  protected compress(msg: Uint32Array, offset: number, isLast: boolean): void {
    const { h, l } = u64.fromBig(BigInt(this.length));
    // prettier-ignore
    const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } =
      compress(
        SIGMA, offset, msg, 10,
        this.v0, this.v1, this.v2, this.v3, this.v4, this.v5, this.v6, this.v7,
        B2S_IV[0], B2S_IV[1], B2S_IV[2], B2S_IV[3], l ^ B2S_IV[4], h ^ B2S_IV[5], isLast ? ~B2S_IV[6] : B2S_IV[6], B2S_IV[7]
      );
    this.v0 ^= v0 ^ v8;
    this.v1 ^= v1 ^ v9;
    this.v2 ^= v2 ^ v10;
    this.v3 ^= v3 ^ v11;
    this.v4 ^= v4 ^ v12;
    this.v5 ^= v5 ^ v13;
    this.v6 ^= v6 ^ v14;
    this.v7 ^= v7 ^ v15;
  }
  destroy(): void {
    this.destroyed = true;
    clean(this.buffer32);
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
  }
}

/**
 * Blake2s hash function. Focuses on 8-bit to 32-bit platforms. 1.5x faster than blake2b in JS.
 * @param msg - message that would be hashed
 * @param opts - dkLen output length, key for MAC mode, salt, personalization
 */
export const blake2s: CHashO = /* @__PURE__ */ createHashWithOpts<BLAKE2s, BlakeOpts>(
  (opts) => new BLAKE2s(opts)
);
