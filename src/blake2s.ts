import * as blake2 from './_blake2';
import { rotr, toBytes, wrapConstructor, u32 } from './utils';

// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19), same as SHA-256
// prettier-ignore
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

// Mixing function G splitted in two halfs
function G1(a: number, b: number, c: number, d: number, x: number) {
  a = (a + b + x) | 0;
  d = rotr(d ^ a, 16);
  c = (c + d) | 0;
  b = rotr(b ^ c, 12);
  return { a, b, c, d };
}

function G2(a: number, b: number, c: number, d: number, x: number) {
  a = (a + b + x) | 0;
  d = rotr(d ^ a, 8);
  c = (c + d) | 0;
  b = rotr(b ^ c, 7);
  return { a, b, c, d };
}

class Blake2S extends blake2.Blake2 {
  // Internal state, same as SHA-256
  private v0 = IV[0] | 0;
  private v1 = IV[1] | 0;
  private v2 = IV[2] | 0;
  private v3 = IV[3] | 0;
  private v4 = IV[4] | 0;
  private v5 = IV[5] | 0;
  private v6 = IV[6] | 0;
  private v7 = IV[7] | 0;

  constructor(opts: blake2.BlakeOpts) {
    super(64, opts.dkLen === undefined ? 32 : opts.dkLen, opts, 32, 8, 8);
    const keyLength = opts.key ? opts.key.length : 0;
    this.v0 ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
    if (opts.salt) {
      const salt = u32(toBytes(opts.salt));
      this.v4 ^= salt[0];
      this.v5 ^= salt[1];
    }
    if (opts.personalization) {
      const pers = u32(toBytes(opts.personalization));
      this.v6 ^= pers[0];
      this.v7 ^= pers[1];
    }
    if (opts.key) {
      // Pad to blockLen and update
      const tmp = new Uint8Array(this.blockLen);
      tmp.set(toBytes(opts.key));
      this.update(tmp);
    }
  }
  _get(): [number, number, number, number, number, number, number, number] {
    const { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
    return [v0, v1, v2, v3, v4, v5, v6, v7];
  }
  // prettier-ignore
  private _set(
    v0: number, v1: number, v2: number, v3: number, v4: number, v5: number, v6: number, v7: number
  ) {
    this.v0 = v0 | 0;
    this.v1 = v1 | 0;
    this.v2 = v2 | 0;
    this.v3 = v3 | 0;
    this.v4 = v4 | 0;
    this.v5 = v5 | 0;
    this.v6 = v6 | 0;
    this.v7 = v7 | 0;
  }
  _compress(msg: Uint32Array, offset: number, isLast: boolean) {
    // First half from state.
    let { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
    // Second half from IV.
    let v8 = IV[0] | 0;
    let v9 = IV[1] | 0;
    let v10 = IV[2] | 0;
    let v11 = IV[3] | 0;
    const len = BigInt(this.length);
    let v12 = IV[4] ^ Number(len & (2n ** 32n - 1n)); // Low word of the offset.
    let v13 = IV[5] ^ Number(len >> 32n); // High word.
    let v14 = IV[6] | 0;
    let v15 = IV[7] | 0;
    if (isLast) v14 = ~v14; // Invert all bits for last block
    for (let i = 0; i < 10; i++) {
      const s = blake2.SIGMA[i];
      let j = 0;
      ({ a: v0, b: v4, c: v8, d: v12 } = G1(v0, v4, v8, v12, msg[offset + s[j++]]));
      ({ a: v0, b: v4, c: v8, d: v12 } = G2(v0, v4, v8, v12, msg[offset + s[j++]]));
      ({ a: v1, b: v5, c: v9, d: v13 } = G1(v1, v5, v9, v13, msg[offset + s[j++]]));
      ({ a: v1, b: v5, c: v9, d: v13 } = G2(v1, v5, v9, v13, msg[offset + s[j++]]));
      ({ a: v2, b: v6, c: v10, d: v14 } = G1(v2, v6, v10, v14, msg[offset + s[j++]]));
      ({ a: v2, b: v6, c: v10, d: v14 } = G2(v2, v6, v10, v14, msg[offset + s[j++]]));
      ({ a: v3, b: v7, c: v11, d: v15 } = G1(v3, v7, v11, v15, msg[offset + s[j++]]));
      ({ a: v3, b: v7, c: v11, d: v15 } = G2(v3, v7, v11, v15, msg[offset + s[j++]]));

      ({ a: v0, b: v5, c: v10, d: v15 } = G1(v0, v5, v10, v15, msg[offset + s[j++]]));
      ({ a: v0, b: v5, c: v10, d: v15 } = G2(v0, v5, v10, v15, msg[offset + s[j++]]));
      ({ a: v1, b: v6, c: v11, d: v12 } = G1(v1, v6, v11, v12, msg[offset + s[j++]]));
      ({ a: v1, b: v6, c: v11, d: v12 } = G2(v1, v6, v11, v12, msg[offset + s[j++]]));
      ({ a: v2, b: v7, c: v8, d: v13 } = G1(v2, v7, v8, v13, msg[offset + s[j++]]));
      ({ a: v2, b: v7, c: v8, d: v13 } = G2(v2, v7, v8, v13, msg[offset + s[j++]]));
      ({ a: v3, b: v4, c: v9, d: v14 } = G1(v3, v4, v9, v14, msg[offset + s[j++]]));
      ({ a: v3, b: v4, c: v9, d: v14 } = G2(v3, v4, v9, v14, msg[offset + s[j++]]));
    }
    this.v0 ^= v0 ^ v8;
    this.v1 ^= v1 ^ v9;
    this.v2 ^= v2 ^ v10;
    this.v3 ^= v3 ^ v11;
    this.v4 ^= v4 ^ v12;
    this.v5 ^= v5 ^ v13;
    this.v6 ^= v6 ^ v14;
    this.v7 ^= v7 ^ v15;
  }
  clean() {
    this.buffer.fill(0);
    this._set(0, 0, 0, 0, 0, 0, 0, 0);
    this.cleaned = true;
  }
}

export const blake2s = wrapConstructor<blake2.BlakeOpts>((opts) => new Blake2S(opts));
