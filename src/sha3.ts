/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */
import { rotlBH, rotlBL, rotlSH, rotlSL, split } from './_u64.ts';
// prettier-ignore
import {
  abytes, aexists, anumber, aoutput,
  clean, createHasher,
  oidNist,
  swap32IfBE,
  u32,
  type CHash, type CHashXOF,
  type Hash,
  type HashInfo,
  type HashXOF
} from './utils.ts';

// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
const SHA3_PI: number[] = [];
const SHA3_ROTL: number[] = [];
const _SHA3_IOTA: bigint[] = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  // Pi
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  // Rotational
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  // Iota
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
    if (R & _2n) t ^= _1n << ((_1n << /* @__PURE__ */ BigInt(j)) - _1n);
  }
  _SHA3_IOTA.push(t);
}
const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];

// Left rotation (without 0, 32, 64)
const rotlH = (h: number, l: number, s: number) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (h: number, l: number, s: number) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));

/** `keccakf1600` internal function, additionally allows to adjust round count. */
export function keccakP(s: Uint32Array, rounds: number = 24): void {
  const B = new Uint32Array(5 * 2);
  // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
  for (let round = 24 - rounds; round < 24; round++) {
    // Theta θ
    for (let x = 0; x < 10; x++) B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    // Rho (ρ) and Pi (π)
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    // Chi (χ)
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++) B[x] = s[y + x];
      for (let x = 0; x < 10; x++) s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    // Iota (ι)
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}

/** Keccak sponge function. */
export class Keccak implements Hash<Keccak>, HashXOF<Keccak> {
  protected state: Uint8Array;
  protected pos = 0;
  protected posOut = 0;
  protected finished = false;
  protected state32: Uint32Array;
  protected destroyed = false;

  public blockLen: number;
  public suffix: number;
  public outputLen: number;
  protected enableXOF = false;
  protected rounds: number;

  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(
    blockLen: number,
    suffix: number,
    outputLen: number,
    enableXOF = false,
    rounds: number = 24
  ) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    // Can be passed from user as dkLen
    anumber(outputLen);
    // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
    // 0 < blockLen < 200
    if (!(0 < blockLen && blockLen < 200))
      throw new Error('only keccak-f1600 function is supported');
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone(): Keccak {
    return this._cloneInto();
  }
  protected keccak(): void {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data: Uint8Array): this {
    aexists(this);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++) state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen) this.keccak();
    }
    return this;
  }
  protected finish(): void {
    if (this.finished) return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    // Do the padding
    state[pos] ^= suffix;
    if ((suffix & 0x80) !== 0 && pos === blockLen - 1) this.keccak();
    state[blockLen - 1] ^= 0x80;
    this.keccak();
  }
  protected writeInto(out: Uint8Array): Uint8Array {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen) this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out: Uint8Array): Uint8Array {
    // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
    if (!this.enableXOF) throw new Error('XOF is not possible for this instance');
    return this.writeInto(out);
  }
  xof(bytes: number): Uint8Array {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out: Uint8Array): Uint8Array {
    aoutput(out, this);
    if (this.finished) throw new Error('digest() was already called');
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest(): Uint8Array {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy(): void {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to?: Keccak): Keccak {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    // Suffix can change in cSHAKE
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}

const gen = (suffix: number, blockLen: number, outputLen: number, info: HashInfo = {}) =>
  createHasher(() => new Keccak(blockLen, suffix, outputLen), info);

/** SHA3-224 hash function. */
export const sha3_224: CHash = /* @__PURE__ */ (() => gen(0x06, 144, 224 / 8, oidNist(0x07)))();
/** SHA3-256 hash function. Different from keccak-256. */
export const sha3_256: CHash = /* @__PURE__ */ (() => gen(0x06, 136, 256 / 8, oidNist(0x08)))();
/** SHA3-384 hash function. */
export const sha3_384: CHash = /* @__PURE__ */ (() => gen(0x06, 104, 384 / 8, oidNist(0x09)))();
/** SHA3-512 hash function. */
export const sha3_512: CHash = /* @__PURE__ */ (() => gen(0x06, 72, 512 / 8, oidNist(0x0a)))();

/** keccak-224 hash function. */
export const keccak_224: CHash = /* @__PURE__ */ (() => gen(0x01, 144, 224 / 8))();
/** keccak-256 hash function. Different from SHA3-256. */
export const keccak_256: CHash = /* @__PURE__ */ (() => gen(0x01, 136, 256 / 8))();
/** keccak-384 hash function. */
export const keccak_384: CHash = /* @__PURE__ */ (() => gen(0x01, 104, 384 / 8))();
/** keccak-512 hash function. */
export const keccak_512: CHash = /* @__PURE__ */ (() => gen(0x01, 72, 512 / 8))();

export type ShakeOpts = { dkLen?: number };

const genShake = (suffix: number, blockLen: number, outputLen: number, info: HashInfo = {}) =>
  createHasher<Keccak, ShakeOpts>(
    (opts: ShakeOpts = {}) =>
      new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true),
    info
  );

/** SHAKE128 XOF with 128-bit security. */
export const shake128: CHashXOF<Keccak, ShakeOpts> = /* @__PURE__ */ (() =>
  genShake(0x1f, 168, 128 / 8, oidNist(0x0b)))();
/** SHAKE256 XOF with 256-bit security. */
export const shake256: CHashXOF<Keccak, ShakeOpts> = /* @__PURE__ */ (() =>
  genShake(0x1f, 136, 256 / 8, oidNist(0x0c)))();

/** SHAKE128 XOF with 256-bit output (NIST version). */
export const shake128_32: CHashXOF<Keccak, ShakeOpts> = /* @__PURE__ */ (() =>
  genShake(0x1f, 168, 256 / 8, oidNist(0x0b)))();
/** SHAKE256 XOF with 512-bit output (NIST version). */
export const shake256_64: CHashXOF<Keccak, ShakeOpts> = /* @__PURE__ */ (() =>
  genShake(0x1f, 136, 512 / 8, oidNist(0x0c)))();
