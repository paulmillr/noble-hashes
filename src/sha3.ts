import * as u64 from './_u64';
import {
  Hash,
  u32,
  Input,
  toBytes,
  wrapConstructor,
  wrapConstructorWithOpts,
  assertNumber,
} from './utils';

// Various per round constants calculations
const [SHA3_PI, SHA3_ROTL, _SHA3_IOTA]: [number[], number[], bigint[]] = [[], [], []];
for (let round = 0, R = 1n, x = 1, y = 0; round < 24; round++) {
  // Pi
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  // Rotational
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  // Iota
  let t = 0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << 1n) ^ ((R >> 7n) * 0x71n)) % 256n;
    if (R & 2n) t ^= 1n << ((1n << BigInt(j)) - 1n);
  }
  _SHA3_IOTA.push(t);
}
const [SHA3_IOTA_H, SHA3_IOTA_L] = u64.split(_SHA3_IOTA, true);

// Left rotation (without 0, 32, 64)
const rotlH = (h: number, l: number, s: number) =>
  s > 32 ? u64.rotlBH(h, l, s) : u64.rotlSH(h, l, s);
const rotlL = (h: number, l: number, s: number) =>
  s > 32 ? u64.rotlBL(h, l, s) : u64.rotlSL(h, l, s);

// Same as keccakf1600, but allows to skip some rounds
function keccakP(s: Uint32Array, rounds: number = 24) {
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
  B.fill(0);
}

export class Keccak extends Hash<Keccak> {
  protected state: Uint8Array;
  private pos = 0;
  protected finished = false;
  protected state32: Uint32Array;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(
    public blockLen: number,
    public suffix: number,
    public outputLen: number,
    private rounds: number = 24
  ) {
    super();
    // Can be passed from user as dkLen
    assertNumber(outputLen);
    // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
    if (0 >= this.blockLen || this.blockLen >= 200)
      throw new Error('Sha3 supports only keccak-f1600 function');
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  private keccak() {
    keccakP(this.state32, this.rounds);
  }
  update(data: Input) {
    const { blockLen, state, finished } = this;
    if (finished) throw new Error('digest() was already called');
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++) state[this.pos++] ^= data[pos++];
      if (this.pos !== blockLen) continue;
      this.keccak();
      this.pos = 0;
    }
    return this;
  }
  _writeDigest(out: Uint8Array) {
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    const { state, suffix, pos, blockLen, outputLen } = this;
    // Do the padding
    state[pos] ^= suffix;
    if ((suffix & 0x80) !== 0 && pos === blockLen - 1) this.keccak();
    state[blockLen - 1] ^= 0x80;
    this.keccak();
    // Squeeze
    for (let left = outputLen, outPos = 0; left > 0; ) {
      const chunk = Math.min(left, this.blockLen);
      out.set(this.state.subarray(0, chunk), outPos);
      left -= chunk;
      outPos += chunk;
      if (left) this.keccak();
    }
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this._writeDigest(out);
    this._clean();
    return out;
  }
  _clean() {
    this.state.fill(0);
  }
  _cloneInto(to?: Keccak): Keccak {
    const { blockLen, suffix, outputLen, rounds, state, pos, finished } = this;
    to ||= new Keccak(blockLen, suffix, outputLen, rounds);
    to.state.set(state);
    to.pos = pos;
    to.finished = finished;
    // Suffix can change in cSHAKE
    to.suffix = suffix;
    to.outputLen = outputLen;
    return to;
  }
}

const gen = (suffix: number, blockLen: number, outputLen: number) =>
  wrapConstructor(() => new Keccak(blockLen, suffix, outputLen));

export const sha3_224 = gen(0x06, 144, 224 / 8);
export const sha3_256 = gen(0x06, 136, 256 / 8);
export const sha3_384 = gen(0x06, 104, 384 / 8);
export const sha3_512 = gen(0x06, 72, 512 / 8);
export const keccak_224 = gen(0x01, 144, 224 / 8);
export const keccak_256 = gen(0x01, 136, 256 / 8);
export const keccak_384 = gen(0x01, 104, 384 / 8);
export const keccak_512 = gen(0x01, 72, 512 / 8);

export type ShakeOpts = { dkLen?: number };

const genShake = (suffix: number, blockLen: number, outputLen: number) =>
  wrapConstructorWithOpts<Keccak, ShakeOpts>(
    (opts?: ShakeOpts) =>
      new Keccak(blockLen, suffix, opts?.dkLen !== undefined ? opts.dkLen : outputLen)
  );

export const shake128 = genShake(0x1f, 168, 128 / 8);
export const shake256 = genShake(0x1f, 136, 256 / 8);
