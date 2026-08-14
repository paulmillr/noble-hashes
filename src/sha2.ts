/**
 * SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
 * SHA256 is the fastest hash implementable in JS, even faster than Blake3.
 * Check out {@link https://www.rfc-editor.org/rfc/rfc4634 | RFC 4634} and
 * {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | FIPS 180-4}.
 * @module
 */
import { HashMD, SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from './_md.ts';
import { pbkdf2Guard, pbkdf2Register, type Pbkdf2FastEngine } from './_pbkdf2.ts';
import * as u64 from './_u64.ts';
import {
  _wrapShortHash,
  type CHash,
  clean,
  createHasher,
  type Hash,
  oidNist,
  rotr,
  type TArg,
  type TRet,
} from './utils.ts';

/**
 * SHA-224 / SHA-256 round constants from RFC 6234 §5.1: the first 32 bits
 * of the cube roots of the first 64 primes (2..311).
 */
// prettier-ignore
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

/** Reusable 16-word rolling SHA-224 / SHA-256 message schedule. */
const SHA256_W = /* @__PURE__ */ new Uint32Array(16);

// Reuse the rolling schedule for short one-shot calls. Reentrant calls get private scratch; the
// schedule is wiped after every call, including exceptional exits.
let sha256OneShotBusy = false;

function setBig32(out: TArg<Uint8Array>, pos: number, word: number) {
  out[pos] = word >>> 24;
  out[pos + 1] = word >>> 16;
  out[pos + 2] = word >>> 8;
  out[pos + 3] = word;
}

// This stays outside the lease's try/finally: wrapping the hot loop in a finally region prevents
// V8 from optimizing it. The caller owns and wipes W.
function sha256OneShotCore(
  input: TArg<Uint8Array>,
  len: number,
  is224: boolean,
  W: TArg<Uint32Array>
): TRet<Uint8Array> {
  W.fill(0);
  let pos = 0;
  for (; pos + 4 <= len; pos += 4)
    W[pos >>> 2] =
      (input[pos] << 24) | (input[pos + 1] << 16) | (input[pos + 2] << 8) | input[pos + 3];
  let word = 0;
  let shift = 24;
  for (; pos < len; pos++, shift -= 8) word |= input[pos] << shift;
  W[pos >>> 2] = word | (0x80 << shift);
  W[15] = len * 8;

  // The exported IV tables are mutable for backwards compatibility; mirror the stateful
  // constructors by reading their current values for every call.
  const IV = is224 ? SHA224_IV : SHA256_IV;
  const A0 = IV[0] | 0;
  const B0 = IV[1] | 0;
  const C0 = IV[2] | 0;
  const D0 = IV[3] | 0;
  const E0 = IV[4] | 0;
  const F0 = IV[5] | 0;
  const G0 = IV[6] | 0;
  const H0 = IV[7] | 0;
  let A = A0;
  let B = B0;
  let C = C0;
  let D = D0;
  let E = E0;
  let F = F0;
  let G = G0;
  let H = H0;
  for (let i = 0; i < 64; i++) {
    const j = i & 15;
    if (i >= 16) {
      const W15 = W[(j + 1) & 15];
      const W2 = W[(j + 14) & 15];
      W[j] =
        ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
          W[(j + 9) & 15] +
          (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
          W[j]) |
        0;
    }
    const sigma1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
    const T1 = (H + sigma1 + (G ^ (E & (F ^ G))) + SHA256_K[i] + W[j]) | 0;
    const sigma0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
    const T2 = (sigma0 + ((A & B) ^ (C & (A ^ B)))) | 0;
    H = G;
    G = F;
    F = E;
    E = (D + T1) | 0;
    D = C;
    C = B;
    B = A;
    A = (T1 + T2) | 0;
  }

  const out = new Uint8Array(is224 ? 28 : 32);
  setBig32(out, 0, (A + A0) | 0);
  setBig32(out, 4, (B + B0) | 0);
  setBig32(out, 8, (C + C0) | 0);
  setBig32(out, 12, (D + D0) | 0);
  setBig32(out, 16, (E + E0) | 0);
  setBig32(out, 20, (F + F0) | 0);
  setBig32(out, 24, (G + G0) | 0);
  if (!is224) setBig32(out, 28, (H + H0) | 0);
  return out as TRet<Uint8Array>;
}

// Messages of 56..119 bytes always require exactly two padded blocks. Keep this separate from
// the one-block core: making the hot tiny-input function handle both geometries cuts its V8 and
// SpiderMonkey throughput even after both branches have tiered up.
function sha256TwoBlockCore(
  input: TArg<Uint8Array>,
  len: number,
  is224: boolean,
  W: TArg<Uint32Array>
): TRet<Uint8Array> {
  const IV = is224 ? SHA224_IV : SHA256_IV;
  let A = IV[0] | 0;
  let B = IV[1] | 0;
  let C = IV[2] | 0;
  let D = IV[3] | 0;
  let E = IV[4] | 0;
  let F = IV[5] | 0;
  let G = IV[6] | 0;
  let H = IV[7] | 0;
  for (let block = 0; block < 2; block++) {
    W.fill(0);
    const start = block * 64;
    const blockLen = Math.min(64, Math.max(0, len - start));
    let pos = 0;
    for (; pos + 4 <= blockLen; pos += 4) {
      const offset = start + pos;
      W[pos >>> 2] =
        (input[offset] << 24) |
        (input[offset + 1] << 16) |
        (input[offset + 2] << 8) |
        input[offset + 3];
    }
    let word = 0;
    let shift = 24;
    for (; pos < blockLen; pos++, shift -= 8) word |= input[start + pos] << shift;
    // For 56..63 bytes the terminator is in block zero and block one contains only the length.
    // At 64 bytes the terminator starts block one; 65..119 append it after their second-block tail.
    if (len >= start && blockLen < 64) W[pos >>> 2] = word | (0x80 << shift);
    if (block === 1) W[15] = len * 8;

    const A0 = A;
    const B0 = B;
    const C0 = C;
    const D0 = D;
    const E0 = E;
    const F0 = F;
    const G0 = G;
    const H0 = H;
    for (let i = 0; i < 64; i++) {
      const j = i & 15;
      if (i >= 16) {
        const W15 = W[(j + 1) & 15];
        const W2 = W[(j + 14) & 15];
        W[j] =
          ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
            W[(j + 9) & 15] +
            (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
            W[j]) |
          0;
      }
      const sigma1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
      const T1 = (H + sigma1 + (G ^ (E & (F ^ G))) + SHA256_K[i] + W[j]) | 0;
      const sigma0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
      const T2 = (sigma0 + ((A & B) ^ (C & (A ^ B)))) | 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) | 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) | 0;
    }
    A = (A + A0) | 0;
    B = (B + B0) | 0;
    C = (C + C0) | 0;
    D = (D + D0) | 0;
    E = (E + E0) | 0;
    F = (F + F0) | 0;
    G = (G + G0) | 0;
    H = (H + H0) | 0;
  }

  const out = new Uint8Array(is224 ? 28 : 32);
  setBig32(out, 0, A);
  setBig32(out, 4, B);
  setBig32(out, 8, C);
  setBig32(out, 12, D);
  setBig32(out, 16, E);
  setBig32(out, 20, F);
  setBig32(out, 24, G);
  if (!is224) setBig32(out, 28, H);
  return out as TRet<Uint8Array>;
}

function sha256HashOneShot(input: TArg<Uint8Array>, len: number, is224: boolean): TRet<Uint8Array> {
  const W = sha256OneShotBusy ? new Uint32Array(16) : SHA256_W;
  const shared = W === SHA256_W;
  if (shared) sha256OneShotBusy = true;
  try {
    return len <= 55
      ? sha256OneShotCore(input, len, is224, W)
      : sha256TwoBlockCore(input, len, is224, W);
  } finally {
    clean(W);
    if (shared) sha256OneShotBusy = false;
  }
}

function sha256Wrap<T extends Hash<T>>(
  stateful: TArg<TRet<CHash<T>>>,
  is224: boolean
): TRet<CHash<T>> {
  return _wrapShortHash(stateful, 119, (input: TArg<Uint8Array>, len: number) =>
    sha256HashOneShot(input, len, is224)
  );
}

/** Internal SHA-224 / SHA-256 compression engine from RFC 6234 §6.2. */
abstract class SHA2_32B<T extends SHA2_32B<T>> extends HashMD<T> {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and makes sha256 3x slower (measured).
  protected A = 0;
  protected B = 0;
  protected C = 0;
  protected D = 0;
  protected E = 0;
  protected F = 0;
  protected G = 0;
  protected H = 0;

  constructor(outputLen: number, IV: Uint32Array) {
    super(64, outputLen, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  protected get(): [number, number, number, number, number, number, number, number] {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  protected set(
    A: number, B: number, C: number, D: number, E: number, F: number, G: number, H: number
  ): void {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to?: T): T {
    (to ||= new (this.constructor as any)() as T).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  protected process(view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
    let { A, B, C, D, E, F, G, H } = this;
    let T1 = 0;
    let T2 = 0;
    // A 16-word ring avoids materializing the full 64-word schedule. Two straight rounds keep
    // loop overhead low without the register-pressure cliffs of wider unrolling.
    for (let i = 0; i < 64; i += 2) {
      const j = i & 15;
      if (i >= 16) {
        const W15 = SHA256_W[(j + 1) & 15];
        const W2 = SHA256_W[(j + 14) & 15];
        SHA256_W[j] =
          ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
            SHA256_W[(j + 9) & 15] +
            (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
            SHA256_W[j]) |
          0;
      }
      T1 =
        (H +
          (rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25)) +
          (G ^ (E & (F ^ G))) +
          SHA256_K[i] +
          SHA256_W[j]) |
        0;
      T2 = ((rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + ((A & B) ^ (C & (A ^ B)))) | 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) | 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) | 0;

      const j1 = (i + 1) & 15;
      if (i >= 16) {
        const W15 = SHA256_W[(j1 + 1) & 15];
        const W2 = SHA256_W[(j1 + 14) & 15];
        SHA256_W[j1] =
          ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
            SHA256_W[(j1 + 9) & 15] +
            (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
            SHA256_W[j1]) |
          0;
      }
      T1 =
        (H +
          (rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25)) +
          (G ^ (E & (F ^ G))) +
          SHA256_K[i + 1] +
          SHA256_W[j1]) |
        0;
      T2 = ((rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + ((A & B) ^ (C & (A ^ B)))) | 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) | 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) | 0;
    }
    // Add the compressed chunk to the current hash value
    A = (A + this.A) | 0;
    B = (B + this.B) | 0;
    C = (C + this.C) | 0;
    D = (D + this.D) | 0;
    E = (E + this.E) | 0;
    F = (F + this.F) | 0;
    G = (G + this.G) | 0;
    H = (H + this.H) | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  protected roundClean(): void {
    clean(SHA256_W);
  }
  destroy(): void {
    // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves
    // update()/digest() callable on reused instances.
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
}

/** Internal SHA-256 hash class grounded in RFC 6234 §6.2. */
export class _SHA256 extends SHA2_32B<_SHA256> {
  constructor() {
    super(32, SHA256_IV);
  }
}

/** Internal SHA-224 hash class grounded in RFC 6234 §6.2 and §8.5. */
export class _SHA224 extends SHA2_32B<_SHA224> {
  constructor() {
    super(28, SHA224_IV);
  }
}

// PBKDF2-HMAC-SHA256 U2..Uc always compresses the same padded 32-byte geometry. Keep a dedicated
// numeric core: the digest words feed the next HMAC directly and T is serialized only once.
function pbkdf2Wipe(...arrays: TArg<Uint32Array[]>): void {
  for (const array of arrays) for (let i = 0; i < array.length; i++) array[i] = 0;
}

function sha256Pbkdf2Compressor(W: TArg<Uint32Array>) {
  return (mid: TArg<Uint32Array>, msg: TArg<Uint32Array>, out: TArg<Uint32Array>) => {
    W[0] = msg[0];
    W[1] = msg[1];
    W[2] = msg[2];
    W[3] = msg[3];
    W[4] = msg[4];
    W[5] = msg[5];
    W[6] = msg[6];
    W[7] = msg[7];
    W[8] = 0x80000000;
    W[9] = W[10] = W[11] = W[12] = W[13] = W[14] = 0;
    // (64-byte HMAC pad + 32-byte digest) * 8
    W[15] = 768;
    let A = mid[0] | 0;
    let B = mid[1] | 0;
    let C = mid[2] | 0;
    let D = mid[3] | 0;
    let E = mid[4] | 0;
    let F = mid[5] | 0;
    let G = mid[6] | 0;
    let H = mid[7] | 0;
    for (let i = 0; i < 64; i += 2) {
      let j = i & 15;
      if (i >= 16) {
        const W15 = W[(j + 1) & 15];
        const W2 = W[(j + 14) & 15];
        W[j] =
          ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
            W[(j + 9) & 15] +
            (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
            W[j]) |
          0;
      }
      let T1 =
        (H + (rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25)) + (G ^ (E & (F ^ G))) + SHA256_K[i] + W[j]) |
        0;
      let T2 = ((rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + ((A & B) ^ (C & (A ^ B)))) | 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) | 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) | 0;

      j = (i + 1) & 15;
      if (i >= 16) {
        const W15 = W[(j + 1) & 15];
        const W2 = W[(j + 14) & 15];
        W[j] =
          ((rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10)) +
            W[(j + 9) & 15] +
            (rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3)) +
            W[j]) |
          0;
      }
      T1 =
        (H +
          (rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25)) +
          (G ^ (E & (F ^ G))) +
          SHA256_K[i + 1] +
          W[j]) |
        0;
      T2 = ((rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + ((A & B) ^ (C & (A ^ B)))) | 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) | 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) | 0;
    }
    out[0] = A + mid[0];
    out[1] = B + mid[1];
    out[2] = C + mid[2];
    out[3] = D + mid[3];
    out[4] = E + mid[4];
    out[5] = F + mid[5];
    out[6] = G + mid[6];
    out[7] = H + mid[7];
  };
}

function sha256Pbkdf2Factory() {
  const proto = _SHA256.prototype as any;
  const valid = pbkdf2Guard(proto, [
    '_cloneInto',
    '_cloneIntoMeta',
    'update',
    'digestInto',
    'destroy',
    'process',
    'roundClean',
    'get',
    'set',
    'constructor',
  ]);
  return (iHash: any, oHash: any): TRet<Pbkdf2FastEngine | undefined> => {
    if (!valid(iHash) || !valid(oHash)) return;
    const read = (hash: any) =>
      Uint32Array.of(hash.A, hash.B, hash.C, hash.D, hash.E, hash.F, hash.G, hash.H);
    const write = (out: TArg<Uint8Array>, words: TArg<Uint32Array>) => {
      for (let pos = 0; pos < out.length; pos += 4) setBig32(out, pos, words[pos >>> 2]);
    };
    const iState = read(iHash);
    const oState = read(oHash);
    const state = new Uint32Array(8);
    const inner = new Uint32Array(8);
    const T = new Uint32Array(8);
    // Per-call scratch: async calls never share secret schedule data.
    const W = new Uint32Array(16);
    const compress = sha256Pbkdf2Compressor(W);
    return {
      valid: () => valid(iHash) && valid(oHash),
      start(u: TArg<Uint8Array>) {
        for (let i = 0; i < 8; i++) {
          const pos = i * 4;
          state[i] = T[i] = (u[pos] << 24) | (u[pos + 1] << 16) | (u[pos + 2] << 8) | u[pos + 3];
        }
      },
      rounds(count: number) {
        for (let r = 0; r < count; r++) {
          compress(iState, state, inner);
          compress(oState, inner, state);
          T[0] ^= state[0];
          T[1] ^= state[1];
          T[2] ^= state[2];
          T[3] ^= state[3];
          T[4] ^= state[4];
          T[5] ^= state[5];
          T[6] ^= state[6];
          T[7] ^= state[7];
        }
        pbkdf2Wipe(W); // Async yields only after this method returns.
      },
      snapshot(u: TArg<Uint8Array>, out: TArg<Uint8Array>) {
        write(u, state);
        write(out, T);
      },
      finish(out: TArg<Uint8Array>) {
        write(out, T);
      },
      destroy() {
        pbkdf2Wipe(iState, oState, state, inner, T, W);
      },
    };
  };
}

// SHA2-512 is slower than sha256 in js because u64 operations are slow.

// BEGIN generated SHA-512 constants
// Generated by test/misc/sha2-constants.js from the FIPS 180-4 cube-root definition.
// prettier-ignore
const SHA512_Kh = /* @__PURE__ */ Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
  0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
]);
// prettier-ignore
const SHA512_Kl = /* @__PURE__ */ Uint32Array.from([
  0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
  0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
  0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
  0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
  0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
  0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
  0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
  0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
  0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
  0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
]);
// END generated SHA-512 constants

// Reusable high-half schedule buffer for the RFC 6234 §6.4 64-bit `W_t` words.
const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
// Reusable low-half schedule buffer for the RFC 6234 §6.4 64-bit `W_t` words.
const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);

/** Internal SHA-384 / SHA-512 compression engine from RFC 6234 §6.4. */
abstract class SHA2_64B<T extends SHA2_64B<T>> extends HashMD<T> {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // h -- high 32 bits, l -- low 32 bits
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and slows hashing down (measured on sha256).
  protected Ah = 0;
  protected Al = 0;
  protected Bh = 0;
  protected Bl = 0;
  protected Ch = 0;
  protected Cl = 0;
  protected Dh = 0;
  protected Dl = 0;
  protected Eh = 0;
  protected El = 0;
  protected Fh = 0;
  protected Fl = 0;
  protected Gh = 0;
  protected Gl = 0;
  protected Hh = 0;
  protected Hl = 0;

  constructor(outputLen: number, IV: Uint32Array) {
    super(128, outputLen, 16, false);
    this.Ah = IV[0] | 0;
    this.Al = IV[1] | 0;
    this.Bh = IV[2] | 0;
    this.Bl = IV[3] | 0;
    this.Ch = IV[4] | 0;
    this.Cl = IV[5] | 0;
    this.Dh = IV[6] | 0;
    this.Dl = IV[7] | 0;
    this.Eh = IV[8] | 0;
    this.El = IV[9] | 0;
    this.Fh = IV[10] | 0;
    this.Fl = IV[11] | 0;
    this.Gh = IV[12] | 0;
    this.Gl = IV[13] | 0;
    this.Hh = IV[14] | 0;
    this.Hl = IV[15] | 0;
  }
  // prettier-ignore
  protected get(): [
    number, number, number, number, number, number, number, number,
    number, number, number, number, number, number, number, number
  ] {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  protected set(
    Ah: number, Al: number, Bh: number, Bl: number, Ch: number, Cl: number, Dh: number, Dl: number,
    Eh: number, El: number, Fh: number, Fl: number, Gh: number, Gl: number, Hh: number, Hl: number
  ): void {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  _cloneInto(to?: T): T {
    (to ||= new (this.constructor as any)() as T).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  protected process(view: DataView, offset: number): void {
    // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32((offset += 4));
    }
    for (let i = 16; i < 80; i++) {
      // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
      const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
      // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
      const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
      // SHA512_W[i] = s0 + s1 + SHA512_W[i - 7] + SHA512_W[i - 16];
      const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    // Compression function main loop, 80 rounds
    for (let i = 0; i < 80; i++) {
      // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
      const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
      const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
      //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
      const CHIh = (Eh & Fh) ^ (~Eh & Gh);
      const CHIl = (El & Fl) ^ (~El & Gl);
      // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
      // prettier-ignore
      const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
      const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
      const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
      const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
      const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = u64.add3L(T1l, sigma0l, MAJl);
      Ah = u64.add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    // Add the compressed chunk to the current hash value
    ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  protected roundClean(): void {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy(): void {
    // HashMD callers route post-destroy usability through `destroyed`; zeroizing alone still leaves
    // update()/digest() callable on reused instances.
    this.destroyed = true;
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
}

/** Internal SHA-512 hash class grounded in RFC 6234 §6.3 and §6.4. */
export class _SHA512 extends SHA2_64B<_SHA512> {
  constructor() {
    super(64, SHA512_IV);
  }
}

function sha512Pbkdf2Compressor(Wh: TArg<Uint32Array>, Wl: TArg<Uint32Array>) {
  return (mid: TArg<Uint32Array>, msg: TArg<Uint32Array>, out: TArg<Uint32Array>) => {
    for (let i = 0; i < 8; i++) {
      Wh[i] = msg[i * 2];
      Wl[i] = msg[i * 2 + 1];
    }
    Wh[8] = 0x80000000;
    Wl[8] = 0;
    for (let i = 9; i < 15; i++) Wh[i] = Wl[i] = 0;
    Wh[15] = 0;
    Wl[15] = 1536; // (128-byte HMAC pad + 64-byte digest) * 8
    let Ah = mid[0] | 0;
    let Al = mid[1] | 0;
    let Bh = mid[2] | 0;
    let Bl = mid[3] | 0;
    let Ch = mid[4] | 0;
    let Cl = mid[5] | 0;
    let Dh = mid[6] | 0;
    let Dl = mid[7] | 0;
    let Eh = mid[8] | 0;
    let El = mid[9] | 0;
    let Fh = mid[10] | 0;
    let Fl = mid[11] | 0;
    let Gh = mid[12] | 0;
    let Gl = mid[13] | 0;
    let Hh = mid[14] | 0;
    let Hl = mid[15] | 0;
    for (let i = 0; i < 80; i++) {
      const j = i & 15;
      if (i >= 16) {
        const W15h = Wh[(j + 1) & 15] | 0;
        const W15l = Wl[(j + 1) & 15] | 0;
        const s0h =
          u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
        const s0l =
          u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
        const W2h = Wh[(j + 14) & 15] | 0;
        const W2l = Wl[(j + 14) & 15] | 0;
        const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
        const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
        const suml = u64.add4L(s0l, s1l, Wl[(j + 9) & 15], Wl[j]);
        Wh[j] = u64.add4H(suml, s0h, s1h, Wh[(j + 9) & 15], Wh[j]);
        Wl[j] = suml;
      }
      const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
      const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
      const ch = Gh ^ (Eh & (Fh ^ Gh));
      const cl = Gl ^ (El & (Fl ^ Gl));
      const T1ll = u64.add5L(Hl, sigma1l, cl, SHA512_Kl[i], Wl[j]);
      const T1h = u64.add5H(T1ll, Hh, sigma1h, ch, SHA512_Kh[i], Wh[j]);
      const T1l = T1ll | 0;
      const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
      const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
      const majh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
      const majl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
      Hh = Gh;
      Hl = Gl;
      Gh = Fh;
      Gl = Fl;
      Fh = Eh;
      Fl = El;
      const Ell = u64.add3L(Dl, T1l, 0);
      Eh = u64.add3H(Ell, Dh, T1h, 0);
      El = Ell | 0;
      Dh = Ch;
      Dl = Cl;
      Ch = Bh;
      Cl = Bl;
      Bh = Ah;
      Bl = Al;
      const All = u64.add3L(T1l, sigma0l, majl);
      Ah = u64.add3H(All, T1h, sigma0h, majh);
      Al = All | 0;
    }
    out[0] = Ah;
    out[1] = Al;
    out[2] = Bh;
    out[3] = Bl;
    out[4] = Ch;
    out[5] = Cl;
    out[6] = Dh;
    out[7] = Dl;
    out[8] = Eh;
    out[9] = El;
    out[10] = Fh;
    out[11] = Fl;
    out[12] = Gh;
    out[13] = Gl;
    out[14] = Hh;
    out[15] = Hl;
    for (let i = 0; i < 16; i += 2) {
      const low = (mid[i + 1] >>> 0) + (out[i + 1] >>> 0);
      out[i] = (mid[i] + out[i] + ((low / 2 ** 32) | 0)) | 0;
      out[i + 1] = low | 0;
    }
  };
}

function sha512Pbkdf2Factory() {
  const proto = _SHA512.prototype as any;
  const valid = pbkdf2Guard(proto, [
    '_cloneInto',
    '_cloneIntoMeta',
    'update',
    'digestInto',
    'destroy',
    'process',
    'roundClean',
    'get',
    'set',
    'constructor',
  ]);
  return (iHash: any, oHash: any): TRet<Pbkdf2FastEngine | undefined> => {
    if (!valid(iHash) || !valid(oHash)) return;
    const read = (hash: any) =>
      Uint32Array.of(
        hash.Ah,
        hash.Al,
        hash.Bh,
        hash.Bl,
        hash.Ch,
        hash.Cl,
        hash.Dh,
        hash.Dl,
        hash.Eh,
        hash.El,
        hash.Fh,
        hash.Fl,
        hash.Gh,
        hash.Gl,
        hash.Hh,
        hash.Hl
      );
    const write = (out: TArg<Uint8Array>, words: TArg<Uint32Array>) => {
      for (let pos = 0; pos < out.length; pos += 4) setBig32(out, pos, words[pos >>> 2]);
    };
    const iState = read(iHash);
    const oState = read(oHash);
    const state = new Uint32Array(16);
    const inner = new Uint32Array(16);
    const T = new Uint32Array(16);
    const Wh = new Uint32Array(16);
    const Wl = new Uint32Array(16);
    const compress = sha512Pbkdf2Compressor(Wh, Wl);
    return {
      valid: () => valid(iHash) && valid(oHash),
      start(u: TArg<Uint8Array>) {
        for (let i = 0; i < 16; i++) {
          const pos = i * 4;
          state[i] = T[i] = (u[pos] << 24) | (u[pos + 1] << 16) | (u[pos + 2] << 8) | u[pos + 3];
        }
      },
      rounds(count: number) {
        for (let r = 0; r < count; r++) {
          compress(iState, state, inner);
          compress(oState, inner, state);
          for (let i = 0; i < 16; i++) T[i] ^= state[i];
        }
        pbkdf2Wipe(Wh, Wl);
      },
      snapshot(u: TArg<Uint8Array>, out: TArg<Uint8Array>) {
        write(u, state);
        write(out, T);
      },
      finish(out: TArg<Uint8Array>) {
        write(out, T);
      },
      destroy() {
        pbkdf2Wipe(iState, oState, state, inner, T, Wh, Wl);
      },
    };
  };
}

/** Internal SHA-384 hash class grounded in RFC 6234 §6.3 and §6.4. */
export class _SHA384 extends SHA2_64B<_SHA384> {
  constructor() {
    super(48, SHA384_IV);
  }
}

/**
 * Truncated SHA512/256 and SHA512/224.
 * SHA512_IV is XORed with 0xa5a5a5a5a5a5a5a5, then used as "intermediary" IV of SHA512/t.
 * Then t hashes string to produce result IV.
 * See the repo-side derivation recipe in `test/misc/sha2-gen-iv.js`.
 * These IV literals are checked against that script rather than a dedicated
 * local RFC section.
 */

/** SHA-512/224 IV derived by the SHA-512/t recipe in `test/misc/sha2-gen-iv.js` and
 * stored as sixteen big-endian 32-bit halves. */
const T224_IV = /* @__PURE__ */ Uint32Array.from([
  0x8c3d37c8, 0x19544da2, 0x73e19966, 0x89dcd4d6, 0x1dfab7ae, 0x32ff9c82, 0x679dd514, 0x582f9fcf,
  0x0f6d2b69, 0x7bd44da8, 0x77e36f73, 0x04c48942, 0x3f9d85a8, 0x6a1d36c8, 0x1112e6ad, 0x91d692a1,
]);

/** SHA-512/256 IV derived by the SHA-512/t recipe in `test/misc/sha2-gen-iv.js` and
 * stored as sixteen big-endian 32-bit halves. */
const T256_IV = /* @__PURE__ */ Uint32Array.from([
  0x22312194, 0xfc2bf72c, 0x9f555fa3, 0xc84c64c2, 0x2393b86b, 0x6f53b151, 0x96387719, 0x5940eabd,
  0x96283ee2, 0xa88effe3, 0xbe5e1e25, 0x53863992, 0x2b0199fc, 0x2c85b8aa, 0x0eb72ddc, 0x81c52ca2,
]);

/** Internal SHA-512/224 hash class using the derived `T224_IV` and the shared
 * RFC 6234 §6.4 compression engine. */
export class _SHA512_224 extends SHA2_64B<_SHA512_224> {
  constructor() {
    super(28, T224_IV);
  }
}

/** Internal SHA-512/256 hash class using the derived `T256_IV` and the shared
 * RFC 6234 §6.4 compression engine. */
export class _SHA512_256 extends SHA2_64B<_SHA512_256> {
  constructor() {
    super(32, T256_IV);
  }
}

/**
 * SHA2-256 hash function from RFC 4634. In JS it's the fastest: even faster than Blake3. Some info:
 *
 * - Trying 2^128 hashes would get 50% chance of collision, using birthday attack.
 * - BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
 * - Each sha256 hash is executing 2^18 bit operations.
 * - Good 2024 ASICs can do 200Th/sec with 3500 watts of power, corresponding to 2^36 hashes/joule.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-256.
 * ```ts
 * sha256(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha256: TRet<CHash<_SHA256>> = /* @__PURE__ */ pbkdf2Register(
  /* @__PURE__ */ sha256Wrap(
    /* @__PURE__ */ createHasher(() => new _SHA256(), /* @__PURE__ */ oidNist(0x01)),
    false
  ),
  /* @__PURE__ */ sha256Pbkdf2Factory()
);
/**
 * SHA2-224 hash function from RFC 4634.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-224.
 * ```ts
 * sha224(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha224: TRet<CHash<_SHA224>> = /* @__PURE__ */ sha256Wrap(
  /* @__PURE__ */ createHasher(() => new _SHA224(), /* @__PURE__ */ oidNist(0x04)),
  true
);

/**
 * SHA2-512 hash function from RFC 4634.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-512.
 * ```ts
 * sha512(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha512: TRet<CHash<_SHA512>> = /* @__PURE__ */ pbkdf2Register(
  /* @__PURE__ */ createHasher(() => new _SHA512(), /* @__PURE__ */ oidNist(0x03)),
  /* @__PURE__ */ sha512Pbkdf2Factory()
);
/**
 * SHA2-384 hash function from RFC 4634.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-384.
 * ```ts
 * sha384(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha384: TRet<CHash<_SHA384>> = /* @__PURE__ */ createHasher(
  () => new _SHA384(),
  /* @__PURE__ */ oidNist(0x02)
);

/**
 * SHA2-512/256 "truncated" hash function, with improved resistance to length extension attacks.
 * See the paper on {@link https://eprint.iacr.org/2010/548.pdf | truncated SHA512}.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-512/256.
 * ```ts
 * sha512_256(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha512_256: TRet<CHash<_SHA512_256>> = /* @__PURE__ */ createHasher(
  () => new _SHA512_256(),
  /* @__PURE__ */ oidNist(0x06)
);
/**
 * SHA2-512/224 "truncated" hash function, with improved resistance to length extension attacks.
 * See the paper on {@link https://eprint.iacr.org/2010/548.pdf | truncated SHA512}.
 * @param msg - message bytes to hash
 * @param opts - Reserved hash options.
 * @returns Digest bytes.
 * @example
 * Hash a message with SHA2-512/224.
 * ```ts
 * sha512_224(new Uint8Array([97, 98, 99]));
 * ```
 */
export const sha512_224: TRet<CHash<_SHA512_224>> = /* @__PURE__ */ createHasher(
  () => new _SHA512_224(),
  /* @__PURE__ */ oidNist(0x05)
);
