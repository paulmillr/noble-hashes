/**
 * SHA3 (keccak) addons.
 *
 * * cSHAKE, KMAC, TupleHash, ParallelHash + XOF variants from
 *   [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
 * * KangarooTwelve 🦘 and TurboSHAKE - reduced-round keccak from
 *   [k12-draft-17](https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/17/)
 * * KeccakPRG: Pseudo-random generator based on Keccak [(pdf)](https://keccak.team/files/CSF-0.1.pdf)
 * @module
 */
import { Keccak, type ShakeOpts } from './sha3.ts';
import {
  abytes,
  anumber,
  type CHash,
  type CHashXOF,
  createHasher,
  type Hash,
  type HashXOF,
  type KDFInput,
  kdfInputToBytes,
  type PRG,
  u32,
} from './utils.ts';

// cSHAKE && KMAC (NIST SP800-185)
const _8n = /* @__PURE__ */ BigInt(8);
const _ffn = /* @__PURE__ */ BigInt(0xff);

// It is safe to use bigints here, since they used only for length encoding (not actual data).
// We use bigints in sha256 for lengths too.
function leftEncode(n: number | bigint): Uint8Array {
  n = BigInt(n);
  const res = [Number(n & _ffn)];
  n >>= _8n;
  for (; n > 0; n >>= _8n) res.unshift(Number(n & _ffn));
  res.unshift(res.length);
  return new Uint8Array(res);
}

function rightEncode(n: number | bigint): Uint8Array {
  n = BigInt(n);
  const res = [Number(n & _ffn)];
  n >>= _8n;
  for (; n > 0; n >>= _8n) res.unshift(Number(n & _ffn));
  res.push(res.length);
  return new Uint8Array(res);
}

function chooseLen(opts: ShakeOpts, outputLen: number): number {
  return opts.dkLen === undefined ? outputLen : opts.dkLen;
}

const abytesOrZero = (buf?: Uint8Array) => {
  if (buf === undefined) return EMPTY_BUFFER;
  abytes(buf);
  return buf;
};
// NOTE: second modulo is necessary since we don't need to add padding if current element takes whole block
const getPadding = (len: number, block: number) => new Uint8Array((block - (len % block)) % block);
export type cShakeOpts = ShakeOpts & { personalization?: Uint8Array; NISTfn?: KDFInput };

// Personalization
function cshakePers(hash: Keccak, opts: cShakeOpts = {}): Keccak {
  if (!opts || (!opts.personalization && !opts.NISTfn)) return hash;
  // Encode and pad inplace to avoid unneccesary memory copies/slices (so we don't need to zero them later)
  // bytepad(encode_string(N) || encode_string(S), 168)
  const blockLenBytes = leftEncode(hash.blockLen);
  const fn = opts.NISTfn === undefined ? EMPTY_BUFFER : kdfInputToBytes(opts.NISTfn);
  const fnLen = leftEncode(_8n * BigInt(fn.length)); // length in bits
  const pers = abytesOrZero(opts.personalization);
  const persLen = leftEncode(_8n * BigInt(pers.length)); // length in bits
  if (!fn.length && !pers.length) return hash;
  hash.suffix = 0x04;
  hash.update(blockLenBytes).update(fnLen).update(fn).update(persLen).update(pers);
  let totalLen = blockLenBytes.length + fnLen.length + fn.length + persLen.length + pers.length;
  hash.update(getPadding(totalLen, hash.blockLen));
  return hash;
}

const gencShake = (suffix: number, blockLen: number, outputLen: number) =>
  createHasher<Keccak, cShakeOpts>((opts: cShakeOpts = {}) =>
    cshakePers(new Keccak(blockLen, suffix, chooseLen(opts, outputLen), true), opts)
  );

// TODO: refactor
// export type ICShake = {
//   (msg: Uint8Array, opts?: cShakeOpts): Uint8Array;
//   outputLen: number;
//   blockLen: number;
//   create(opts: cShakeOpts): HashXOF<Keccak>;
// };
export type ITupleHash = {
  (messages: Uint8Array[], opts?: cShakeOpts): Uint8Array;
  create(opts?: cShakeOpts): TupleHash;
};
// export type IParHash = {
//   (message: Uint8Array, opts?: ParallelOpts): Uint8Array;
//   create(opts?: ParallelOpts): ParallelHash;
// };
/** NIST cSHAKE-128 XOF. */
export const cshake128: CHashXOF<Keccak, cShakeOpts> = /* @__PURE__ */ (() =>
  gencShake(0x1f, 168, 128 / 8))();
/** NIST cSHAKE-256 XOF. */
export const cshake256: CHashXOF<Keccak, cShakeOpts> = /* @__PURE__ */ (() =>
  gencShake(0x1f, 136, 256 / 8))();

export class KMAC extends Keccak implements HashXOF<KMAC> {
  constructor(
    blockLen: number,
    outputLen: number,
    enableXOF: boolean,
    key: Uint8Array,
    opts: cShakeOpts = {}
  ) {
    super(blockLen, 0x1f, outputLen, enableXOF);
    cshakePers(this, { NISTfn: 'KMAC', personalization: opts.personalization });
    abytes(key);
    // 1. newX = bytepad(encode_string(K), 168) || X || right_encode(L).
    const blockLenBytes = leftEncode(this.blockLen);
    const keyLen = leftEncode(_8n * BigInt(key.length));
    this.update(blockLenBytes).update(keyLen).update(key);
    const totalLen = blockLenBytes.length + keyLen.length + key.length;
    this.update(getPadding(totalLen, this.blockLen));
  }
  protected finish(): void {
    if (!this.finished) this.update(rightEncode(this.enableXOF ? 0 : _8n * BigInt(this.outputLen))); // outputLen in bits
    super.finish();
  }
  _cloneInto(to?: KMAC): KMAC {
    // Create new instance without calling constructor since key already in state and we don't know it.
    // Force "to" to be instance of KMAC instead of Sha3.
    if (!to) {
      to = Object.create(Object.getPrototypeOf(this), {}) as KMAC;
      to.state = this.state.slice();
      to.blockLen = this.blockLen;
      to.state32 = u32(to.state);
    }
    return super._cloneInto(to) as KMAC;
  }
  clone(): KMAC {
    return this._cloneInto();
  }
}

function genKmac(blockLen: number, outputLen: number, xof = false) {
  const kmac = (key: Uint8Array, message: Uint8Array, opts?: cShakeOpts): Uint8Array =>
    kmac.create(key, opts).update(message).digest();
  kmac.create = (key: Uint8Array, opts: cShakeOpts = {}) =>
    new KMAC(blockLen, chooseLen(opts, outputLen), xof, key, opts);
  return kmac;
}

export const kmac128: {
  (key: Uint8Array, message: Uint8Array, opts?: cShakeOpts): Uint8Array;
  create(key: Uint8Array, opts?: cShakeOpts): KMAC;
} = /* @__PURE__ */ (() => genKmac(168, 128 / 8))();
export const kmac256: {
  (key: Uint8Array, message: Uint8Array, opts?: cShakeOpts): Uint8Array;
  create(key: Uint8Array, opts?: cShakeOpts): KMAC;
} = /* @__PURE__ */ (() => genKmac(136, 256 / 8))();
export const kmac128xof: {
  (key: Uint8Array, message: Uint8Array, opts?: cShakeOpts): Uint8Array;
  create(key: Uint8Array, opts?: cShakeOpts): KMAC;
} = /* @__PURE__ */ (() => genKmac(168, 128 / 8, true))();
export const kmac256xof: {
  (key: Uint8Array, message: Uint8Array, opts?: cShakeOpts): Uint8Array;
  create(key: Uint8Array, opts?: cShakeOpts): KMAC;
} = /* @__PURE__ */ (() => genKmac(136, 256 / 8, true))();

// TupleHash
// Usage: tuple(['ab', 'cd']) != tuple(['a', 'bcd'])
export class TupleHash extends Keccak implements HashXOF<TupleHash> {
  constructor(blockLen: number, outputLen: number, enableXOF: boolean, opts: cShakeOpts = {}) {
    super(blockLen, 0x1f, outputLen, enableXOF);
    cshakePers(this, { NISTfn: 'TupleHash', personalization: opts.personalization });
    // Change update after cshake processed
    this.update = (data: Uint8Array) => {
      abytes(data);
      super.update(leftEncode(_8n * BigInt(data.length)));
      super.update(data);
      return this;
    };
  }
  protected finish(): void {
    if (!this.finished)
      super.update(rightEncode(this.enableXOF ? 0 : _8n * BigInt(this.outputLen))); // outputLen in bits
    super.finish();
  }
  _cloneInto(to?: TupleHash): TupleHash {
    to ||= new TupleHash(this.blockLen, this.outputLen, this.enableXOF);
    return super._cloneInto(to) as TupleHash;
  }
  clone(): TupleHash {
    return this._cloneInto();
  }
}

function genTuple(blockLen: number, outputLen: number, xof = false) {
  const tuple = (messages: Uint8Array[], opts?: cShakeOpts): Uint8Array => {
    const h = tuple.create(opts);
    for (const msg of messages) h.update(msg);
    return h.digest();
  };
  tuple.create = (opts: cShakeOpts = {}) =>
    new TupleHash(blockLen, chooseLen(opts, outputLen), xof, opts);
  return tuple;
}

/** 128-bit TupleHASH. */
export const tuplehash128: ITupleHash = /* @__PURE__ */ (() => genTuple(168, 128 / 8))();
/** 256-bit TupleHASH. */
export const tuplehash256: ITupleHash = /* @__PURE__ */ (() => genTuple(136, 256 / 8))();
/** 128-bit TupleHASH XOF. */
export const tuplehash128xof: ITupleHash = /* @__PURE__ */ (() => genTuple(168, 128 / 8, true))();
/** 256-bit TupleHASH XOF. */
export const tuplehash256xof: ITupleHash = /* @__PURE__ */ (() => genTuple(136, 256 / 8, true))();

// ParallelHash (same as K12/M14, but without speedup for inputs less 8kb, reduced number of rounds and more simple)
type ParallelOpts = cShakeOpts & { blockLen?: number };

export class ParallelHash extends Keccak implements HashXOF<ParallelHash> {
  private leafHash?: Hash<Keccak>;
  protected leafCons: () => Hash<Keccak>;
  private chunkPos = 0; // Position of current block in chunk
  private chunksDone = 0; // How many chunks we already have
  private chunkLen: number;
  constructor(
    blockLen: number,
    outputLen: number,
    leafCons: () => Hash<Keccak>,
    enableXOF: boolean,
    opts: ParallelOpts = {}
  ) {
    super(blockLen, 0x1f, outputLen, enableXOF);
    cshakePers(this, { NISTfn: 'ParallelHash', personalization: opts.personalization });
    this.leafCons = leafCons;
    let { blockLen: B } = opts;
    B ||= 8;
    anumber(B);
    this.chunkLen = B;
    super.update(leftEncode(B));
    // Change update after cshake processed
    this.update = (data: Uint8Array) => {
      abytes(data);
      const { chunkLen, leafCons } = this;
      for (let pos = 0, len = data.length; pos < len; ) {
        if (this.chunkPos == chunkLen || !this.leafHash) {
          if (this.leafHash) {
            super.update(this.leafHash.digest());
            this.chunksDone++;
          }
          this.leafHash = leafCons();
          this.chunkPos = 0;
        }
        const take = Math.min(chunkLen - this.chunkPos, len - pos);
        this.leafHash.update(data.subarray(pos, pos + take));
        this.chunkPos += take;
        pos += take;
      }
      return this;
    };
  }
  protected finish(): void {
    if (this.finished) return;
    if (this.leafHash) {
      super.update(this.leafHash.digest());
      this.chunksDone++;
    }
    super.update(rightEncode(this.chunksDone));
    super.update(rightEncode(this.enableXOF ? 0 : _8n * BigInt(this.outputLen))); // outputLen in bits
    super.finish();
  }
  _cloneInto(to?: ParallelHash): ParallelHash {
    to ||= new ParallelHash(this.blockLen, this.outputLen, this.leafCons, this.enableXOF);
    if (this.leafHash) to.leafHash = this.leafHash._cloneInto(to.leafHash as Keccak);
    to.chunkPos = this.chunkPos;
    to.chunkLen = this.chunkLen;
    to.chunksDone = this.chunksDone;
    return super._cloneInto(to) as ParallelHash;
  }
  destroy(): void {
    super.destroy.call(this);
    if (this.leafHash) this.leafHash.destroy();
  }
  clone(): ParallelHash {
    return this._cloneInto();
  }
}

function genPrl(
  blockLen: number,
  outputLen: number,
  leaf: ReturnType<typeof gencShake>,
  xof = false
) {
  const parallel = (message: Uint8Array, opts?: ParallelOpts): Uint8Array =>
    parallel.create(opts).update(message).digest();
  parallel.create = (opts: ParallelOpts = {}) =>
    new ParallelHash(
      blockLen,
      chooseLen(opts, outputLen),
      () => leaf.create({ dkLen: 2 * outputLen }),
      xof,
      opts
    );
  parallel.outputLen = outputLen;
  parallel.blockLen = blockLen;
  return parallel;
}

/** 128-bit ParallelHash. In JS, it is not parallel. */
export const parallelhash128: CHash<Keccak, ParallelOpts> = /* @__PURE__ */ (() =>
  genPrl(168, 128 / 8, cshake128))();
/** 256-bit ParallelHash. In JS, it is not parallel. */
export const parallelhash256: CHash<Keccak, ParallelOpts> = /* @__PURE__ */ (() =>
  genPrl(136, 256 / 8, cshake256))();
/** 128-bit ParallelHash XOF. In JS, it is not parallel. */
export const parallelhash128xof: CHashXOF<Keccak, ParallelOpts> = /* @__PURE__ */ (() =>
  genPrl(168, 128 / 8, cshake128, true))();
/** 256-bit ParallelHash. In JS, it is not parallel. */
export const parallelhash256xof: CHashXOF<Keccak, ParallelOpts> = /* @__PURE__ */ (() =>
  genPrl(136, 256 / 8, cshake256, true))();

// Should be simple 'shake with 12 rounds', but no, we got whole new spec about Turbo SHAKE Pro MAX.
export type TurboshakeOpts = ShakeOpts & {
  D?: number; // Domain separation byte
};

const genTurboshake = (blockLen: number, outputLen: number) =>
  createHasher<Keccak, TurboshakeOpts>((opts: TurboshakeOpts = {}) => {
    const D = opts.D === undefined ? 0x1f : opts.D;
    // Section 2.1 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/17/
    if (!Number.isSafeInteger(D) || D < 0x01 || D > 0x7f)
      throw new Error('invalid domain separation byte must be 0x01..0x7f, got: ' + D);
    return new Keccak(blockLen, D, opts.dkLen === undefined ? outputLen : opts.dkLen, true, 12);
  });

/** TurboSHAKE 128-bit: reduced 12-round keccak. */
export const turboshake128: CHashXOF<Keccak, TurboshakeOpts> = /* @__PURE__ */ genTurboshake(
  168,
  256 / 8
);
/** TurboSHAKE 256-bit: reduced 12-round keccak. */
export const turboshake256: CHashXOF<Keccak, TurboshakeOpts> = /* @__PURE__ */ genTurboshake(
  136,
  512 / 8
);

// Same as NIST rightEncode, but returns [0] for zero string
function rightEncodeK12(n: number | bigint): Uint8Array {
  n = BigInt(n);
  const res: number[] = [];
  for (; n > 0; n >>= _8n) res.unshift(Number(n & _ffn));
  res.push(res.length);
  return Uint8Array.from(res);
}

export type KangarooOpts = { dkLen?: number; personalization?: Uint8Array };
const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();

export class KangarooTwelve extends Keccak implements HashXOF<KangarooTwelve> {
  readonly chunkLen = 8192;
  private leafHash?: Keccak;
  protected leafLen: number;
  private personalization: Uint8Array;
  private chunkPos = 0; // Position of current block in chunk
  private chunksDone = 0; // How many chunks we already have
  constructor(
    blockLen: number,
    leafLen: number,
    outputLen: number,
    rounds: number,
    opts: KangarooOpts
  ) {
    super(blockLen, 0x07, outputLen, true, rounds);
    this.leafLen = leafLen;
    this.personalization = abytesOrZero(opts.personalization);
  }
  update(data: Uint8Array): this {
    abytes(data);
    const { chunkLen, blockLen, leafLen, rounds } = this;
    for (let pos = 0, len = data.length; pos < len; ) {
      if (this.chunkPos == chunkLen) {
        if (this.leafHash) super.update(this.leafHash.digest());
        else {
          this.suffix = 0x06; // Its safe to change suffix here since its used only in digest()
          super.update(Uint8Array.from([3, 0, 0, 0, 0, 0, 0, 0]));
        }
        this.leafHash = new Keccak(blockLen, 0x0b, leafLen, false, rounds);
        this.chunksDone++;
        this.chunkPos = 0;
      }
      const take = Math.min(chunkLen - this.chunkPos, len - pos);
      const chunk = data.subarray(pos, pos + take);
      if (this.leafHash) this.leafHash.update(chunk);
      else super.update(chunk);
      this.chunkPos += take;
      pos += take;
    }
    return this;
  }
  protected finish(): void {
    if (this.finished) return;
    const { personalization } = this;
    this.update(personalization).update(rightEncodeK12(personalization.length));
    // Leaf hash
    if (this.leafHash) {
      super.update(this.leafHash.digest());
      super.update(rightEncodeK12(this.chunksDone));
      super.update(Uint8Array.from([0xff, 0xff]));
    }
    super.finish.call(this);
  }
  destroy(): void {
    super.destroy.call(this);
    if (this.leafHash) this.leafHash.destroy();
    // We cannot zero personalization buffer since it is user provided and we don't want to mutate user input
    this.personalization = EMPTY_BUFFER;
  }
  _cloneInto(to?: KangarooTwelve): KangarooTwelve {
    const { blockLen, leafLen, leafHash, outputLen, rounds } = this;
    to ||= new KangarooTwelve(blockLen, leafLen, outputLen, rounds, {});
    super._cloneInto(to);
    if (leafHash) to.leafHash = leafHash._cloneInto(to.leafHash);
    to.personalization.set(this.personalization);
    to.leafLen = this.leafLen;
    to.chunkPos = this.chunkPos;
    to.chunksDone = this.chunksDone;
    return to;
  }
  clone(): KangarooTwelve {
    return this._cloneInto();
  }
}

/** 128-bit KangarooTwelve: reduced 12-round keccak. */
export const kt128: CHash<KangarooTwelve, KangarooOpts> = /* @__PURE__ */ (() =>
  createHasher<KangarooTwelve, KangarooOpts>(
    (opts: KangarooOpts = {}) => new KangarooTwelve(168, 32, chooseLen(opts, 32), 12, opts)
  ))();
/** 256-bit KangarooTwelve: reduced 12-round keccak. */
export const kt256: CHash<KangarooTwelve, KangarooOpts> = /* @__PURE__ */ (() =>
  createHasher<KangarooTwelve, KangarooOpts>(
    (opts: KangarooOpts = {}) => new KangarooTwelve(136, 64, chooseLen(opts, 64), 12, opts)
  ))();

// MarsupilamiFourteen (14-rounds) can be defined as:
// `new KangarooTwelve(136, 64, chooseLen(opts, 64), 14, opts)`

export type HopMAC = (
  key: Uint8Array,
  message: Uint8Array,
  personalization: Uint8Array,
  dkLen?: number
) => Uint8Array;
const genHopMAC =
  (hash: CHash<KangarooTwelve, KangarooOpts>) =>
  (key: Uint8Array, message: Uint8Array, personalization: Uint8Array, dkLen?: number): Uint8Array =>
    hash(key, { personalization: hash(message, { personalization }), dkLen });

/**
 * These untested (there is no test vectors or implementation available). Use at your own risk.
 * HopMAC128(Key, M, C, L) = KT128(Key, KT128(M, C, 32), L)
 * HopMAC256(Key, M, C, L) = KT256(Key, KT256(M, C, 64), L)
 */
export const HopMAC128: HopMAC = genHopMAC(kt128);
export const HopMAC256: HopMAC = genHopMAC(kt256);

/**
 * More at https://github.com/XKCP/XKCP/tree/master/lib/high/Keccak/PRG.
 */
export class KeccakPRG extends Keccak implements PRG {
  protected rate: number;
  constructor(capacity: number) {
    anumber(capacity);
    // Rho should be full bytes
    if (capacity < 0 || capacity > 1600 - 10 || (1600 - capacity - 2) % 8)
      throw new Error('invalid capacity');
    // blockLen = rho in bytes
    super((1600 - capacity - 2) / 8, 0, 0, true);
    this.rate = 1600 - capacity;
    this.posOut = Math.floor((this.rate + 7) / 8);
  }
  protected keccak(): void {
    // Duplex padding
    this.state[this.pos] ^= 0x01;
    this.state[this.blockLen] ^= 0x02; // Rho is full bytes
    super.keccak();
    this.pos = 0;
    this.posOut = 0;
  }
  update(data: Uint8Array): this {
    super.update(data);
    this.posOut = this.blockLen;
    return this;
  }
  protected finish(): void {}
  digestInto(_out: Uint8Array): Uint8Array {
    throw new Error('digest is not allowed, use .fetch instead');
  }
  addEntropy(seed: Uint8Array): void {
    this.update(seed);
  }
  randomBytes(length: number): Uint8Array {
    return this.xof(length);
  }
  clean(): void {
    if (this.rate < 1600 / 2 + 1) throw new Error('rate is too low to use .forget()');
    this.keccak();
    for (let i = 0; i < this.blockLen; i++) this.state[i] = 0;
    this.pos = this.blockLen;
    this.keccak();
    this.posOut = this.blockLen;
  }
  _cloneInto(to?: KeccakPRG): KeccakPRG {
    const { rate } = this;
    to ||= new KeccakPRG(1600 - rate);
    super._cloneInto(to);
    to.rate = rate;
    return to;
  }
  clone(): KeccakPRG {
    return this._cloneInto();
  }
}

/** KeccakPRG: Pseudo-random generator based on Keccak. https://keccak.team/files/CSF-0.1.pdf */
export const keccakprg = (capacity = 254): KeccakPRG => new KeccakPRG(capacity);
