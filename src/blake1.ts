/**
 * Blake1 legacy hash function, one of SHA3 proposals.
 * Rarely used. Check out blake2 or blake3 instead.
 * {@link https://www.aumasson.jp/blake/blake.pdf}
 *
 * In the best case, there are 0 allocations.
 *
 * Differences from blake2:
 *
 * - BE instead of LE
 * - Paddings, similar to MD5, RIPEMD, SHA1, SHA2, but:
 *     - length flag is located before actual length
 *     - padding block is compressed differently (no lengths)
 * Instead of msg[sigma[k]], we have `msg[sigma[k]] ^ constants[sigma[k-1]]`
 * (-1 for g1, g2 without -1)
 * - Salt is XOR-ed into constants instead of state
 * - Salt is XOR-ed with output in `compress`
 * - Additional rows (+64 bytes) in SIGMA for new rounds
 * - Different round count:
 *     - 14 / 10 rounds in blake256 / blake2s
 *     - 16 / 12 rounds in blake512 / blake2b
 * - blake512: G1b: rotr 24 -> 25, G2b: rotr 63 -> 11
 * @module
 */
import { SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from './_md.ts';
import * as u64 from './_u64.ts';
// prettier-ignore
import {
  abytes, aexists, aoutput,
  checkOpts,
  clean, createHasher,
  createView,
  type CHash,
  type Hash,
  type TArg,
  type TRet
} from './utils.ts';

// BLAKE-224/256 uses a generated scalar core. BLAKE-384/512 keeps a compact split-u64 work
// vector: the analogous scalar BLAKE2b core crossed JSC's JIT/code-size limit, so this path
// benchmarks compact combined-G variants instead.

/** Blake1 options. Basically just `salt`. */
export type BlakeOpts = {
  /** Optional salt mixed into initialization. */
  salt?: Uint8Array;
};

// Shared unsalted sentinel, sized for the 64-bit path and reused by the 32-bit path via prefix.
const EMPTY_SALT = /* @__PURE__ */ new Uint32Array(8);

// Base destroy logic only clears salt-derived state; the partial message buffer and length/position
// bookkeeping remain until the instance or backing buffer is reused.
abstract class BLAKE1<T extends BLAKE1<T>> implements Hash<T> {
  readonly canXOF = false;
  protected finished = false;
  protected length = 0;
  protected pos = 0;
  protected destroyed = false;
  // For partial updates less than block size
  protected buffer: Uint8Array;
  protected view: DataView;
  protected salt: Uint32Array;
  abstract compress(view: DataView, offset: number, withLength?: boolean): void;
  protected abstract get(): number[];
  // Each state layout must own this call site. At a monomorphic site TurboFan inlines get()/set()
  // and scalar-replaces the tuple, so no secret-bearing array is allocated. Sharing this site
  // across the 32/64-bit layouts materializes the tuple, which cannot be explicitly wiped, and
  // regresses clone-heavy KDFs.
  abstract _cloneInto(to?: T): T;

  readonly blockLen: number;
  readonly outputLen: number;
  private lengthFlag: number;
  private counterLen: number;
  protected constants: Uint32Array;

  constructor(
    blockLen: number,
    outputLen: number,
    lengthFlag: number,
    counterLen: number,
    saltLen: number,
    constants: Uint32Array,
    opts: BlakeOpts = {}
  ) {
    opts = checkOpts({}, opts);
    const { salt } = opts;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.lengthFlag = lengthFlag;
    this.counterLen = counterLen;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
    if (salt !== undefined) {
      let slt = salt;
      abytes(slt, 4 * saltLen, 'salt');
      // if (slt.length !== 4 * saltLen) throw new Error('wrong salt length');
      const salt32 = (this.salt = new Uint32Array(saltLen));
      const sv = createView(slt);
      this.constants = constants.slice();
      for (let i = 0, offset = 0; i < salt32.length; i++, offset += 4) {
        salt32[i] = sv.getUint32(offset, false);
        this.constants[i] ^= salt32[i];
      }
    } else {
      this.salt = EMPTY_SALT;
      this.constants = constants;
    }
  }
  update(data: TArg<Uint8Array>): this {
    aexists(this);
    abytes(data);
    // From _md, but update length before each compress
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let dataView;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      // Fast path only when there is no buffered partial block: `take === blockLen` implies
      // `this.pos === 0`, so we can process full blocks directly from the input view.
      if (take === blockLen) {
        if (!dataView) dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen) {
          this.length += blockLen;
          this.compress(dataView, pos);
        }
        continue;
      }
      // When the whole input is buffered in one go (common for short messages), passing `data`
      // directly avoids allocating a subarray view.
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.length += blockLen;
        this.compress(view, 0, true);
        this.pos = 0;
      }
    }
    return this;
  }
  destroy(): void {
    this.destroyed = true;
    if (this.salt !== EMPTY_SALT) {
      clean(this.salt, this.constants);
    }
  }
  protected _cloneIntoMeta(to: T): T {
    const { buffer, length, finished, destroyed, constants, salt, pos } = this;
    if (pos) to.buffer.set(buffer);
    // At pos=0 the source buffer is dead. Discard an unfinished destination's old message bytes;
    // finished digestInto() workers are already clean, so hot KDF resets skip this fill.
    else if (to.destroyed || (!to.finished && (to.length || to.pos))) clean(to.buffer);
    // Clone salt-derived arrays by value so destroying the clone cannot wipe the source instance.
    if (salt === EMPTY_SALT) {
      to.constants = constants; // Immutable; sentinel keeps destroy() from wiping it.
      to.salt = EMPTY_SALT;
    } else if (to.salt === EMPTY_SALT) {
      to.constants = constants.slice();
      to.salt = salt.slice();
    } else {
      to.constants.set(constants); // Reuse independently owned salted arrays.
      to.salt.set(salt);
    }
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    return to;
  }
  clone(): T {
    return this._cloneInto();
  }
  digestInto(out: TArg<Uint8Array>): void {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    // Padding
    const { buffer, blockLen, counterLen, lengthFlag, view } = this;
    buffer.fill(0, this.pos); // clean buf
    const counterBits = (this.length + this.pos) * 8;
    const counterPos = blockLen - counterLen - 1;
    buffer[this.pos] |= 0b1000_0000; // End block flag
    this.length += this.pos; // add unwritten length
    // Not enough in buffer for length: write what we have.
    if (this.pos > counterPos) {
      this.compress(view, 0);
      clean(buffer);
      this.pos = 0;
    }
    // Difference with md: here we have lengthFlag!
    buffer[counterPos] |= lengthFlag; // Length flag
    // We always set 8 byte length flag. Because length will overflow significantly sooner.
    u64.setU64FromNum(view, blockLen - 8, counterBits, false);
    // Blake1 omits the counter from the extra all-padding block; only the block that still carries
    // message bytes mixes in the final bit length.
    this.compress(view, 0, this.pos !== 0);
    // Write output
    clean(buffer);
    // digest() passes our own `buffer` as `out`; reuse its cached view instead of allocating one.
    const v = out === buffer ? view : createView(out);
    const state = this.get();
    for (let i = 0; i < this.outputLen / 4; ++i) v.setUint32(i * 4, state[i]);
  }
  digest(): TRet<Uint8Array> {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    // Return a copy so callers do not alias the instance scratch buffer used during finalization.
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res as TRet<Uint8Array>;
  }
}

// Blake1-512 / Blake1-384 constant table `C512`.
// Stored as sixteen 64-bit constants split into `[high32, low32]` halves so
// the Blake1-64 path can reuse one layout for both `v8..v15` initialization
// and the permuted constant lookups.
const B64C = /* @__PURE__ */ Uint32Array.from([
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
  0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
]);
// Snapshot companion constants before an unsalted instance can expose `B64C`
// through its mutable constants field.
const B64CC = /* @__PURE__ */ B64C.slice();
// Blake1-256 / Blake1-224 constant table `C256`, derived as the first half of `C512`.
const B32C = /* @__PURE__ */ B64C.slice(0, 16);

// Blake1-256 IV cloned from SHA-256.
const B256_IV = /* @__PURE__ */ SHA256_IV.slice();
// Blake1-224 IV cloned from SHA-224.
const B224_IV = /* @__PURE__ */ SHA224_IV.slice();
// Blake1-384 IV cloned from the SHA-384 high-then-low 32-bit halves.
const B384_IV = /* @__PURE__ */ SHA384_IV.slice();
// Blake1-512 IV cloned from the SHA-512 high-then-low 32-bit halves.
const B512_IV = /* @__PURE__ */ SHA512_IV.slice();

class BLAKE1_32B extends BLAKE1<BLAKE1_32B> {
  private v0: number;
  private v1: number;
  private v2: number;
  private v3: number;
  private v4: number;
  private v5: number;
  private v6: number;
  private v7: number;
  constructor(outputLen: number, IV: Uint32Array, lengthFlag: number, opts: BlakeOpts = {}) {
    super(64, outputLen, lengthFlag, 8, 4, B32C, opts);
    this.v0 = IV[0] | 0;
    this.v1 = IV[1] | 0;
    this.v2 = IV[2] | 0;
    this.v3 = IV[3] | 0;
    this.v4 = IV[4] | 0;
    this.v5 = IV[5] | 0;
    this.v6 = IV[6] | 0;
    this.v7 = IV[7] | 0;
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
  _cloneInto(to?: BLAKE1_32B): BLAKE1_32B {
    (to ||= new (this.constructor as any)() as BLAKE1_32B).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  destroy(): void {
    super.destroy();
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
  }
  // BEGIN generated BLAKE1-256 compression
  // Generated by test/misc/unrolled-blake1.js from the BLAKE submission SIGMA. Do not edit.
  // prettier-ignore
  compress(view: DataView, offset: number, withLength = true): void {
    const m0 = view.getUint32(offset + 0, false), m1 = view.getUint32(offset + 4, false), m2 = view.getUint32(offset + 8, false), m3 = view.getUint32(offset + 12, false);
    const m4 = view.getUint32(offset + 16, false), m5 = view.getUint32(offset + 20, false), m6 = view.getUint32(offset + 24, false), m7 = view.getUint32(offset + 28, false);
    const m8 = view.getUint32(offset + 32, false), m9 = view.getUint32(offset + 36, false), m10 = view.getUint32(offset + 40, false), m11 = view.getUint32(offset + 44, false);
    const m12 = view.getUint32(offset + 48, false), m13 = view.getUint32(offset + 52, false), m14 = view.getUint32(offset + 56, false), m15 = view.getUint32(offset + 60, false);
    let v00 = this.v0 | 0, v01 = this.v1 | 0, v02 = this.v2 | 0, v03 = this.v3 | 0;
    let v04 = this.v4 | 0, v05 = this.v5 | 0, v06 = this.v6 | 0, v07 = this.v7 | 0;
    let v08 = this.constants[0] | 0, v09 = this.constants[1] | 0;
    let v10 = this.constants[2] | 0, v11 = this.constants[3] | 0;
    const bits = withLength ? this.length * 8 : 0;
    let v12 = (this.constants[4] ^ (bits >>> 0)) | 0, v13 = (this.constants[5] ^ (bits >>> 0)) | 0;
    let v14 = (this.constants[6] ^ ((bits / 4294967296) | 0)) | 0;
    let v15 = (this.constants[7] ^ ((bits / 4294967296) | 0)) | 0;
    // Round 0
    v00 = (v00 + v04 + (m0 ^ 0x85a308d3)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m1 ^ 0x243f6a88)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m2 ^ 0x03707344)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m3 ^ 0x13198a2e)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m4 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m5 ^ 0xa4093822)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m6 ^ 0xec4e6c89)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m7 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m8 ^ 0x38d01377)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m9 ^ 0x452821e6)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m10 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m11 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m12 ^ 0xc97c50dd)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m13 ^ 0xc0ac29b7)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m14 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m15 ^ 0x3f84d5b5)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 1
    v00 = (v00 + v04 + (m14 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m10 ^ 0x3f84d5b5)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m4 ^ 0x452821e6)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m8 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m9 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m15 ^ 0x38d01377)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m13 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m6 ^ 0xc97c50dd)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m1 ^ 0xc0ac29b7)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m12 ^ 0x85a308d3)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m0 ^ 0x13198a2e)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m2 ^ 0x243f6a88)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m11 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m7 ^ 0x34e90c6c)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m5 ^ 0x03707344)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m3 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 2
    v00 = (v00 + v04 + (m11 ^ 0x452821e6)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m8 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m12 ^ 0x243f6a88)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m0 ^ 0xc0ac29b7)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m5 ^ 0x13198a2e)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m2 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m15 ^ 0xc97c50dd)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m13 ^ 0xb5470917)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m10 ^ 0x3f84d5b5)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m14 ^ 0xbe5466cf)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m3 ^ 0x082efa98)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m6 ^ 0x03707344)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m7 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m1 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m9 ^ 0xa4093822)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m4 ^ 0x38d01377)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 3
    v00 = (v00 + v04 + (m7 ^ 0x38d01377)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m9 ^ 0xec4e6c89)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m3 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m1 ^ 0x03707344)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m13 ^ 0xc0ac29b7)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m12 ^ 0xc97c50dd)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m11 ^ 0x3f84d5b5)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m14 ^ 0x34e90c6c)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m2 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m6 ^ 0x13198a2e)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m5 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m10 ^ 0x299f31d0)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m4 ^ 0x243f6a88)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m0 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m15 ^ 0x452821e6)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m8 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 4
    v00 = (v00 + v04 + (m9 ^ 0x243f6a88)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m0 ^ 0x38d01377)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m5 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m7 ^ 0x299f31d0)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m2 ^ 0xa4093822)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m4 ^ 0x13198a2e)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m10 ^ 0xb5470917)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m15 ^ 0xbe5466cf)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m14 ^ 0x85a308d3)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m1 ^ 0x3f84d5b5)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m11 ^ 0xc0ac29b7)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m12 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m6 ^ 0x452821e6)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m8 ^ 0x082efa98)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m3 ^ 0xc97c50dd)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m13 ^ 0x03707344)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 5
    v00 = (v00 + v04 + (m2 ^ 0xc0ac29b7)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m12 ^ 0x13198a2e)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m6 ^ 0xbe5466cf)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m10 ^ 0x082efa98)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m0 ^ 0x34e90c6c)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m11 ^ 0x243f6a88)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m8 ^ 0x03707344)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m3 ^ 0x452821e6)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m4 ^ 0xc97c50dd)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m13 ^ 0xa4093822)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m7 ^ 0x299f31d0)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m5 ^ 0xec4e6c89)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m15 ^ 0x3f84d5b5)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m14 ^ 0xb5470917)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m1 ^ 0x38d01377)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m9 ^ 0x85a308d3)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 6
    v00 = (v00 + v04 + (m12 ^ 0x299f31d0)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m5 ^ 0xc0ac29b7)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m1 ^ 0xb5470917)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m15 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m14 ^ 0xc97c50dd)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m13 ^ 0x3f84d5b5)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m4 ^ 0xbe5466cf)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m10 ^ 0xa4093822)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m0 ^ 0xec4e6c89)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m7 ^ 0x243f6a88)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m6 ^ 0x03707344)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m3 ^ 0x082efa98)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m9 ^ 0x13198a2e)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m2 ^ 0x38d01377)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m8 ^ 0x34e90c6c)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m11 ^ 0x452821e6)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 7
    v00 = (v00 + v04 + (m13 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m11 ^ 0xc97c50dd)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m7 ^ 0x3f84d5b5)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m14 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m12 ^ 0x85a308d3)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m1 ^ 0xc0ac29b7)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m3 ^ 0x38d01377)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m9 ^ 0x03707344)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m5 ^ 0x243f6a88)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m0 ^ 0x299f31d0)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m15 ^ 0xa4093822)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m4 ^ 0xb5470917)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m8 ^ 0x082efa98)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m6 ^ 0x452821e6)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m2 ^ 0xbe5466cf)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m10 ^ 0x13198a2e)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 8
    v00 = (v00 + v04 + (m6 ^ 0xb5470917)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m15 ^ 0x082efa98)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m14 ^ 0x38d01377)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m9 ^ 0x3f84d5b5)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m11 ^ 0x03707344)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m3 ^ 0x34e90c6c)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m0 ^ 0x452821e6)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m8 ^ 0x243f6a88)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m12 ^ 0x13198a2e)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m2 ^ 0xc0ac29b7)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m13 ^ 0xec4e6c89)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m7 ^ 0xc97c50dd)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m1 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m4 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m10 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m5 ^ 0xbe5466cf)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 9
    v00 = (v00 + v04 + (m10 ^ 0x13198a2e)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m2 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m8 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m4 ^ 0x452821e6)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m7 ^ 0x082efa98)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m6 ^ 0xec4e6c89)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m1 ^ 0x299f31d0)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m5 ^ 0x85a308d3)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m15 ^ 0x34e90c6c)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m11 ^ 0xb5470917)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m9 ^ 0x3f84d5b5)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m14 ^ 0x38d01377)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m3 ^ 0xc0ac29b7)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m12 ^ 0x03707344)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m13 ^ 0x243f6a88)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m0 ^ 0xc97c50dd)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 10
    v00 = (v00 + v04 + (m0 ^ 0x85a308d3)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m1 ^ 0x243f6a88)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m2 ^ 0x03707344)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m3 ^ 0x13198a2e)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m4 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m5 ^ 0xa4093822)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m6 ^ 0xec4e6c89)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m7 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m8 ^ 0x38d01377)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m9 ^ 0x452821e6)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m10 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m11 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m12 ^ 0xc97c50dd)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m13 ^ 0xc0ac29b7)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m14 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m15 ^ 0x3f84d5b5)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 11
    v00 = (v00 + v04 + (m14 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m10 ^ 0x3f84d5b5)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m4 ^ 0x452821e6)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m8 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m9 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m15 ^ 0x38d01377)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m13 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m6 ^ 0xc97c50dd)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m1 ^ 0xc0ac29b7)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m12 ^ 0x85a308d3)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m0 ^ 0x13198a2e)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m2 ^ 0x243f6a88)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m11 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m7 ^ 0x34e90c6c)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m5 ^ 0x03707344)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m3 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 12
    v00 = (v00 + v04 + (m11 ^ 0x452821e6)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m8 ^ 0x34e90c6c)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m12 ^ 0x243f6a88)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m0 ^ 0xc0ac29b7)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m5 ^ 0x13198a2e)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m2 ^ 0x299f31d0)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m15 ^ 0xc97c50dd)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m13 ^ 0xb5470917)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m10 ^ 0x3f84d5b5)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m14 ^ 0xbe5466cf)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m3 ^ 0x082efa98)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m6 ^ 0x03707344)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m7 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m1 ^ 0xec4e6c89)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m9 ^ 0xa4093822)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m4 ^ 0x38d01377)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    // Round 13
    v00 = (v00 + v04 + (m7 ^ 0x38d01377)) | 0;
    v12 = ((v12 ^ v00) >>> 16) | ((v12 ^ v00) << 16);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 12) | ((v04 ^ v08) << 20);
    v00 = (v00 + v04 + (m9 ^ 0xec4e6c89)) | 0;
    v12 = ((v12 ^ v00) >>> 8) | ((v12 ^ v00) << 24);
    v08 = (v08 + v12) | 0;
    v04 = ((v04 ^ v08) >>> 7) | ((v04 ^ v08) << 25);
    v01 = (v01 + v05 + (m3 ^ 0x85a308d3)) | 0;
    v13 = ((v13 ^ v01) >>> 16) | ((v13 ^ v01) << 16);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 12) | ((v05 ^ v09) << 20);
    v01 = (v01 + v05 + (m1 ^ 0x03707344)) | 0;
    v13 = ((v13 ^ v01) >>> 8) | ((v13 ^ v01) << 24);
    v09 = (v09 + v13) | 0;
    v05 = ((v05 ^ v09) >>> 7) | ((v05 ^ v09) << 25);
    v02 = (v02 + v06 + (m13 ^ 0xc0ac29b7)) | 0;
    v14 = ((v14 ^ v02) >>> 16) | ((v14 ^ v02) << 16);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 12) | ((v06 ^ v10) << 20);
    v02 = (v02 + v06 + (m12 ^ 0xc97c50dd)) | 0;
    v14 = ((v14 ^ v02) >>> 8) | ((v14 ^ v02) << 24);
    v10 = (v10 + v14) | 0;
    v06 = ((v06 ^ v10) >>> 7) | ((v06 ^ v10) << 25);
    v03 = (v03 + v07 + (m11 ^ 0x3f84d5b5)) | 0;
    v15 = ((v15 ^ v03) >>> 16) | ((v15 ^ v03) << 16);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 12) | ((v07 ^ v11) << 20);
    v03 = (v03 + v07 + (m14 ^ 0x34e90c6c)) | 0;
    v15 = ((v15 ^ v03) >>> 8) | ((v15 ^ v03) << 24);
    v11 = (v11 + v15) | 0;
    v07 = ((v07 ^ v11) >>> 7) | ((v07 ^ v11) << 25);
    v00 = (v00 + v05 + (m2 ^ 0x082efa98)) | 0;
    v15 = ((v15 ^ v00) >>> 16) | ((v15 ^ v00) << 16);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 12) | ((v05 ^ v10) << 20);
    v00 = (v00 + v05 + (m6 ^ 0x13198a2e)) | 0;
    v15 = ((v15 ^ v00) >>> 8) | ((v15 ^ v00) << 24);
    v10 = (v10 + v15) | 0;
    v05 = ((v05 ^ v10) >>> 7) | ((v05 ^ v10) << 25);
    v01 = (v01 + v06 + (m5 ^ 0xbe5466cf)) | 0;
    v12 = ((v12 ^ v01) >>> 16) | ((v12 ^ v01) << 16);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 12) | ((v06 ^ v11) << 20);
    v01 = (v01 + v06 + (m10 ^ 0x299f31d0)) | 0;
    v12 = ((v12 ^ v01) >>> 8) | ((v12 ^ v01) << 24);
    v11 = (v11 + v12) | 0;
    v06 = ((v06 ^ v11) >>> 7) | ((v06 ^ v11) << 25);
    v02 = (v02 + v07 + (m4 ^ 0x243f6a88)) | 0;
    v13 = ((v13 ^ v02) >>> 16) | ((v13 ^ v02) << 16);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 12) | ((v07 ^ v08) << 20);
    v02 = (v02 + v07 + (m0 ^ 0xa4093822)) | 0;
    v13 = ((v13 ^ v02) >>> 8) | ((v13 ^ v02) << 24);
    v08 = (v08 + v13) | 0;
    v07 = ((v07 ^ v08) >>> 7) | ((v07 ^ v08) << 25);
    v03 = (v03 + v04 + (m15 ^ 0x452821e6)) | 0;
    v14 = ((v14 ^ v03) >>> 16) | ((v14 ^ v03) << 16);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 12) | ((v04 ^ v09) << 20);
    v03 = (v03 + v04 + (m8 ^ 0xb5470917)) | 0;
    v14 = ((v14 ^ v03) >>> 8) | ((v14 ^ v03) << 24);
    v09 = (v09 + v14) | 0;
    v04 = ((v04 ^ v09) >>> 7) | ((v04 ^ v09) << 25);
    this.v0 = (this.v0 ^ v00 ^ v08 ^ this.salt[0]) >>> 0; this.v1 = (this.v1 ^ v01 ^ v09 ^ this.salt[1]) >>> 0;
    this.v2 = (this.v2 ^ v02 ^ v10 ^ this.salt[2]) >>> 0; this.v3 = (this.v3 ^ v03 ^ v11 ^ this.salt[3]) >>> 0;
    this.v4 = (this.v4 ^ v04 ^ v12 ^ this.salt[0]) >>> 0; this.v5 = (this.v5 ^ v05 ^ v13 ^ this.salt[1]) >>> 0;
    this.v6 = (this.v6 ^ v06 ^ v14 ^ this.salt[2]) >>> 0; this.v7 = (this.v7 ^ v07 ^ v15 ^ this.salt[3]) >>> 0;
  }
  // END generated BLAKE1-256 compression
}

// Shared Blake1-64 work vector storing 16 working words as adjacent high/low 32-bit halves.
const BBUF = /* @__PURE__ */ new Uint32Array(32);
// Shared synchronous message-word scratch for the 64-bit Blake1 path.
const BLAKE512_W = /* @__PURE__ */ new Uint32Array(32);

// Blake1-64 G mix. Combining both halves keeps eight state limbs in locals and avoids the
// allocation-returning generic u64 helpers in the compression hot loop.
function Gb(
  a: number,
  b: number,
  c: number,
  d: number,
  msg: TArg<Uint32Array>,
  x: number,
  y: number
): void {
  const xp = 2 * x,
    yp = 2 * y;
  const Xh = msg[xp] ^ B64CC[yp], Xl = msg[xp + 1] ^ B64CC[yp + 1]; // prettier-ignore
  const Yh = msg[yp] ^ B64CC[xp], Yl = msg[yp + 1] ^ B64CC[xp + 1]; // prettier-ignore
  let Ah = BBUF[2 * a], Al = BBUF[2 * a + 1]; // prettier-ignore
  let Bh = BBUF[2 * b], Bl = BBUF[2 * b + 1]; // prettier-ignore
  let Ch = BBUF[2 * c], Cl = BBUF[2 * c + 1]; // prettier-ignore
  let Dh = BBUF[2 * d], Dl = BBUF[2 * d + 1]; // prettier-ignore
  let low = (Al >>> 0) + (Bl >>> 0) + (Xl >>> 0);
  Ah = (Ah + Bh + Xh + ((low / 4294967296) | 0)) | 0;
  Al = low | 0;
  let xh = Dh ^ Ah, xl = Dl ^ Al; // prettier-ignore
  Dh = xl;
  Dl = xh;
  low = (Cl >>> 0) + (Dl >>> 0);
  Ch = (Ch + Dh + ((low / 4294967296) | 0)) | 0;
  Cl = low | 0;
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = (xh >>> 25) | (xl << 7);
  Bl = (xl >>> 25) | (xh << 7);
  low = (Al >>> 0) + (Bl >>> 0) + (Yl >>> 0);
  Ah = (Ah + Bh + Yh + ((low / 4294967296) | 0)) | 0;
  Al = low | 0;
  xh = Dh ^ Ah;
  xl = Dl ^ Al;
  Dh = (xh >>> 16) | (xl << 16);
  Dl = (xl >>> 16) | (xh << 16);
  low = (Cl >>> 0) + (Dl >>> 0);
  Ch = (Ch + Dh + ((low / 4294967296) | 0)) | 0;
  Cl = low | 0;
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = (xh >>> 11) | (xl << 21);
  Bl = (xl >>> 11) | (xh << 21);
  BBUF[2 * a] = Ah;
  BBUF[2 * a + 1] = Al;
  BBUF[2 * b] = Bh;
  BBUF[2 * b + 1] = Bl;
  BBUF[2 * c] = Ch;
  BBUF[2 * c + 1] = Cl;
  BBUF[2 * d] = Dh;
  BBUF[2 * d + 1] = Dl;
}

// Legacy field names keep the local `l/h` spelling, but array/state order stays `[high, low]` to
// match the IV tables and `BBUF` layout.
class BLAKE1_64B extends BLAKE1<BLAKE1_64B> {
  private v0l: number;
  private v0h: number;
  private v1l: number;
  private v1h: number;
  private v2l: number;
  private v2h: number;
  private v3l: number;
  private v3h: number;
  private v4l: number;
  private v4h: number;
  private v5l: number;
  private v5h: number;
  private v6l: number;
  private v6h: number;
  private v7l: number;
  private v7h: number;
  constructor(outputLen: number, IV: Uint32Array, lengthFlag: number, opts: BlakeOpts = {}) {
    super(128, outputLen, lengthFlag, 16, 8, B64C, opts);
    this.v0l = IV[0] | 0;
    this.v0h = IV[1] | 0;
    this.v1l = IV[2] | 0;
    this.v1h = IV[3] | 0;
    this.v2l = IV[4] | 0;
    this.v2h = IV[5] | 0;
    this.v3l = IV[6] | 0;
    this.v3h = IV[7] | 0;
    this.v4l = IV[8] | 0;
    this.v4h = IV[9] | 0;
    this.v5l = IV[10] | 0;
    this.v5h = IV[11] | 0;
    this.v6l = IV[12] | 0;
    this.v6h = IV[13] | 0;
    this.v7l = IV[14] | 0;
    this.v7h = IV[15] | 0;
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
  _cloneInto(to?: BLAKE1_64B): BLAKE1_64B {
    (to ||= new (this.constructor as any)() as BLAKE1_64B).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  destroy(): void {
    super.destroy();
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
  compress(view: DataView, offset: number, withLength = true): void {
    for (let i = 0; i < 32; i++, offset += 4) BLAKE512_W[i] = view.getUint32(offset, false);
    // First half from state. Direct writes: get() would allocate an array +
    // closure per block (same reasoning as blake2b's compress).
    // prettier-ignore
    const { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
    // prettier-ignore
    { BBUF[0] = v0l; BBUF[1] = v0h; BBUF[2] = v1l; BBUF[3] = v1h;
      BBUF[4] = v2l; BBUF[5] = v2h; BBUF[6] = v3l; BBUF[7] = v3h;
      BBUF[8] = v4l; BBUF[9] = v4h; BBUF[10] = v5l; BBUF[11] = v5h;
      BBUF[12] = v6l; BBUF[13] = v6h; BBUF[14] = v7l; BBUF[15] = v7h; }
    BBUF.set(this.constants.subarray(0, 16), 16);
    if (withLength) {
      // Blake1-64 injects the 64-bit bit counter into `v12` and `v13`; the final all-padding
      // block passes `withLength = false`, leaving the trailing constant lanes untouched.
      const bits = this.length * 8;
      const h = u64.fromNumH(bits);
      const l = u64.fromNumL(bits);
      BBUF[24] = (BBUF[24] ^ h) >>> 0;
      BBUF[25] = (BBUF[25] ^ l) >>> 0;
      BBUF[26] = (BBUF[26] ^ h) >>> 0;
      BBUF[27] = (BBUF[27] ^ l) >>> 0;
    }
    // BEGIN generated BLAKE1-512 compression
    // Generated by test/misc/unrolled-blake1.js from the BLAKE submission SIGMA. Do not edit.
    // Round 0
    Gb(0, 4, 8, 12, BLAKE512_W, 0, 1);
    Gb(1, 5, 9, 13, BLAKE512_W, 2, 3);
    Gb(2, 6, 10, 14, BLAKE512_W, 4, 5);
    Gb(3, 7, 11, 15, BLAKE512_W, 6, 7);
    Gb(0, 5, 10, 15, BLAKE512_W, 8, 9);
    Gb(1, 6, 11, 12, BLAKE512_W, 10, 11);
    Gb(2, 7, 8, 13, BLAKE512_W, 12, 13);
    Gb(3, 4, 9, 14, BLAKE512_W, 14, 15);
    // Round 1
    Gb(0, 4, 8, 12, BLAKE512_W, 14, 10);
    Gb(1, 5, 9, 13, BLAKE512_W, 4, 8);
    Gb(2, 6, 10, 14, BLAKE512_W, 9, 15);
    Gb(3, 7, 11, 15, BLAKE512_W, 13, 6);
    Gb(0, 5, 10, 15, BLAKE512_W, 1, 12);
    Gb(1, 6, 11, 12, BLAKE512_W, 0, 2);
    Gb(2, 7, 8, 13, BLAKE512_W, 11, 7);
    Gb(3, 4, 9, 14, BLAKE512_W, 5, 3);
    // Round 2
    Gb(0, 4, 8, 12, BLAKE512_W, 11, 8);
    Gb(1, 5, 9, 13, BLAKE512_W, 12, 0);
    Gb(2, 6, 10, 14, BLAKE512_W, 5, 2);
    Gb(3, 7, 11, 15, BLAKE512_W, 15, 13);
    Gb(0, 5, 10, 15, BLAKE512_W, 10, 14);
    Gb(1, 6, 11, 12, BLAKE512_W, 3, 6);
    Gb(2, 7, 8, 13, BLAKE512_W, 7, 1);
    Gb(3, 4, 9, 14, BLAKE512_W, 9, 4);
    // Round 3
    Gb(0, 4, 8, 12, BLAKE512_W, 7, 9);
    Gb(1, 5, 9, 13, BLAKE512_W, 3, 1);
    Gb(2, 6, 10, 14, BLAKE512_W, 13, 12);
    Gb(3, 7, 11, 15, BLAKE512_W, 11, 14);
    Gb(0, 5, 10, 15, BLAKE512_W, 2, 6);
    Gb(1, 6, 11, 12, BLAKE512_W, 5, 10);
    Gb(2, 7, 8, 13, BLAKE512_W, 4, 0);
    Gb(3, 4, 9, 14, BLAKE512_W, 15, 8);
    // Round 4
    Gb(0, 4, 8, 12, BLAKE512_W, 9, 0);
    Gb(1, 5, 9, 13, BLAKE512_W, 5, 7);
    Gb(2, 6, 10, 14, BLAKE512_W, 2, 4);
    Gb(3, 7, 11, 15, BLAKE512_W, 10, 15);
    Gb(0, 5, 10, 15, BLAKE512_W, 14, 1);
    Gb(1, 6, 11, 12, BLAKE512_W, 11, 12);
    Gb(2, 7, 8, 13, BLAKE512_W, 6, 8);
    Gb(3, 4, 9, 14, BLAKE512_W, 3, 13);
    // Round 5
    Gb(0, 4, 8, 12, BLAKE512_W, 2, 12);
    Gb(1, 5, 9, 13, BLAKE512_W, 6, 10);
    Gb(2, 6, 10, 14, BLAKE512_W, 0, 11);
    Gb(3, 7, 11, 15, BLAKE512_W, 8, 3);
    Gb(0, 5, 10, 15, BLAKE512_W, 4, 13);
    Gb(1, 6, 11, 12, BLAKE512_W, 7, 5);
    Gb(2, 7, 8, 13, BLAKE512_W, 15, 14);
    Gb(3, 4, 9, 14, BLAKE512_W, 1, 9);
    // Round 6
    Gb(0, 4, 8, 12, BLAKE512_W, 12, 5);
    Gb(1, 5, 9, 13, BLAKE512_W, 1, 15);
    Gb(2, 6, 10, 14, BLAKE512_W, 14, 13);
    Gb(3, 7, 11, 15, BLAKE512_W, 4, 10);
    Gb(0, 5, 10, 15, BLAKE512_W, 0, 7);
    Gb(1, 6, 11, 12, BLAKE512_W, 6, 3);
    Gb(2, 7, 8, 13, BLAKE512_W, 9, 2);
    Gb(3, 4, 9, 14, BLAKE512_W, 8, 11);
    // Round 7
    Gb(0, 4, 8, 12, BLAKE512_W, 13, 11);
    Gb(1, 5, 9, 13, BLAKE512_W, 7, 14);
    Gb(2, 6, 10, 14, BLAKE512_W, 12, 1);
    Gb(3, 7, 11, 15, BLAKE512_W, 3, 9);
    Gb(0, 5, 10, 15, BLAKE512_W, 5, 0);
    Gb(1, 6, 11, 12, BLAKE512_W, 15, 4);
    Gb(2, 7, 8, 13, BLAKE512_W, 8, 6);
    Gb(3, 4, 9, 14, BLAKE512_W, 2, 10);
    // Round 8
    Gb(0, 4, 8, 12, BLAKE512_W, 6, 15);
    Gb(1, 5, 9, 13, BLAKE512_W, 14, 9);
    Gb(2, 6, 10, 14, BLAKE512_W, 11, 3);
    Gb(3, 7, 11, 15, BLAKE512_W, 0, 8);
    Gb(0, 5, 10, 15, BLAKE512_W, 12, 2);
    Gb(1, 6, 11, 12, BLAKE512_W, 13, 7);
    Gb(2, 7, 8, 13, BLAKE512_W, 1, 4);
    Gb(3, 4, 9, 14, BLAKE512_W, 10, 5);
    // Round 9
    Gb(0, 4, 8, 12, BLAKE512_W, 10, 2);
    Gb(1, 5, 9, 13, BLAKE512_W, 8, 4);
    Gb(2, 6, 10, 14, BLAKE512_W, 7, 6);
    Gb(3, 7, 11, 15, BLAKE512_W, 1, 5);
    Gb(0, 5, 10, 15, BLAKE512_W, 15, 11);
    Gb(1, 6, 11, 12, BLAKE512_W, 9, 14);
    Gb(2, 7, 8, 13, BLAKE512_W, 3, 12);
    Gb(3, 4, 9, 14, BLAKE512_W, 13, 0);
    // Round 10
    Gb(0, 4, 8, 12, BLAKE512_W, 0, 1);
    Gb(1, 5, 9, 13, BLAKE512_W, 2, 3);
    Gb(2, 6, 10, 14, BLAKE512_W, 4, 5);
    Gb(3, 7, 11, 15, BLAKE512_W, 6, 7);
    Gb(0, 5, 10, 15, BLAKE512_W, 8, 9);
    Gb(1, 6, 11, 12, BLAKE512_W, 10, 11);
    Gb(2, 7, 8, 13, BLAKE512_W, 12, 13);
    Gb(3, 4, 9, 14, BLAKE512_W, 14, 15);
    // Round 11
    Gb(0, 4, 8, 12, BLAKE512_W, 14, 10);
    Gb(1, 5, 9, 13, BLAKE512_W, 4, 8);
    Gb(2, 6, 10, 14, BLAKE512_W, 9, 15);
    Gb(3, 7, 11, 15, BLAKE512_W, 13, 6);
    Gb(0, 5, 10, 15, BLAKE512_W, 1, 12);
    Gb(1, 6, 11, 12, BLAKE512_W, 0, 2);
    Gb(2, 7, 8, 13, BLAKE512_W, 11, 7);
    Gb(3, 4, 9, 14, BLAKE512_W, 5, 3);
    // Round 12
    Gb(0, 4, 8, 12, BLAKE512_W, 11, 8);
    Gb(1, 5, 9, 13, BLAKE512_W, 12, 0);
    Gb(2, 6, 10, 14, BLAKE512_W, 5, 2);
    Gb(3, 7, 11, 15, BLAKE512_W, 15, 13);
    Gb(0, 5, 10, 15, BLAKE512_W, 10, 14);
    Gb(1, 6, 11, 12, BLAKE512_W, 3, 6);
    Gb(2, 7, 8, 13, BLAKE512_W, 7, 1);
    Gb(3, 4, 9, 14, BLAKE512_W, 9, 4);
    // Round 13
    Gb(0, 4, 8, 12, BLAKE512_W, 7, 9);
    Gb(1, 5, 9, 13, BLAKE512_W, 3, 1);
    Gb(2, 6, 10, 14, BLAKE512_W, 13, 12);
    Gb(3, 7, 11, 15, BLAKE512_W, 11, 14);
    Gb(0, 5, 10, 15, BLAKE512_W, 2, 6);
    Gb(1, 6, 11, 12, BLAKE512_W, 5, 10);
    Gb(2, 7, 8, 13, BLAKE512_W, 4, 0);
    Gb(3, 4, 9, 14, BLAKE512_W, 15, 8);
    // Round 14
    Gb(0, 4, 8, 12, BLAKE512_W, 9, 0);
    Gb(1, 5, 9, 13, BLAKE512_W, 5, 7);
    Gb(2, 6, 10, 14, BLAKE512_W, 2, 4);
    Gb(3, 7, 11, 15, BLAKE512_W, 10, 15);
    Gb(0, 5, 10, 15, BLAKE512_W, 14, 1);
    Gb(1, 6, 11, 12, BLAKE512_W, 11, 12);
    Gb(2, 7, 8, 13, BLAKE512_W, 6, 8);
    Gb(3, 4, 9, 14, BLAKE512_W, 3, 13);
    // Round 15
    Gb(0, 4, 8, 12, BLAKE512_W, 2, 12);
    Gb(1, 5, 9, 13, BLAKE512_W, 6, 10);
    Gb(2, 6, 10, 14, BLAKE512_W, 0, 11);
    Gb(3, 7, 11, 15, BLAKE512_W, 8, 3);
    Gb(0, 5, 10, 15, BLAKE512_W, 4, 13);
    Gb(1, 6, 11, 12, BLAKE512_W, 7, 5);
    Gb(2, 7, 8, 13, BLAKE512_W, 15, 14);
    Gb(3, 4, 9, 14, BLAKE512_W, 1, 9);
    // END generated BLAKE1-512 compression
    this.v0l ^= BBUF[0] ^ BBUF[16] ^ this.salt[0];
    this.v0h ^= BBUF[1] ^ BBUF[17] ^ this.salt[1];
    this.v1l ^= BBUF[2] ^ BBUF[18] ^ this.salt[2];
    this.v1h ^= BBUF[3] ^ BBUF[19] ^ this.salt[3];
    this.v2l ^= BBUF[4] ^ BBUF[20] ^ this.salt[4];
    this.v2h ^= BBUF[5] ^ BBUF[21] ^ this.salt[5];
    this.v3l ^= BBUF[6] ^ BBUF[22] ^ this.salt[6];
    this.v3h ^= BBUF[7] ^ BBUF[23] ^ this.salt[7];
    this.v4l ^= BBUF[8] ^ BBUF[24] ^ this.salt[0];
    this.v4h ^= BBUF[9] ^ BBUF[25] ^ this.salt[1];
    this.v5l ^= BBUF[10] ^ BBUF[26] ^ this.salt[2];
    this.v5h ^= BBUF[11] ^ BBUF[27] ^ this.salt[3];
    this.v6l ^= BBUF[12] ^ BBUF[28] ^ this.salt[4];
    this.v6h ^= BBUF[13] ^ BBUF[29] ^ this.salt[5];
    this.v7l ^= BBUF[14] ^ BBUF[30] ^ this.salt[6];
    this.v7h ^= BBUF[15] ^ BBUF[31] ^ this.salt[7];
    clean(BBUF, BLAKE512_W);
  }
}

/** Internal blake1-224 hash class. */
export class _BLAKE224 extends BLAKE1_32B {
  constructor(opts: BlakeOpts = {}) {
    super(28, B224_IV, 0b0000_0000, opts);
  }
}
/** Internal blake1-256 hash class. */
export class _BLAKE256 extends BLAKE1_32B {
  constructor(opts: BlakeOpts = {}) {
    super(32, B256_IV, 0b0000_0001, opts);
  }
}
/** Internal blake1-384 hash class. */
export class _BLAKE384 extends BLAKE1_64B {
  constructor(opts: BlakeOpts = {}) {
    super(48, B384_IV, 0b0000_0000, opts);
  }
}
/** Internal blake1-512 hash class. */
export class _BLAKE512 extends BLAKE1_64B {
  constructor(opts: BlakeOpts = {}) {
    super(64, B512_IV, 0b0000_0001, opts);
  }
}
/**
 * Blake1-224 hash function.
 * @param msg - message bytes to hash
 * @param opts - Optional Blake1 settings. See {@link BlakeOpts}. If set,
 *   `opts.salt` must be exactly 16 bytes.
 * @returns Digest bytes.
 * @example
 * Hash a message with Blake1-224.
 * ```ts
 * blake224(new Uint8Array([97, 98, 99]));
 * ```
 */
export const blake224: TRet<CHash<_BLAKE224, BlakeOpts>> = /* @__PURE__ */ createHasher(
  (opts) => new _BLAKE224(opts)
);
/**
 * Blake1-256 hash function.
 * @param msg - message bytes to hash
 * @param opts - Optional Blake1 settings. See {@link BlakeOpts}. If set,
 *   `opts.salt` must be exactly 16 bytes.
 * @returns Digest bytes.
 * @example
 * Hash a message with Blake1-256.
 * ```ts
 * blake256(new Uint8Array([97, 98, 99]));
 * ```
 * @example
 * Hash a message with Blake1-256 and a 16-byte salt.
 * ```ts
 * blake256(new Uint8Array([97, 98, 99]), { salt: new Uint8Array(16) });
 * ```
 */
export const blake256: TRet<CHash<_BLAKE256, BlakeOpts>> = /* @__PURE__ */ createHasher(
  (opts) => new _BLAKE256(opts)
);
/**
 * Blake1-384 hash function.
 * @param msg - message bytes to hash
 * @param opts - Optional Blake1 settings. See {@link BlakeOpts}. If set,
 *   `opts.salt` must be exactly 32 bytes.
 * @returns Digest bytes.
 * @example
 * Hash a message with Blake1-384.
 * ```ts
 * blake384(new Uint8Array([97, 98, 99]));
 * ```
 */
export const blake384: TRet<CHash<_BLAKE384, BlakeOpts>> = /* @__PURE__ */ createHasher(
  (opts) => new _BLAKE384(opts)
);
/**
 * Blake1-512 hash function.
 * @param msg - message bytes to hash
 * @param opts - Optional Blake1 settings. See {@link BlakeOpts}. If set,
 *   `opts.salt` must be exactly 32 bytes.
 * @returns Digest bytes.
 * @example
 * Hash a message with Blake1-512.
 * ```ts
 * blake512(new Uint8Array([97, 98, 99]));
 * ```
 */
export const blake512: TRet<CHash<_BLAKE512, BlakeOpts>> = /* @__PURE__ */ createHasher(
  (opts) => new _BLAKE512(opts)
);
