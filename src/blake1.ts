/**
 * Blake1 legacy hash function, one of SHA3 proposals.
 * Rarely used. Check out blake2 or blake3 instead.
 * https://www.aumasson.jp/blake/blake.pdf
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
import { BSIGMA, G1s, G2s } from './_blake.ts';
import { SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from './_md.ts';
import * as u64 from './_u64.ts';
// prettier-ignore
import {
  abytes, aexists, aoutput,
  clean, createHasher,
  createView,
  type CHash,
  type Hash
} from './utils.ts';

/** Blake1 options. Basically just "salt" */
export type BlakeOpts = {
  salt?: Uint8Array;
};

// Empty zero-filled salt
const EMPTY_SALT = /* @__PURE__ */ new Uint32Array(8);

abstract class BLAKE1<T extends BLAKE1<T>> implements Hash<T> {
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
  protected abstract set(...args: number[]): void;

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
    const { salt } = opts;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.lengthFlag = lengthFlag;
    this.counterLen = counterLen;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
    if (salt) {
      let slt = salt;
      abytes(slt);
      if (slt.length !== 4 * saltLen) throw new Error('wrong salt length');
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
  update(data: Uint8Array): this {
    aexists(this);
    abytes(data);
    // From _md, but update length before each compress
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let dataView;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      // Fast path: we have at least one block in input, cast it to view and process
      if (take === blockLen) {
        if (!dataView) dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen) {
          this.length += blockLen;
          this.compress(dataView, pos);
        }
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
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
  _cloneInto(to?: T): T {
    to ||= new (this.constructor as any)() as T;
    to.set(...this.get());
    const { buffer, length, finished, destroyed, constants, salt, pos } = this;
    to.buffer.set(buffer);
    to.constants = constants.slice();
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    to.salt = salt.slice();
    return to;
  }
  clone(): T {
    return this._cloneInto();
  }
  digestInto(out: Uint8Array): void {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    // Padding
    const { buffer, blockLen, counterLen, lengthFlag, view } = this;
    clean(buffer.subarray(this.pos)); // clean buf
    const counter = BigInt((this.length + this.pos) * 8);
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
    view.setBigUint64(blockLen - 8, counter, false);
    this.compress(view, 0, this.pos !== 0); // don't add length if length is not empty block?
    // Write output
    clean(buffer);
    const v = createView(out);
    const state = this.get();
    for (let i = 0; i < this.outputLen / 4; ++i) v.setUint32(i * 4, state[i]);
  }
  digest(): Uint8Array {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
}

// Constants
const B64C = /* @__PURE__ */ Uint32Array.from([
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
  0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
]);
// first half of C512
const B32C = B64C.slice(0, 16);

const B256_IV = /* @__PURE__ */ SHA256_IV.slice();
const B224_IV = /* @__PURE__ */ SHA224_IV.slice();
const B384_IV = /* @__PURE__ */ SHA384_IV.slice();
const B512_IV = /* @__PURE__ */ SHA512_IV.slice();

function generateTBL256() {
  const TBL = [];
  for (let i = 0, j = 0; i < 14; i++, j += 16) {
    for (let offset = 1; offset < 16; offset += 2) {
      TBL.push(B32C[BSIGMA[j + offset]]);
      TBL.push(B32C[BSIGMA[j + offset - 1]]);
    }
  }
  return new Uint32Array(TBL);
}
const TBL256 = /* @__PURE__ */ generateTBL256(); // C256[SIGMA[X]] precompute

// Reusable temporary buffer
const BLAKE256_W = /* @__PURE__ */ new Uint32Array(16);

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
  destroy(): void {
    super.destroy();
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
  }
  compress(view: DataView, offset: number, withLength = true): void {
    for (let i = 0; i < 16; i++, offset += 4) BLAKE256_W[i] = view.getUint32(offset, false);
    // NOTE: we cannot re-use compress from blake2s, since there is additional xor over u256[SIGMA[e]]
    let v00 = this.v0 | 0;
    let v01 = this.v1 | 0;
    let v02 = this.v2 | 0;
    let v03 = this.v3 | 0;
    let v04 = this.v4 | 0;
    let v05 = this.v5 | 0;
    let v06 = this.v6 | 0;
    let v07 = this.v7 | 0;
    let v08 = this.constants[0] | 0;
    let v09 = this.constants[1] | 0;
    let v10 = this.constants[2] | 0;
    let v11 = this.constants[3] | 0;
    const { h, l } = u64.fromBig(BigInt(withLength ? this.length * 8 : 0));
    let v12 = (this.constants[4] ^ l) >>> 0;
    let v13 = (this.constants[5] ^ l) >>> 0;
    let v14 = (this.constants[6] ^ h) >>> 0;
    let v15 = (this.constants[7] ^ h) >>> 0;
    // prettier-ignore
    for (let i = 0, k = 0, j = 0; i < 14; i++) {
      ({ a: v00, b: v04, c: v08, d: v12 } = G1s(v00, v04, v08, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v00, b: v04, c: v08, d: v12 } = G2s(v00, v04, v08, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v01, b: v05, c: v09, d: v13 } = G1s(v01, v05, v09, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v01, b: v05, c: v09, d: v13 } = G2s(v01, v05, v09, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v02, b: v06, c: v10, d: v14 } = G1s(v02, v06, v10, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v02, b: v06, c: v10, d: v14 } = G2s(v02, v06, v10, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v03, b: v07, c: v11, d: v15 } = G1s(v03, v07, v11, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v03, b: v07, c: v11, d: v15 } = G2s(v03, v07, v11, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v00, b: v05, c: v10, d: v15 } = G1s(v00, v05, v10, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v00, b: v05, c: v10, d: v15 } = G2s(v00, v05, v10, v15, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v01, b: v06, c: v11, d: v12 } = G1s(v01, v06, v11, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v01, b: v06, c: v11, d: v12 } = G2s(v01, v06, v11, v12, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v02, b: v07, c: v08, d: v13 } = G1s(v02, v07, v08, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v02, b: v07, c: v08, d: v13 } = G2s(v02, v07, v08, v13, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v03, b: v04, c: v09, d: v14 } = G1s(v03, v04, v09, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
      ({ a: v03, b: v04, c: v09, d: v14 } = G2s(v03, v04, v09, v14, BLAKE256_W[BSIGMA[k++]] ^ TBL256[j++]));
    }
    this.v0 = (this.v0 ^ v00 ^ v08 ^ this.salt[0]) >>> 0;
    this.v1 = (this.v1 ^ v01 ^ v09 ^ this.salt[1]) >>> 0;
    this.v2 = (this.v2 ^ v02 ^ v10 ^ this.salt[2]) >>> 0;
    this.v3 = (this.v3 ^ v03 ^ v11 ^ this.salt[3]) >>> 0;
    this.v4 = (this.v4 ^ v04 ^ v12 ^ this.salt[0]) >>> 0;
    this.v5 = (this.v5 ^ v05 ^ v13 ^ this.salt[1]) >>> 0;
    this.v6 = (this.v6 ^ v06 ^ v14 ^ this.salt[2]) >>> 0;
    this.v7 = (this.v7 ^ v07 ^ v15 ^ this.salt[3]) >>> 0;
    clean(BLAKE256_W);
  }
}

const BBUF = /* @__PURE__ */ new Uint32Array(32);
const BLAKE512_W = /* @__PURE__ */ new Uint32Array(32);

function generateTBL512() {
  const TBL = [];
  for (let r = 0, k = 0; r < 16; r++, k += 16) {
    for (let offset = 1; offset < 16; offset += 2) {
      TBL.push(B64C[BSIGMA[k + offset] * 2 + 0]);
      TBL.push(B64C[BSIGMA[k + offset] * 2 + 1]);
      TBL.push(B64C[BSIGMA[k + offset - 1] * 2 + 0]);
      TBL.push(B64C[BSIGMA[k + offset - 1] * 2 + 1]);
    }
  }
  return new Uint32Array(TBL);
}
const TBL512 = /* @__PURE__ */ generateTBL512(); // C512[SIGMA[X]] precompute

// Mixing function G splitted in two halfs
function G1b(a: number, b: number, c: number, d: number, msg: Uint32Array, k: number) {
  const Xpos = 2 * BSIGMA[k];
  const Xl = msg[Xpos + 1] ^ TBL512[k * 2 + 1], Xh = msg[Xpos] ^ TBL512[k * 2]; // prettier-ignore
  let Al = BBUF[2 * a + 1], Ah = BBUF[2 * a]; // prettier-ignore
  let Bl = BBUF[2 * b + 1], Bh = BBUF[2 * b]; // prettier-ignore
  let Cl = BBUF[2 * c + 1], Ch = BBUF[2 * c]; // prettier-ignore
  let Dl = BBUF[2 * d + 1], Dh = BBUF[2 * d]; // prettier-ignore
  // v[a] = (v[a] + v[b] + x) | 0;
  let ll = u64.add3L(Al, Bl, Xl);
  Ah = u64.add3H(ll, Ah, Bh, Xh) >>> 0;
  Al = (ll | 0) >>> 0;
  // v[d] = rotr(v[d] ^ v[a], 32)
  ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
  ({ Dh, Dl } = { Dh: u64.rotr32H(Dh, Dl), Dl: u64.rotr32L(Dh, Dl) });
  // v[c] = (v[c] + v[d]) | 0;
  ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
  // v[b] = rotr(v[b] ^ v[c], 25)
  ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
  ({ Bh, Bl } = { Bh: u64.rotrSH(Bh, Bl, 25), Bl: u64.rotrSL(Bh, Bl, 25) });
  (BBUF[2 * a + 1] = Al), (BBUF[2 * a] = Ah);
  (BBUF[2 * b + 1] = Bl), (BBUF[2 * b] = Bh);
  (BBUF[2 * c + 1] = Cl), (BBUF[2 * c] = Ch);
  (BBUF[2 * d + 1] = Dl), (BBUF[2 * d] = Dh);
}

function G2b(a: number, b: number, c: number, d: number, msg: Uint32Array, k: number) {
  const Xpos = 2 * BSIGMA[k];
  const Xl = msg[Xpos + 1] ^ TBL512[k * 2 + 1], Xh = msg[Xpos] ^ TBL512[k * 2]; // prettier-ignore
  let Al = BBUF[2 * a + 1], Ah = BBUF[2 * a]; // prettier-ignore
  let Bl = BBUF[2 * b + 1], Bh = BBUF[2 * b]; // prettier-ignore
  let Cl = BBUF[2 * c + 1], Ch = BBUF[2 * c]; // prettier-ignore
  let Dl = BBUF[2 * d + 1], Dh = BBUF[2 * d]; // prettier-ignore
  // v[a] = (v[a] + v[b] + x) | 0;
  let ll = u64.add3L(Al, Bl, Xl);
  Ah = u64.add3H(ll, Ah, Bh, Xh);
  Al = ll | 0;
  // v[d] = rotr(v[d] ^ v[a], 16)
  ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
  ({ Dh, Dl } = { Dh: u64.rotrSH(Dh, Dl, 16), Dl: u64.rotrSL(Dh, Dl, 16) });
  // v[c] = (v[c] + v[d]) | 0;
  ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
  // v[b] = rotr(v[b] ^ v[c], 11)
  ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
  ({ Bh, Bl } = { Bh: u64.rotrSH(Bh, Bl, 11), Bl: u64.rotrSL(Bh, Bl, 11) });
  (BBUF[2 * a + 1] = Al), (BBUF[2 * a] = Ah);
  (BBUF[2 * b + 1] = Bl), (BBUF[2 * b] = Bh);
  (BBUF[2 * c + 1] = Cl), (BBUF[2 * c] = Ch);
  (BBUF[2 * d + 1] = Dl), (BBUF[2 * d] = Dh);
}

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
  destroy(): void {
    super.destroy();
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
  compress(view: DataView, offset: number, withLength = true): void {
    for (let i = 0; i < 32; i++, offset += 4) BLAKE512_W[i] = view.getUint32(offset, false);

    this.get().forEach((v, i) => (BBUF[i] = v)); // First half from state.
    BBUF.set(this.constants.subarray(0, 16), 16);
    if (withLength) {
      const { h, l } = u64.fromBig(BigInt(this.length * 8));
      BBUF[24] = (BBUF[24] ^ h) >>> 0;
      BBUF[25] = (BBUF[25] ^ l) >>> 0;
      BBUF[26] = (BBUF[26] ^ h) >>> 0;
      BBUF[27] = (BBUF[27] ^ l) >>> 0;
    }
    for (let i = 0, k = 0; i < 16; i++) {
      G1b(0, 4, 8, 12, BLAKE512_W, k++);
      G2b(0, 4, 8, 12, BLAKE512_W, k++);
      G1b(1, 5, 9, 13, BLAKE512_W, k++);
      G2b(1, 5, 9, 13, BLAKE512_W, k++);
      G1b(2, 6, 10, 14, BLAKE512_W, k++);
      G2b(2, 6, 10, 14, BLAKE512_W, k++);
      G1b(3, 7, 11, 15, BLAKE512_W, k++);
      G2b(3, 7, 11, 15, BLAKE512_W, k++);

      G1b(0, 5, 10, 15, BLAKE512_W, k++);
      G2b(0, 5, 10, 15, BLAKE512_W, k++);
      G1b(1, 6, 11, 12, BLAKE512_W, k++);
      G2b(1, 6, 11, 12, BLAKE512_W, k++);
      G1b(2, 7, 8, 13, BLAKE512_W, k++);
      G2b(2, 7, 8, 13, BLAKE512_W, k++);
      G1b(3, 4, 9, 14, BLAKE512_W, k++);
      G2b(3, 4, 9, 14, BLAKE512_W, k++);
    }
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
export class BLAKE224 extends BLAKE1_32B {
  constructor(opts: BlakeOpts = {}) {
    super(28, B224_IV, 0b0000_0000, opts);
  }
}
/** Internal blake1-256 hash class. */
export class BLAKE256 extends BLAKE1_32B {
  constructor(opts: BlakeOpts = {}) {
    super(32, B256_IV, 0b0000_0001, opts);
  }
}
/** Internal blake1-384 hash class. */
export class BLAKE384 extends BLAKE1_64B {
  constructor(opts: BlakeOpts = {}) {
    super(48, B384_IV, 0b0000_0000, opts);
  }
}
/** Internal blake1-512 hash class. */
export class BLAKE512 extends BLAKE1_64B {
  constructor(opts: BlakeOpts = {}) {
    super(64, B512_IV, 0b0000_0001, opts);
  }
}
/** blake1-224 hash function */
export const blake224: CHash<BLAKE224, BlakeOpts> = /* @__PURE__ */ createHasher<
  BLAKE224,
  BlakeOpts
>((opts) => new BLAKE224(opts));
/** blake1-256 hash function */
export const blake256: CHash<BLAKE256, BlakeOpts> = /* @__PURE__ */ createHasher<
  BLAKE256,
  BlakeOpts
>((opts) => new BLAKE256(opts));
/** blake1-384 hash function */
export const blake384: CHash<BLAKE384, BlakeOpts> = /* @__PURE__ */ createHasher<
  BLAKE512,
  BlakeOpts
>((opts) => new BLAKE384(opts));
/** blake1-512 hash function */
export const blake512: CHash<BLAKE512, BlakeOpts> = /* @__PURE__ */ createHasher<
  BLAKE512,
  BlakeOpts
>((opts) => new BLAKE512(opts));
