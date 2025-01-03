/**
 * RIPEMD-160 legacy hash function.
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 * @module
 */
import { HashMD } from './_md.js';
import { rotl, wrapConstructor, CHash } from './utils.js';

const Rho = /* @__PURE__ */ new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
const Id = /* @__PURE__ */ new Uint8Array(new Array(16).fill(0).map((_, i) => i));
const Pi = /* @__PURE__ */ Id.map((i) => (9 * i + 5) % 16);
let idxL = [Id];
let idxR = [Pi];
for (let i = 0; i < 4; i++) for (let j of [idxL, idxR]) j.push(j[i].map((k) => Rho[k]));

const shifts = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => new Uint8Array(i));
const shiftsL = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
const shiftsR = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
const Kl = /* @__PURE__ */ new Uint32Array([
  0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e,
]);
const Kr = /* @__PURE__ */ new Uint32Array([
  0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000,
]);
// It's called f() in spec.
function f(group: number, x: number, y: number, z: number): number {
  if (group === 0) return x ^ y ^ z;
  else if (group === 1) return (x & y) | (~x & z);
  else if (group === 2) return (x | ~y) ^ z;
  else if (group === 3) return (x & z) | (y & ~z);
  else return x ^ (y | ~z);
}
// Temporary buffer, not used to store anything between runs
const R_BUF = /* @__PURE__ */ new Uint32Array(16);
export class RIPEMD160 extends HashMD<RIPEMD160> {
  private h0 = 0x67452301 | 0;
  private h1 = 0xefcdab89 | 0;
  private h2 = 0x98badcfe | 0;
  private h3 = 0x10325476 | 0;
  private h4 = 0xc3d2e1f0 | 0;

  constructor() {
    super(64, 20, 8, true);
  }
  protected get(): [number, number, number, number, number] {
    const { h0, h1, h2, h3, h4 } = this;
    return [h0, h1, h2, h3, h4];
  }
  protected set(h0: number, h1: number, h2: number, h3: number, h4: number): void {
    this.h0 = h0 | 0;
    this.h1 = h1 | 0;
    this.h2 = h2 | 0;
    this.h3 = h3 | 0;
    this.h4 = h4 | 0;
  }
  protected process(view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) R_BUF[i] = view.getUint32(offset, true);
    // prettier-ignore
    let al = this.h0 | 0, ar = al,
        bl = this.h1 | 0, br = bl,
        cl = this.h2 | 0, cr = cl,
        dl = this.h3 | 0, dr = dl,
        el = this.h4 | 0, er = el;

    // Instead of iterating 0 to 80, we split it into 5 groups
    // And use the groups in constants, functions, etc. Much simpler
    for (let group = 0; group < 5; group++) {
      const rGroup = 4 - group;
      const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
      const rl = idxL[group], rr = idxR[group]; // prettier-ignore
      const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
      for (let i = 0; i < 16; i++) {
        const tl = (rotl(al + f(group, bl, cl, dl) + R_BUF[rl[i]] + hbl, sl[i]) + el) | 0;
        al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
      }
      // 2 loops are 10% faster
      for (let i = 0; i < 16; i++) {
        const tr = (rotl(ar + f(rGroup, br, cr, dr) + R_BUF[rr[i]] + hbr, sr[i]) + er) | 0;
        ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
      }
    }
    // Add the compressed chunk to the current hash value
    this.set(
      (this.h1 + cl + dr) | 0,
      (this.h2 + dl + er) | 0,
      (this.h3 + el + ar) | 0,
      (this.h4 + al + br) | 0,
      (this.h0 + bl + cr) | 0
    );
  }
  protected roundClean(): void {
    R_BUF.fill(0);
  }
  destroy(): void {
    this.destroyed = true;
    this.buffer.fill(0);
    this.set(0, 0, 0, 0, 0);
  }
}

/** RIPEMD-160 - a legacy hash function from 1990s. */
export const ripemd160: CHash = /* @__PURE__ */ wrapConstructor(() => new RIPEMD160());
