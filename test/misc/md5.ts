import { HashMD } from './_md.js';
import { rotl, wrapConstructor } from './utils.js';

// MD5 (RFC 1321) was cryptographically broken.
// It is still widely used in legacy apps. Don't use it for a new protocol.
// - Collisions: 2**18 (vs 2**60 for SHA1)
// - No practical pre-image attacks (only theoretical, 2**123.4)
// - HMAC seems kinda ok: https://datatracker.ietf.org/doc/html/rfc6151
// Architecture is similar to SHA1. Differences:
// - reduced output length: 16 bytes (128 bit) instead of 20
// - 64 rounds, instead of 80
// - little-endian: could be faster, but will require more code
// - non-linear index selection: huge speed-up for unroll
// - per round constants: more memory accesses, additional speed-up for unroll

// tests
// MD5: {
//   fn: md5,
//   obj: md5.create,
//   node: (buf) => Uint8Array.from(createHash('md5').update(buf).digest()),
//   node_obj: () => createHash('md5'),
//   nist: [
//     '90015098 3cd24fb0d 6963f7d2 8e17f72',
//     'd41d8cd9 8f00b204e 9800998e cf8427e',
//     '8215ef07 96a20bcaa ae116d38 76c664a',
//     '03dd8807 a93175fb0 62dfb55d c7d359c',
//     '7707d6ae 4e027c70e ea2a935c 2296f21',
//   ],
// },

// Per-round constants
const K = Array.from({ length: 64 }, (_, i) => Math.floor(2 ** 32 * Math.abs(Math.sin(i + 1))));

// Choice: a ? b : c
const Chi = (a: number, b: number, c: number) => (a & b) ^ (~a & c);

// Initial state (same as sha1, but 4 u32 instead of 5)
const IV = /* @__PURE__ */ new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

// Temporary buffer, not used to store anything between runs
// Named this way for SHA1 compat
const MD5_W = /* @__PURE__ */ new Uint32Array(16);
class MD5 extends HashMD<MD5> {
  private A = IV[0] | 0;
  private B = IV[1] | 0;
  private C = IV[2] | 0;
  private D = IV[3] | 0;

  constructor() {
    super(64, 16, 8, true);
  }
  protected get(): [number, number, number, number] {
    const { A, B, C, D } = this;
    return [A, B, C, D];
  }
  protected set(A: number, B: number, C: number, D: number) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
  }
  protected process(view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) MD5_W[i] = view.getUint32(offset, true);
    // Compression function main loop, 64 rounds
    let { A, B, C, D } = this;
    for (let i = 0; i < 64; i++) {
      let F, g, s;
      if (i < 16) {
        F = Chi(B, C, D);
        g = i;
        s = [7, 12, 17, 22];
      } else if (i < 32) {
        F = Chi(D, B, C);
        g = (5 * i + 1) % 16;
        s = [5, 9, 14, 20];
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
        s = [4, 11, 16, 23];
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
        s = [6, 10, 15, 21];
      }
      F = F + A + K[i] + MD5_W[g];
      A = D;
      D = C;
      C = B;
      B = B + rotl(F, s[i % 4]);
    }
    // Add the compressed chunk to the current hash value
    A = (A + this.A) | 0;
    B = (B + this.B) | 0;
    C = (C + this.C) | 0;
    D = (D + this.D) | 0;
    this.set(A, B, C, D);
  }
  protected roundClean() {
    MD5_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0);
    this.buffer.fill(0);
  }
}

export const md5 = /* @__PURE__ */ wrapConstructor(() => new MD5());
