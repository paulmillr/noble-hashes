/**
 * RFC 7914 Scrypt KDF. Can be used to create a key from password and salt.
 * @module
 */
import { hmac } from './hmac.ts';
import { sha256 } from './sha2.ts';
// prettier-ignore
import {
  anumber, asyncLoop,
  checkOpts, clean, createView, kdfInputToBytes,
  rotl,
  swap32IfBE,
  u32,
  type KDFInput,
  type TArg,
  type TRet
} from './utils.ts';

// Exact PBKDF2-HMAC-SHA256(c=1) subset used by RFC 7914's two PBKDF2 stages.
// This deliberately mirrors the generic engine's conversion, allocation, clone, truncation,
// destruction, and error order while omitting its variable-hash/options/feedback machinery.
function scryptPbkdf2(password: TArg<KDFInput>, salt: TArg<KDFInput>, dkLen: number) {
  const p = kdfInputToBytes(password, 'password');
  const s = kdfInputToBytes(salt, 'salt');
  const DK = new Uint8Array(dkLen);
  const { iHash, oHash, outputLen } = hmac.create(sha256, p);
  const u = new Uint8Array(outputLen);
  const counter = new Uint8Array(4);
  const view = createView(counter);
  const salted = iHash._cloneInto().update(s);
  const work = oHash._cloneInto();
  // The generic c=1 engine captures these feedback clone methods even though c=1 has no feedback
  // round. Preserve the two observable property reads for patched prototype accessors.
  void iHash._cloneInto;
  void oHash._cloneInto;
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += outputLen) {
    const Ti = DK.subarray(pos, pos + outputLen);
    view.setInt32(0, ti, false);
    salted._cloneInto(work).update(counter).digestInto(u);
    oHash._cloneInto(work).update(u).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
  }
  iHash.destroy();
  oHash.destroy();
  salted.destroy();
  work.destroy();
  clean(u);
  return DK as TRet<Uint8Array>;
}

// The main Scrypt loop: uses Salsa extensively.
// Six versions of the function were tried, this is the fastest one.
// RFC 7914 §3 / §4 step 2 applies Salsa20/8 to one 16-word (64-byte) block
// after xor'ing two such blocks.
// The local `y*` snapshot keeps the xor input stable even when `out` aliases `prev` or `input`.
// prettier-ignore
function XorAndSalsa(
  prev: TArg<Uint32Array>,
  pi: number,
  input: TArg<Uint32Array>,
  ii: number,
  out: TArg<Uint32Array>,
  oi: number
) {
  // Based on https://cr.yp.to/salsa20.html and RFC 7914's Salsa20/8 core.
  // Xor blocks
  let y00 = prev[pi++] ^ input[ii++], y01 = prev[pi++] ^ input[ii++];
  let y02 = prev[pi++] ^ input[ii++], y03 = prev[pi++] ^ input[ii++];
  let y04 = prev[pi++] ^ input[ii++], y05 = prev[pi++] ^ input[ii++];
  let y06 = prev[pi++] ^ input[ii++], y07 = prev[pi++] ^ input[ii++];
  let y08 = prev[pi++] ^ input[ii++], y09 = prev[pi++] ^ input[ii++];
  let y10 = prev[pi++] ^ input[ii++], y11 = prev[pi++] ^ input[ii++];
  let y12 = prev[pi++] ^ input[ii++], y13 = prev[pi++] ^ input[ii++];
  let y14 = prev[pi++] ^ input[ii++], y15 = prev[pi++] ^ input[ii++];
  // Save state to temporary variables (salsa)
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  // Main loop (salsa)
  for (let i = 0; i < 8; i += 2) {
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0,  9);
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18);
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0,  9);
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18);
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0,  9);
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18);
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0,  9);
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18);
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0,  9);
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18);
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0,  9);
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18);
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0,  9);
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18);
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0,  9);
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18);
  }
  // Write output (salsa)
  out[oi++] = (y00 + x00) | 0; out[oi++] = (y01 + x01) | 0;
  out[oi++] = (y02 + x02) | 0; out[oi++] = (y03 + x03) | 0;
  out[oi++] = (y04 + x04) | 0; out[oi++] = (y05 + x05) | 0;
  out[oi++] = (y06 + x06) | 0; out[oi++] = (y07 + x07) | 0;
  out[oi++] = (y08 + x08) | 0; out[oi++] = (y09 + x09) | 0;
  out[oi++] = (y10 + x10) | 0; out[oi++] = (y11 + x11) | 0;
  out[oi++] = (y12 + x12) | 0; out[oi++] = (y13 + x13) | 0;
  out[oi++] = (y14 + x14) | 0; out[oi++] = (y15 + x15) | 0;
}

function BlockMixBase(
  input: TArg<Uint32Array>,
  ii: number,
  out: TArg<Uint32Array>,
  oi: number,
  r: number
) {
  // The block B is `r` 128-byte chunks, i.e. `2r` 16-word (64-byte) Salsa blocks.
  let head = oi;
  let tail = oi + 16 * r;
  // The first previous block can be read directly from B[2r-1]. Later previous blocks already
  // live in `out`; splitting the first pair removes a 16-word copy and the old per-pair branch.
  XorAndSalsa(input, ii + (2 * r - 1) * 16, input, ii, out, head);
  XorAndSalsa(out, head, input, ii + 16, out, tail);
  head += 16;
  tail += 16;
  ii += 32;
  for (let i = 1; i < r; i++, head += 16, tail += 16, ii += 32) {
    // RFC 7914 §4 step 3 outputs `Y[0], Y[2], ...` first, then `Y[1], Y[3], ...`;
    // `head` and `tail` lay out those even/odd halves in place.
    XorAndSalsa(out, tail - 16, input, ii, out, head);
    // tail[i] = Salsa(blockIn[2*i+1] ^ head[i])
    XorAndSalsa(out, head, input, ii + 16, out, tail);
  }
}

// BEGIN generated scrypt scalar BlockMix
// Generated by test/misc/unrolled-scrypt.js. Do not edit by hand.
// Carrying the chaining block in scalars avoids 15 intermediate 64-byte output reloads at r=8.
// prettier-ignore
function BlockMixScalar(
  input: TArg<Uint32Array>,
  ii: number,
  out: TArg<Uint32Array>,
  oi: number,
  r: number
) {
  let head = oi;
  let tail = oi + 16 * r;
  let si = ii + (2 * r - 1) * 16;
  let s00 = input[si++], s01 = input[si++];
  let s02 = input[si++], s03 = input[si++];
  let s04 = input[si++], s05 = input[si++];
  let s06 = input[si++], s07 = input[si++];
  let s08 = input[si++], s09 = input[si++];
  let s10 = input[si++], s11 = input[si++];
  let s12 = input[si++], s13 = input[si++];
  let s14 = input[si++], s15 = input[si++];
  for (let block = 0; block < r; block++) {
  let y00 = s00 ^ input[ii++], y01 = s01 ^ input[ii++];
  let y02 = s02 ^ input[ii++], y03 = s03 ^ input[ii++];
  let y04 = s04 ^ input[ii++], y05 = s05 ^ input[ii++];
  let y06 = s06 ^ input[ii++], y07 = s07 ^ input[ii++];
  let y08 = s08 ^ input[ii++], y09 = s09 ^ input[ii++];
  let y10 = s10 ^ input[ii++], y11 = s11 ^ input[ii++];
  let y12 = s12 ^ input[ii++], y13 = s13 ^ input[ii++];
  let y14 = s14 ^ input[ii++], y15 = s15 ^ input[ii++];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let round = 0; round < 4; round += 2) {
    x04 ^= ((x00 + x12 | 0) << 7) | ((x00 + x12 | 0) >>> 25); x08 ^= ((x04 + x00 | 0) << 9) | ((x04 + x00 | 0) >>> 23);
    x12 ^= ((x08 + x04 | 0) << 13) | ((x08 + x04 | 0) >>> 19); x00 ^= ((x12 + x08 | 0) << 18) | ((x12 + x08 | 0) >>> 14);
    x09 ^= ((x05 + x01 | 0) << 7) | ((x05 + x01 | 0) >>> 25); x13 ^= ((x09 + x05 | 0) << 9) | ((x09 + x05 | 0) >>> 23);
    x01 ^= ((x13 + x09 | 0) << 13) | ((x13 + x09 | 0) >>> 19); x05 ^= ((x01 + x13 | 0) << 18) | ((x01 + x13 | 0) >>> 14);
    x14 ^= ((x10 + x06 | 0) << 7) | ((x10 + x06 | 0) >>> 25); x02 ^= ((x14 + x10 | 0) << 9) | ((x14 + x10 | 0) >>> 23);
    x06 ^= ((x02 + x14 | 0) << 13) | ((x02 + x14 | 0) >>> 19); x10 ^= ((x06 + x02 | 0) << 18) | ((x06 + x02 | 0) >>> 14);
    x03 ^= ((x15 + x11 | 0) << 7) | ((x15 + x11 | 0) >>> 25); x07 ^= ((x03 + x15 | 0) << 9) | ((x03 + x15 | 0) >>> 23);
    x11 ^= ((x07 + x03 | 0) << 13) | ((x07 + x03 | 0) >>> 19); x15 ^= ((x11 + x07 | 0) << 18) | ((x11 + x07 | 0) >>> 14);
    x01 ^= ((x00 + x03 | 0) << 7) | ((x00 + x03 | 0) >>> 25); x02 ^= ((x01 + x00 | 0) << 9) | ((x01 + x00 | 0) >>> 23);
    x03 ^= ((x02 + x01 | 0) << 13) | ((x02 + x01 | 0) >>> 19); x00 ^= ((x03 + x02 | 0) << 18) | ((x03 + x02 | 0) >>> 14);
    x06 ^= ((x05 + x04 | 0) << 7) | ((x05 + x04 | 0) >>> 25); x07 ^= ((x06 + x05 | 0) << 9) | ((x06 + x05 | 0) >>> 23);
    x04 ^= ((x07 + x06 | 0) << 13) | ((x07 + x06 | 0) >>> 19); x05 ^= ((x04 + x07 | 0) << 18) | ((x04 + x07 | 0) >>> 14);
    x11 ^= ((x10 + x09 | 0) << 7) | ((x10 + x09 | 0) >>> 25); x08 ^= ((x11 + x10 | 0) << 9) | ((x11 + x10 | 0) >>> 23);
    x09 ^= ((x08 + x11 | 0) << 13) | ((x08 + x11 | 0) >>> 19); x10 ^= ((x09 + x08 | 0) << 18) | ((x09 + x08 | 0) >>> 14);
    x12 ^= ((x15 + x14 | 0) << 7) | ((x15 + x14 | 0) >>> 25); x13 ^= ((x12 + x15 | 0) << 9) | ((x12 + x15 | 0) >>> 23);
    x14 ^= ((x13 + x12 | 0) << 13) | ((x13 + x12 | 0) >>> 19); x15 ^= ((x14 + x13 | 0) << 18) | ((x14 + x13 | 0) >>> 14);
    x04 ^= ((x00 + x12 | 0) << 7) | ((x00 + x12 | 0) >>> 25); x08 ^= ((x04 + x00 | 0) << 9) | ((x04 + x00 | 0) >>> 23);
    x12 ^= ((x08 + x04 | 0) << 13) | ((x08 + x04 | 0) >>> 19); x00 ^= ((x12 + x08 | 0) << 18) | ((x12 + x08 | 0) >>> 14);
    x09 ^= ((x05 + x01 | 0) << 7) | ((x05 + x01 | 0) >>> 25); x13 ^= ((x09 + x05 | 0) << 9) | ((x09 + x05 | 0) >>> 23);
    x01 ^= ((x13 + x09 | 0) << 13) | ((x13 + x09 | 0) >>> 19); x05 ^= ((x01 + x13 | 0) << 18) | ((x01 + x13 | 0) >>> 14);
    x14 ^= ((x10 + x06 | 0) << 7) | ((x10 + x06 | 0) >>> 25); x02 ^= ((x14 + x10 | 0) << 9) | ((x14 + x10 | 0) >>> 23);
    x06 ^= ((x02 + x14 | 0) << 13) | ((x02 + x14 | 0) >>> 19); x10 ^= ((x06 + x02 | 0) << 18) | ((x06 + x02 | 0) >>> 14);
    x03 ^= ((x15 + x11 | 0) << 7) | ((x15 + x11 | 0) >>> 25); x07 ^= ((x03 + x15 | 0) << 9) | ((x03 + x15 | 0) >>> 23);
    x11 ^= ((x07 + x03 | 0) << 13) | ((x07 + x03 | 0) >>> 19); x15 ^= ((x11 + x07 | 0) << 18) | ((x11 + x07 | 0) >>> 14);
    x01 ^= ((x00 + x03 | 0) << 7) | ((x00 + x03 | 0) >>> 25); x02 ^= ((x01 + x00 | 0) << 9) | ((x01 + x00 | 0) >>> 23);
    x03 ^= ((x02 + x01 | 0) << 13) | ((x02 + x01 | 0) >>> 19); x00 ^= ((x03 + x02 | 0) << 18) | ((x03 + x02 | 0) >>> 14);
    x06 ^= ((x05 + x04 | 0) << 7) | ((x05 + x04 | 0) >>> 25); x07 ^= ((x06 + x05 | 0) << 9) | ((x06 + x05 | 0) >>> 23);
    x04 ^= ((x07 + x06 | 0) << 13) | ((x07 + x06 | 0) >>> 19); x05 ^= ((x04 + x07 | 0) << 18) | ((x04 + x07 | 0) >>> 14);
    x11 ^= ((x10 + x09 | 0) << 7) | ((x10 + x09 | 0) >>> 25); x08 ^= ((x11 + x10 | 0) << 9) | ((x11 + x10 | 0) >>> 23);
    x09 ^= ((x08 + x11 | 0) << 13) | ((x08 + x11 | 0) >>> 19); x10 ^= ((x09 + x08 | 0) << 18) | ((x09 + x08 | 0) >>> 14);
    x12 ^= ((x15 + x14 | 0) << 7) | ((x15 + x14 | 0) >>> 25); x13 ^= ((x12 + x15 | 0) << 9) | ((x12 + x15 | 0) >>> 23);
    x14 ^= ((x13 + x12 | 0) << 13) | ((x13 + x12 | 0) >>> 19); x15 ^= ((x14 + x13 | 0) << 18) | ((x14 + x13 | 0) >>> 14);
  }
  s00 = (y00 + x00) | 0; out[head++] = s00; s01 = (y01 + x01) | 0; out[head++] = s01;
  s02 = (y02 + x02) | 0; out[head++] = s02; s03 = (y03 + x03) | 0; out[head++] = s03;
  s04 = (y04 + x04) | 0; out[head++] = s04; s05 = (y05 + x05) | 0; out[head++] = s05;
  s06 = (y06 + x06) | 0; out[head++] = s06; s07 = (y07 + x07) | 0; out[head++] = s07;
  s08 = (y08 + x08) | 0; out[head++] = s08; s09 = (y09 + x09) | 0; out[head++] = s09;
  s10 = (y10 + x10) | 0; out[head++] = s10; s11 = (y11 + x11) | 0; out[head++] = s11;
  s12 = (y12 + x12) | 0; out[head++] = s12; s13 = (y13 + x13) | 0; out[head++] = s13;
  s14 = (y14 + x14) | 0; out[head++] = s14; s15 = (y15 + x15) | 0; out[head++] = s15;
  y00 = s00 ^ input[ii++], y01 = s01 ^ input[ii++];
  y02 = s02 ^ input[ii++], y03 = s03 ^ input[ii++];
  y04 = s04 ^ input[ii++], y05 = s05 ^ input[ii++];
  y06 = s06 ^ input[ii++], y07 = s07 ^ input[ii++];
  y08 = s08 ^ input[ii++], y09 = s09 ^ input[ii++];
  y10 = s10 ^ input[ii++], y11 = s11 ^ input[ii++];
  y12 = s12 ^ input[ii++], y13 = s13 ^ input[ii++];
  y14 = s14 ^ input[ii++], y15 = s15 ^ input[ii++];
  x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let round = 0; round < 4; round += 2) {
    x04 ^= ((x00 + x12 | 0) << 7) | ((x00 + x12 | 0) >>> 25); x08 ^= ((x04 + x00 | 0) << 9) | ((x04 + x00 | 0) >>> 23);
    x12 ^= ((x08 + x04 | 0) << 13) | ((x08 + x04 | 0) >>> 19); x00 ^= ((x12 + x08 | 0) << 18) | ((x12 + x08 | 0) >>> 14);
    x09 ^= ((x05 + x01 | 0) << 7) | ((x05 + x01 | 0) >>> 25); x13 ^= ((x09 + x05 | 0) << 9) | ((x09 + x05 | 0) >>> 23);
    x01 ^= ((x13 + x09 | 0) << 13) | ((x13 + x09 | 0) >>> 19); x05 ^= ((x01 + x13 | 0) << 18) | ((x01 + x13 | 0) >>> 14);
    x14 ^= ((x10 + x06 | 0) << 7) | ((x10 + x06 | 0) >>> 25); x02 ^= ((x14 + x10 | 0) << 9) | ((x14 + x10 | 0) >>> 23);
    x06 ^= ((x02 + x14 | 0) << 13) | ((x02 + x14 | 0) >>> 19); x10 ^= ((x06 + x02 | 0) << 18) | ((x06 + x02 | 0) >>> 14);
    x03 ^= ((x15 + x11 | 0) << 7) | ((x15 + x11 | 0) >>> 25); x07 ^= ((x03 + x15 | 0) << 9) | ((x03 + x15 | 0) >>> 23);
    x11 ^= ((x07 + x03 | 0) << 13) | ((x07 + x03 | 0) >>> 19); x15 ^= ((x11 + x07 | 0) << 18) | ((x11 + x07 | 0) >>> 14);
    x01 ^= ((x00 + x03 | 0) << 7) | ((x00 + x03 | 0) >>> 25); x02 ^= ((x01 + x00 | 0) << 9) | ((x01 + x00 | 0) >>> 23);
    x03 ^= ((x02 + x01 | 0) << 13) | ((x02 + x01 | 0) >>> 19); x00 ^= ((x03 + x02 | 0) << 18) | ((x03 + x02 | 0) >>> 14);
    x06 ^= ((x05 + x04 | 0) << 7) | ((x05 + x04 | 0) >>> 25); x07 ^= ((x06 + x05 | 0) << 9) | ((x06 + x05 | 0) >>> 23);
    x04 ^= ((x07 + x06 | 0) << 13) | ((x07 + x06 | 0) >>> 19); x05 ^= ((x04 + x07 | 0) << 18) | ((x04 + x07 | 0) >>> 14);
    x11 ^= ((x10 + x09 | 0) << 7) | ((x10 + x09 | 0) >>> 25); x08 ^= ((x11 + x10 | 0) << 9) | ((x11 + x10 | 0) >>> 23);
    x09 ^= ((x08 + x11 | 0) << 13) | ((x08 + x11 | 0) >>> 19); x10 ^= ((x09 + x08 | 0) << 18) | ((x09 + x08 | 0) >>> 14);
    x12 ^= ((x15 + x14 | 0) << 7) | ((x15 + x14 | 0) >>> 25); x13 ^= ((x12 + x15 | 0) << 9) | ((x12 + x15 | 0) >>> 23);
    x14 ^= ((x13 + x12 | 0) << 13) | ((x13 + x12 | 0) >>> 19); x15 ^= ((x14 + x13 | 0) << 18) | ((x14 + x13 | 0) >>> 14);
    x04 ^= ((x00 + x12 | 0) << 7) | ((x00 + x12 | 0) >>> 25); x08 ^= ((x04 + x00 | 0) << 9) | ((x04 + x00 | 0) >>> 23);
    x12 ^= ((x08 + x04 | 0) << 13) | ((x08 + x04 | 0) >>> 19); x00 ^= ((x12 + x08 | 0) << 18) | ((x12 + x08 | 0) >>> 14);
    x09 ^= ((x05 + x01 | 0) << 7) | ((x05 + x01 | 0) >>> 25); x13 ^= ((x09 + x05 | 0) << 9) | ((x09 + x05 | 0) >>> 23);
    x01 ^= ((x13 + x09 | 0) << 13) | ((x13 + x09 | 0) >>> 19); x05 ^= ((x01 + x13 | 0) << 18) | ((x01 + x13 | 0) >>> 14);
    x14 ^= ((x10 + x06 | 0) << 7) | ((x10 + x06 | 0) >>> 25); x02 ^= ((x14 + x10 | 0) << 9) | ((x14 + x10 | 0) >>> 23);
    x06 ^= ((x02 + x14 | 0) << 13) | ((x02 + x14 | 0) >>> 19); x10 ^= ((x06 + x02 | 0) << 18) | ((x06 + x02 | 0) >>> 14);
    x03 ^= ((x15 + x11 | 0) << 7) | ((x15 + x11 | 0) >>> 25); x07 ^= ((x03 + x15 | 0) << 9) | ((x03 + x15 | 0) >>> 23);
    x11 ^= ((x07 + x03 | 0) << 13) | ((x07 + x03 | 0) >>> 19); x15 ^= ((x11 + x07 | 0) << 18) | ((x11 + x07 | 0) >>> 14);
    x01 ^= ((x00 + x03 | 0) << 7) | ((x00 + x03 | 0) >>> 25); x02 ^= ((x01 + x00 | 0) << 9) | ((x01 + x00 | 0) >>> 23);
    x03 ^= ((x02 + x01 | 0) << 13) | ((x02 + x01 | 0) >>> 19); x00 ^= ((x03 + x02 | 0) << 18) | ((x03 + x02 | 0) >>> 14);
    x06 ^= ((x05 + x04 | 0) << 7) | ((x05 + x04 | 0) >>> 25); x07 ^= ((x06 + x05 | 0) << 9) | ((x06 + x05 | 0) >>> 23);
    x04 ^= ((x07 + x06 | 0) << 13) | ((x07 + x06 | 0) >>> 19); x05 ^= ((x04 + x07 | 0) << 18) | ((x04 + x07 | 0) >>> 14);
    x11 ^= ((x10 + x09 | 0) << 7) | ((x10 + x09 | 0) >>> 25); x08 ^= ((x11 + x10 | 0) << 9) | ((x11 + x10 | 0) >>> 23);
    x09 ^= ((x08 + x11 | 0) << 13) | ((x08 + x11 | 0) >>> 19); x10 ^= ((x09 + x08 | 0) << 18) | ((x09 + x08 | 0) >>> 14);
    x12 ^= ((x15 + x14 | 0) << 7) | ((x15 + x14 | 0) >>> 25); x13 ^= ((x12 + x15 | 0) << 9) | ((x12 + x15 | 0) >>> 23);
    x14 ^= ((x13 + x12 | 0) << 13) | ((x13 + x12 | 0) >>> 19); x15 ^= ((x14 + x13 | 0) << 18) | ((x14 + x13 | 0) >>> 14);
  }
  s00 = (y00 + x00) | 0; out[tail++] = s00; s01 = (y01 + x01) | 0; out[tail++] = s01;
  s02 = (y02 + x02) | 0; out[tail++] = s02; s03 = (y03 + x03) | 0; out[tail++] = s03;
  s04 = (y04 + x04) | 0; out[tail++] = s04; s05 = (y05 + x05) | 0; out[tail++] = s05;
  s06 = (y06 + x06) | 0; out[tail++] = s06; s07 = (y07 + x07) | 0; out[tail++] = s07;
  s08 = (y08 + x08) | 0; out[tail++] = s08; s09 = (y09 + x09) | 0; out[tail++] = s09;
  s10 = (y10 + x10) | 0; out[tail++] = s10; s11 = (y11 + x11) | 0; out[tail++] = s11;
  s12 = (y12 + x12) | 0; out[tail++] = s12; s13 = (y13 + x13) | 0; out[tail++] = s13;
  s14 = (y14 + x14) | 0; out[tail++] = s14; s15 = (y15 + x15) | 0; out[tail++] = s15;
  }
}
// END generated scrypt scalar BlockMix
/**
 * Scrypt options:
 * - `N` is cpu/mem work factor (power of 2 e.g. `2**18`)
 * - `r` is block size (8 is common), fine-tunes sequential memory read size and performance
 * - `p` is parallelization factor (1 is common)
 * - `dkLen` is output key length in bytes e.g. 32, and must be `>= 1` per RFC 7914 §2.
 * - `asyncTick` - (default: 10) max time in ms for which async function can block execution
 * - `maxmem` - (default: `1024 ** 3 + 1024` aka 1GB+1KB). A limit that the app could use for scrypt
 * - `onProgress` - callback function that would be executed for progress report
 */
export type ScryptOpts = {
  /** CPU and memory work factor. Must be a power of two. */
  N: number;
  /** Block size parameter. */
  r: number;
  /** Parallelization factor. */
  p: number;
  /** Desired derived key length in bytes, must be `>= 1` per RFC 7914 §2. */
  dkLen?: number;
  /** Max scheduler block time in milliseconds for the async variant. */
  asyncTick?: number;
  /** Maximum temporary memory budget in bytes. */
  maxmem?: number;
  /**
   * Optional progress callback invoked during long-running derivations.
   * @param progress - completion fraction in the `0..1` range
   * Should not throw; if it does, derivation is aborted and scrypt work
   * buffers are wiped before the error propagates.
   */
  onProgress?: (progress: number) => void;
};

// Common prologue and epilogue for sync/async functions
function scryptInit(password: TArg<KDFInput>, salt: TArg<KDFInput>, _opts?: ScryptOpts) {
  // Maxmem - 1GB+1KB by default
  const opts = checkOpts(
    {
      dkLen: 32,
      asyncTick: 10,
      maxmem: 1024 ** 3 + 1024,
    },
    _opts
  );
  const { N, r, p, dkLen, asyncTick, maxmem, onProgress } = opts;
  anumber(N, 'N');
  anumber(r, 'r');
  anumber(p, 'p');
  anumber(dkLen, 'dkLen');
  anumber(asyncTick, 'asyncTick');
  anumber(maxmem, 'maxmem');
  if (onProgress !== undefined && typeof onProgress !== 'function')
    throw new Error('"onProgress" must be a function');
  // Without this, r=0 slips through: blockSize=0 turns the `p` upper bound into
  // Infinity and the failure surfaces later as a confusing pbkdf2 dkLen error.
  if (r < 1) throw new Error('"r" expected integer >= 1');
  const blockSize = 128 * r;
  const blockSize32 = blockSize / 4;

  // Max N is 2^32 (Integrify is 32-bit).
  // Real limit can be 2^22: some JS engines limit Uint8Array to 4GB.
  // Spec check `N >= 2^(blockSize / 8)` is not done for compat with popular libs,
  // which used incorrect r: 1, p: 8. Also, the check seems to be a spec error:
  // https://www.rfc-editor.org/errata_search.php?rfc=7914
  const pow32 = Math.pow(2, 32);
  if (N <= 1 || (N & (N - 1)) !== 0 || N > pow32)
    throw new Error('"N" expected a power of 2, and 2^1 <= N <= 2^32');
  if (p < 1 || p > ((pow32 - 1) * 32) / blockSize)
    throw new Error('"p" expected integer 1..((2^32 - 1) * 32) / (128 * r)');
  // RFC 7914 §2 defines `dkLen` as a positive integer.
  if (dkLen < 1 || dkLen > (pow32 - 1) * 32)
    throw new Error('"dkLen" expected integer 1..(2^32 - 1) * 32');
  // Include the shared `tmp` scratch block so `maxmem` matches noble's actual temporary allocation.
  // Node requires more headroom here, so this accounting is intentionally noble-specific.
  const memUsed = blockSize * (N + p + 1);
  if (memUsed > maxmem)
    throw new Error(
      '"maxmem" limit was hit: memUsed(128*r*(N+p+1))=' + memUsed + ', maxmem=' + maxmem
    );
  // [B0...Bp−1] ← PBKDF2HMAC-SHA256(Passphrase, Salt, 1, blockSize*ParallelizationFactor)
  // Since it has only one iteration there is no reason to use async variant
  const B = scryptPbkdf2(password, salt, blockSize * p);
  const B32 = u32(B);
  // Re-used between parallel iterations. Array(iterations) of B
  const V = u32(new Uint8Array(blockSize * N));
  const tmp = u32(new Uint8Array(blockSize));
  let blockMixCb = () => {};
  if (onProgress) {
    const totalBlockMix = 2 * N * p;
    // Invoke callback if progress changes from 10.01 to 10.02
    // Allows to draw smooth progress bar on up to 8K screen
    const callbackPer = Math.max(Math.floor(totalBlockMix / 10000), 1);
    let blockMixCnt = 0;
    blockMixCb = () => {
      blockMixCnt++;
      if (onProgress && (!(blockMixCnt % callbackPer) || blockMixCnt === totalBlockMix)) {
        // Wiping here instead of a try/catch around the main loops keeps them
        // try-free: measured ~1% slower at N=2^21 with the loops inside a try.
        // onProgress is the only user code that can throw mid-derivation.
        try {
          onProgress(blockMixCnt / totalBlockMix);
        } catch (e) {
          clean(B, V, tmp);
          throw e;
        }
      }
    };
  }
  return { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick };
}

function scryptOutput(
  password: TArg<KDFInput>,
  dkLen: number,
  B: TArg<Uint8Array>,
  V: TArg<Uint32Array>,
  tmp: TArg<Uint32Array>
): TRet<Uint8Array> {
  // Shared final PBKDF2-and-cleanup step: keep the derived key, wipe the scrypt workspace.
  const res = scryptPbkdf2(password, B, dkLen);
  clean(B, V, tmp);
  return res;
}

/**
 * Scrypt KDF from RFC 7914. See {@link ScryptOpts}.
 * @param password - password or key material to derive from;
 *   JS string inputs are UTF-8 encoded first
 * @param salt - unique salt bytes or string; JS string inputs are UTF-8 encoded first
 * @param opts - Scrypt cost and memory parameters. `dkLen`, if provided,
 *   must be `>= 1` per RFC 7914 §2. See {@link ScryptOpts}.
 * @returns Derived key bytes.
 * @throws If the Scrypt cost, memory, or callback options are invalid. {@link Error}
 * @example
 * Derive a key with scrypt.
 * ```ts
 * scrypt('password', 'salt', { N: 2**18, r: 8, p: 1, dkLen: 32 });
 * ```
 * @example
 * Derive a key with small demo costs and progress/memory controls.
 * ```ts
 * const progressLog: number[] = [];
 * scrypt('password', 'salt', {
 *   N: 16,
 *   r: 8,
 *   p: 1,
 *   dkLen: 32,
 *   maxmem: 1024 * 1024,
 *   asyncTick: 10,
 *   onProgress(progress) {
 *     progressLog.push(progress);
 *   },
 * });
 * ```
 */
export function scrypt(
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: ScryptOpts
): TRet<Uint8Array> {
  const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb } = scryptInit(
    password,
    salt,
    opts
  );
  const blockMix = r < 4 ? BlockMixBase : BlockMixScalar;
  swap32IfBE(B32);
  for (let pi = 0; pi < p; pi++) {
    const Pi = blockSize32 * pi;
    for (let i = 0; i < blockSize32; i++) V[i] = B32[Pi + i]; // V[0] = B[i]
    for (let i = 0, pos = 0; i < N - 1; i++) {
      blockMix(V, pos, V, (pos += blockSize32), r); // V[i] = blockMix(V[i-1]);
      blockMixCb();
    }
    blockMix(V, (N - 1) * blockSize32, B32, Pi, r); // Process last element
    blockMixCb();
    for (let i = 0; i < N; i++) {
      // First u32 of the last 64-byte block (u32 is LE)
      // RFC 7914 Integerify(X) uses the whole last 64-byte block, but mod N
      // only depends on the low word here because N is a power of two and
      // this implementation caps N at 2^32.
      // & (N - 1) is % N as N is a power of 2, N & (N - 1) = 0 is checked
      // above; >>> 0 for unsigned, input fits in u32.
      const j = (B32[Pi + blockSize32 - 16] & (N - 1)) >>> 0; // j = Integrify(X) % iterations
      // tmp = B ^ V[j]
      const vj = j * blockSize32;
      for (let k = 0; k < blockSize32; k += 8) {
        tmp[k] = B32[Pi + k] ^ V[vj + k];
        tmp[k + 1] = B32[Pi + k + 1] ^ V[vj + k + 1];
        tmp[k + 2] = B32[Pi + k + 2] ^ V[vj + k + 2];
        tmp[k + 3] = B32[Pi + k + 3] ^ V[vj + k + 3];
        tmp[k + 4] = B32[Pi + k + 4] ^ V[vj + k + 4];
        tmp[k + 5] = B32[Pi + k + 5] ^ V[vj + k + 5];
        tmp[k + 6] = B32[Pi + k + 6] ^ V[vj + k + 6];
        tmp[k + 7] = B32[Pi + k + 7] ^ V[vj + k + 7];
      }
      blockMix(tmp, 0, B32, Pi, r); // B = blockMix(B ^ V[j])
      blockMixCb();
    }
  }
  swap32IfBE(B32);
  return scryptOutput(password, dkLen, B, V, tmp);
}

/**
 * Scrypt KDF from RFC 7914. Async version. See {@link ScryptOpts}.
 * @param password - password or key material to derive from;
 *   JS string inputs are UTF-8 encoded first
 * @param salt - unique salt bytes or string; JS string inputs are UTF-8 encoded first
 * @param opts - Scrypt cost and memory parameters. `dkLen`, if provided,
 *   must be `>= 1` per RFC 7914 §2. `asyncTick` is only a local
 *   scheduler-yield control for this JS wrapper, not part of RFC 7914.
 *   See {@link ScryptOpts}.
 * @returns Promise resolving to derived key bytes.
 * @throws If the Scrypt cost, memory, or callback options are invalid. {@link Error}
 * @example
 * Derive a key with scrypt asynchronously.
 * ```ts
 * await scryptAsync('password', 'salt', { N: 2**18, r: 8, p: 1, dkLen: 32 });
 * ```
 * @example
 * Derive a key asynchronously with small demo costs and progress/memory controls.
 * ```ts
 * await scryptAsync('password', 'salt', {
 *   N: 16,
 *   r: 8,
 *   p: 1,
 *   dkLen: 32,
 *   maxmem: 1024 * 1024,
 *   asyncTick: 1,
 *   onProgress(progress) {
 *     if (progress > 1) throw new Error('invalid progress');
 *   },
 * });
 * ```
 */
export async function scryptAsync(
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: ScryptOpts
): Promise<TRet<Uint8Array>> {
  const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick } = scryptInit(
    password,
    salt,
    opts
  );
  const blockMix = r < 4 ? BlockMixBase : BlockMixScalar;
  swap32IfBE(B32);
  for (let pi = 0; pi < p; pi++) {
    const Pi = blockSize32 * pi;
    for (let i = 0; i < blockSize32; i++) V[i] = B32[Pi + i]; // V[0] = B[i]
    let pos = 0;
    await asyncLoop(N - 1, asyncTick, () => {
      blockMix(V, pos, V, (pos += blockSize32), r); // V[i] = blockMix(V[i-1]);
      blockMixCb();
    });
    blockMix(V, (N - 1) * blockSize32, B32, Pi, r); // Process last element
    blockMixCb();
    await asyncLoop(N, asyncTick, () => {
      // First u32 of the last 64-byte block (u32 is LE)
      // RFC 7914 Integerify(X) uses the whole last 64-byte block, but mod N
      // only depends on the low word here because N is a power of two and
      // this implementation caps N at 2^32.
      // & (N - 1) is % N as N is a power of 2, N & (N - 1) = 0 is checked
      // above; >>> 0 for unsigned, input fits in u32.
      const j = (B32[Pi + blockSize32 - 16] & (N - 1)) >>> 0; // j = Integrify(X) % iterations
      // tmp = B ^ V[j]
      const vj = j * blockSize32;
      for (let k = 0; k < blockSize32; k += 8) {
        tmp[k] = B32[Pi + k] ^ V[vj + k];
        tmp[k + 1] = B32[Pi + k + 1] ^ V[vj + k + 1];
        tmp[k + 2] = B32[Pi + k + 2] ^ V[vj + k + 2];
        tmp[k + 3] = B32[Pi + k + 3] ^ V[vj + k + 3];
        tmp[k + 4] = B32[Pi + k + 4] ^ V[vj + k + 4];
        tmp[k + 5] = B32[Pi + k + 5] ^ V[vj + k + 5];
        tmp[k + 6] = B32[Pi + k + 6] ^ V[vj + k + 6];
        tmp[k + 7] = B32[Pi + k + 7] ^ V[vj + k + 7];
      }
      blockMix(tmp, 0, B32, Pi, r); // B = blockMix(B ^ V[j])
      blockMixCb();
    });
  }
  swap32IfBE(B32);
  return scryptOutput(password, dkLen, B, V, tmp);
}
