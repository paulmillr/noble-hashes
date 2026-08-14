/**
 * Argon2 KDF from RFC 9106. Can be used to create a key from password and salt.
 * We suggest to use Scrypt. JS Argon is 3-4x slower than native code because of 64-bitness:
 * * argon uses uint64, but JS doesn't have fast uint64array: each u64 lives as two u32 halves
 * * u64 multiply-high is emulated; the exact high half is recovered from a f64 product (see `P`)
 * * the permutation `P` keeps its whole 16-word state in 32 u32 locals per register group,
 *   with the four independent G chains interleaved so the CPU can overlap their latency chains
 * @module
 */
import { blake2b } from './blake2.ts';
import {
  anumber,
  checkOpts,
  clean,
  kdfInputToBytes,
  nextTick,
  swap32IfBE,
  swap8IfBE,
  u32,
  u8,
  type KDFInput,
  type TArg,
  type TRet,
} from './utils.ts';

// RFC 9106 §3.1 type `y`: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id. The numeric values are the
// spec-bound part here; the object keys are internal labels.
const AT = { Argon2d: 0, Argon2i: 1, Argon2id: 2 } as const;
type Types = (typeof AT)[keyof typeof AT];

// RFC 9106 sync points constant `SL = 4`, fixed by the design rather than exposed as a tuning knob.
const ARGON2_SYNC_POINTS = 4;
// Preserve Argon2's `LE32(len(X)) || X` encoding for omitted
// optional fields by emitting empty bytes.
const abytesOrZero = (buf?: TArg<KDFInput>, errorTitle = ''): TRet<Uint8Array> => {
  if (buf === undefined) return Uint8Array.of();
  return kdfInputToBytes(buf, errorTitle);
};

// Temporary block buffer.
// 1024-byte block: 256 u32 = 128 interleaved low/high halves = RFC's
// 8x8 matrix of 16-byte registers.
const A2_BUF = new Uint32Array(256);

// Permutation P from RFC 9106 §3.6 over 8 16-byte registers, addressed as 16 u64 word
// indices into `A2_BUF` (each word is a pair of adjacent low/high u32s). The whole state
// is loaded into 32 u32 locals up front and stored back once at the end, instead of paying
// per-quarter-round memory traffic on `A2_BUF`.
//
// Each BlaMka step `X = X + Y + 2 * trunc(X) * trunc(Y)` (trunc = low 32 bits) starts
// with an exact low product from `Math.imul`. The rounded double product is within 1024 of
// the exact u64 product; subtracting that exact low half and rounding to the nearest multiple
// of 2^32 therefore recovers the exact high half. RFC 9106 Figure 19 GB then rotates by 32,
// 24, 16, and 63 bits after each XOR.
//
// RFC 9106 Figure 18 runs G(0,4,8,12)..G(3,7,11,15), then G(0,5,10,15)..G(3,4,9,14). The
// four G chains inside each half are data-independent, so their steps are emitted
// interleaved (chain id = temps suffix) letting the CPU overlap the four multiply/carry
// latency chains. Measured ~1.6x vs a G() helper mutating A2_BUF per call.
// prettier-ignore
function P(
  i00: number, i01: number, i02: number, i03: number, i04: number, i05: number, i06: number, i07: number, i08: number, i09: number, i10: number, i11: number, i12: number, i13: number, i14: number, i15: number,
) {
  const x = A2_BUF;
  let V00l = x[2 * i00], V00h = x[2 * i00 + 1];
  let V01l = x[2 * i01], V01h = x[2 * i01 + 1];
  let V02l = x[2 * i02], V02h = x[2 * i02 + 1];
  let V03l = x[2 * i03], V03h = x[2 * i03 + 1];
  let V04l = x[2 * i04], V04h = x[2 * i04 + 1];
  let V05l = x[2 * i05], V05h = x[2 * i05 + 1];
  let V06l = x[2 * i06], V06h = x[2 * i06 + 1];
  let V07l = x[2 * i07], V07h = x[2 * i07 + 1];
  let V08l = x[2 * i08], V08h = x[2 * i08 + 1];
  let V09l = x[2 * i09], V09h = x[2 * i09 + 1];
  let V10l = x[2 * i10], V10h = x[2 * i10 + 1];
  let V11l = x[2 * i11], V11h = x[2 * i11 + 1];
  let V12l = x[2 * i12], V12h = x[2 * i12 + 1];
  let V13l = x[2 * i13], V13h = x[2 * i13 + 1];
  let V14l = x[2 * i14], V14h = x[2 * i14 + 1];
  let V15l = x[2 * i15], V15h = x[2 * i15 + 1];
  let ml0 = 0, mh0 = 0, rl0 = 0, xl0 = 0, xh0 = 0,
      ml1 = 0, mh1 = 0, rl1 = 0, xl1 = 0, xh1 = 0,
      ml2 = 0, mh2 = 0, rl2 = 0, xl2 = 0, xh2 = 0,
      ml3 = 0, mh3 = 0, rl3 = 0, xl3 = 0, xh3 = 0;
  // First half: G(0, 4, 8, 12), G(1, 5, 9, 13), G(2, 6, 10, 14), G(3, 7, 11, 15), four chains interleaved.
  // step 1: A += B + 2*AlBl; D = rotr64(D^A, 32) - all 4 chains
  ml0 = Math.imul(V00l, V04l);
  mh0 = (((V00l >>> 0) * (V04l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V00l >>> 0) + (V04l >>> 0) + ((ml0 << 1) >>> 0);
  V00h = (V00h + V04h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V00l = rl0 | 0;
  xh0 = V12h ^ V00h; xl0 = V12l ^ V00l;
  V12h = xl0; V12l = xh0;
  ml1 = Math.imul(V01l, V05l);
  mh1 = (((V01l >>> 0) * (V05l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V01l >>> 0) + (V05l >>> 0) + ((ml1 << 1) >>> 0);
  V01h = (V01h + V05h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V01l = rl1 | 0;
  xh1 = V13h ^ V01h; xl1 = V13l ^ V01l;
  V13h = xl1; V13l = xh1;
  ml2 = Math.imul(V02l, V06l);
  mh2 = (((V02l >>> 0) * (V06l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V02l >>> 0) + (V06l >>> 0) + ((ml2 << 1) >>> 0);
  V02h = (V02h + V06h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V02l = rl2 | 0;
  xh2 = V14h ^ V02h; xl2 = V14l ^ V02l;
  V14h = xl2; V14l = xh2;
  ml3 = Math.imul(V03l, V07l);
  mh3 = (((V03l >>> 0) * (V07l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V03l >>> 0) + (V07l >>> 0) + ((ml3 << 1) >>> 0);
  V03h = (V03h + V07h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V03l = rl3 | 0;
  xh3 = V15h ^ V03h; xl3 = V15l ^ V03l;
  V15h = xl3; V15l = xh3;
  // step 2: C += D + 2*ClDl; B = rotr64(B^C, 24) - all 4 chains
  ml0 = Math.imul(V08l, V12l);
  mh0 = (((V08l >>> 0) * (V12l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V08l >>> 0) + (V12l >>> 0) + ((ml0 << 1) >>> 0);
  V08h = (V08h + V12h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V08l = rl0 | 0;
  xh0 = V04h ^ V08h; xl0 = V04l ^ V08l;
  V04h = (xh0 >>> 24) | (xl0 << 8); V04l = (xh0 << 8) | (xl0 >>> 24);
  ml1 = Math.imul(V09l, V13l);
  mh1 = (((V09l >>> 0) * (V13l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V09l >>> 0) + (V13l >>> 0) + ((ml1 << 1) >>> 0);
  V09h = (V09h + V13h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V09l = rl1 | 0;
  xh1 = V05h ^ V09h; xl1 = V05l ^ V09l;
  V05h = (xh1 >>> 24) | (xl1 << 8); V05l = (xh1 << 8) | (xl1 >>> 24);
  ml2 = Math.imul(V10l, V14l);
  mh2 = (((V10l >>> 0) * (V14l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V10l >>> 0) + (V14l >>> 0) + ((ml2 << 1) >>> 0);
  V10h = (V10h + V14h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V10l = rl2 | 0;
  xh2 = V06h ^ V10h; xl2 = V06l ^ V10l;
  V06h = (xh2 >>> 24) | (xl2 << 8); V06l = (xh2 << 8) | (xl2 >>> 24);
  ml3 = Math.imul(V11l, V15l);
  mh3 = (((V11l >>> 0) * (V15l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V11l >>> 0) + (V15l >>> 0) + ((ml3 << 1) >>> 0);
  V11h = (V11h + V15h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V11l = rl3 | 0;
  xh3 = V07h ^ V11h; xl3 = V07l ^ V11l;
  V07h = (xh3 >>> 24) | (xl3 << 8); V07l = (xh3 << 8) | (xl3 >>> 24);
  // step 3: A += B + 2*AlBl; D = rotr64(D^A, 16) - all 4 chains
  ml0 = Math.imul(V00l, V04l);
  mh0 = (((V00l >>> 0) * (V04l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V00l >>> 0) + (V04l >>> 0) + ((ml0 << 1) >>> 0);
  V00h = (V00h + V04h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V00l = rl0 | 0;
  xh0 = V12h ^ V00h; xl0 = V12l ^ V00l;
  V12h = (xh0 >>> 16) | (xl0 << 16); V12l = (xh0 << 16) | (xl0 >>> 16);
  ml1 = Math.imul(V01l, V05l);
  mh1 = (((V01l >>> 0) * (V05l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V01l >>> 0) + (V05l >>> 0) + ((ml1 << 1) >>> 0);
  V01h = (V01h + V05h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V01l = rl1 | 0;
  xh1 = V13h ^ V01h; xl1 = V13l ^ V01l;
  V13h = (xh1 >>> 16) | (xl1 << 16); V13l = (xh1 << 16) | (xl1 >>> 16);
  ml2 = Math.imul(V02l, V06l);
  mh2 = (((V02l >>> 0) * (V06l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V02l >>> 0) + (V06l >>> 0) + ((ml2 << 1) >>> 0);
  V02h = (V02h + V06h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V02l = rl2 | 0;
  xh2 = V14h ^ V02h; xl2 = V14l ^ V02l;
  V14h = (xh2 >>> 16) | (xl2 << 16); V14l = (xh2 << 16) | (xl2 >>> 16);
  ml3 = Math.imul(V03l, V07l);
  mh3 = (((V03l >>> 0) * (V07l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V03l >>> 0) + (V07l >>> 0) + ((ml3 << 1) >>> 0);
  V03h = (V03h + V07h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V03l = rl3 | 0;
  xh3 = V15h ^ V03h; xl3 = V15l ^ V03l;
  V15h = (xh3 >>> 16) | (xl3 << 16); V15l = (xh3 << 16) | (xl3 >>> 16);
  // step 4: C += D + 2*ClDl; B = rotr64(B^C, 63) - all 4 chains
  ml0 = Math.imul(V08l, V12l);
  mh0 = (((V08l >>> 0) * (V12l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V08l >>> 0) + (V12l >>> 0) + ((ml0 << 1) >>> 0);
  V08h = (V08h + V12h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V08l = rl0 | 0;
  xh0 = V04h ^ V08h; xl0 = V04l ^ V08l;
  V04h = (xh0 << 1) | (xl0 >>> 31); V04l = (xh0 >>> 31) | (xl0 << 1);
  ml1 = Math.imul(V09l, V13l);
  mh1 = (((V09l >>> 0) * (V13l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V09l >>> 0) + (V13l >>> 0) + ((ml1 << 1) >>> 0);
  V09h = (V09h + V13h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V09l = rl1 | 0;
  xh1 = V05h ^ V09h; xl1 = V05l ^ V09l;
  V05h = (xh1 << 1) | (xl1 >>> 31); V05l = (xh1 >>> 31) | (xl1 << 1);
  ml2 = Math.imul(V10l, V14l);
  mh2 = (((V10l >>> 0) * (V14l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V10l >>> 0) + (V14l >>> 0) + ((ml2 << 1) >>> 0);
  V10h = (V10h + V14h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V10l = rl2 | 0;
  xh2 = V06h ^ V10h; xl2 = V06l ^ V10l;
  V06h = (xh2 << 1) | (xl2 >>> 31); V06l = (xh2 >>> 31) | (xl2 << 1);
  ml3 = Math.imul(V11l, V15l);
  mh3 = (((V11l >>> 0) * (V15l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V11l >>> 0) + (V15l >>> 0) + ((ml3 << 1) >>> 0);
  V11h = (V11h + V15h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V11l = rl3 | 0;
  xh3 = V07h ^ V11h; xl3 = V07l ^ V11l;
  V07h = (xh3 << 1) | (xl3 >>> 31); V07l = (xh3 >>> 31) | (xl3 << 1);
  // Second half: G(0, 5, 10, 15), G(1, 6, 11, 12), G(2, 7, 8, 13), G(3, 4, 9, 14), four chains interleaved.
  // step 1: A += B + 2*AlBl; D = rotr64(D^A, 32) - all 4 chains
  ml0 = Math.imul(V00l, V05l);
  mh0 = (((V00l >>> 0) * (V05l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V00l >>> 0) + (V05l >>> 0) + ((ml0 << 1) >>> 0);
  V00h = (V00h + V05h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V00l = rl0 | 0;
  xh0 = V15h ^ V00h; xl0 = V15l ^ V00l;
  V15h = xl0; V15l = xh0;
  ml1 = Math.imul(V01l, V06l);
  mh1 = (((V01l >>> 0) * (V06l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V01l >>> 0) + (V06l >>> 0) + ((ml1 << 1) >>> 0);
  V01h = (V01h + V06h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V01l = rl1 | 0;
  xh1 = V12h ^ V01h; xl1 = V12l ^ V01l;
  V12h = xl1; V12l = xh1;
  ml2 = Math.imul(V02l, V07l);
  mh2 = (((V02l >>> 0) * (V07l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V02l >>> 0) + (V07l >>> 0) + ((ml2 << 1) >>> 0);
  V02h = (V02h + V07h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V02l = rl2 | 0;
  xh2 = V13h ^ V02h; xl2 = V13l ^ V02l;
  V13h = xl2; V13l = xh2;
  ml3 = Math.imul(V03l, V04l);
  mh3 = (((V03l >>> 0) * (V04l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V03l >>> 0) + (V04l >>> 0) + ((ml3 << 1) >>> 0);
  V03h = (V03h + V04h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V03l = rl3 | 0;
  xh3 = V14h ^ V03h; xl3 = V14l ^ V03l;
  V14h = xl3; V14l = xh3;
  // step 2: C += D + 2*ClDl; B = rotr64(B^C, 24) - all 4 chains
  ml0 = Math.imul(V10l, V15l);
  mh0 = (((V10l >>> 0) * (V15l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V10l >>> 0) + (V15l >>> 0) + ((ml0 << 1) >>> 0);
  V10h = (V10h + V15h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V10l = rl0 | 0;
  xh0 = V05h ^ V10h; xl0 = V05l ^ V10l;
  V05h = (xh0 >>> 24) | (xl0 << 8); V05l = (xh0 << 8) | (xl0 >>> 24);
  ml1 = Math.imul(V11l, V12l);
  mh1 = (((V11l >>> 0) * (V12l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V11l >>> 0) + (V12l >>> 0) + ((ml1 << 1) >>> 0);
  V11h = (V11h + V12h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V11l = rl1 | 0;
  xh1 = V06h ^ V11h; xl1 = V06l ^ V11l;
  V06h = (xh1 >>> 24) | (xl1 << 8); V06l = (xh1 << 8) | (xl1 >>> 24);
  ml2 = Math.imul(V08l, V13l);
  mh2 = (((V08l >>> 0) * (V13l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V08l >>> 0) + (V13l >>> 0) + ((ml2 << 1) >>> 0);
  V08h = (V08h + V13h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V08l = rl2 | 0;
  xh2 = V07h ^ V08h; xl2 = V07l ^ V08l;
  V07h = (xh2 >>> 24) | (xl2 << 8); V07l = (xh2 << 8) | (xl2 >>> 24);
  ml3 = Math.imul(V09l, V14l);
  mh3 = (((V09l >>> 0) * (V14l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V09l >>> 0) + (V14l >>> 0) + ((ml3 << 1) >>> 0);
  V09h = (V09h + V14h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V09l = rl3 | 0;
  xh3 = V04h ^ V09h; xl3 = V04l ^ V09l;
  V04h = (xh3 >>> 24) | (xl3 << 8); V04l = (xh3 << 8) | (xl3 >>> 24);
  // step 3: A += B + 2*AlBl; D = rotr64(D^A, 16) - all 4 chains
  ml0 = Math.imul(V00l, V05l);
  mh0 = (((V00l >>> 0) * (V05l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V00l >>> 0) + (V05l >>> 0) + ((ml0 << 1) >>> 0);
  V00h = (V00h + V05h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V00l = rl0 | 0;
  xh0 = V15h ^ V00h; xl0 = V15l ^ V00l;
  V15h = (xh0 >>> 16) | (xl0 << 16); V15l = (xh0 << 16) | (xl0 >>> 16);
  ml1 = Math.imul(V01l, V06l);
  mh1 = (((V01l >>> 0) * (V06l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V01l >>> 0) + (V06l >>> 0) + ((ml1 << 1) >>> 0);
  V01h = (V01h + V06h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V01l = rl1 | 0;
  xh1 = V12h ^ V01h; xl1 = V12l ^ V01l;
  V12h = (xh1 >>> 16) | (xl1 << 16); V12l = (xh1 << 16) | (xl1 >>> 16);
  ml2 = Math.imul(V02l, V07l);
  mh2 = (((V02l >>> 0) * (V07l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V02l >>> 0) + (V07l >>> 0) + ((ml2 << 1) >>> 0);
  V02h = (V02h + V07h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V02l = rl2 | 0;
  xh2 = V13h ^ V02h; xl2 = V13l ^ V02l;
  V13h = (xh2 >>> 16) | (xl2 << 16); V13l = (xh2 << 16) | (xl2 >>> 16);
  ml3 = Math.imul(V03l, V04l);
  mh3 = (((V03l >>> 0) * (V04l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V03l >>> 0) + (V04l >>> 0) + ((ml3 << 1) >>> 0);
  V03h = (V03h + V04h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V03l = rl3 | 0;
  xh3 = V14h ^ V03h; xl3 = V14l ^ V03l;
  V14h = (xh3 >>> 16) | (xl3 << 16); V14l = (xh3 << 16) | (xl3 >>> 16);
  // step 4: C += D + 2*ClDl; B = rotr64(B^C, 63) - all 4 chains
  ml0 = Math.imul(V10l, V15l);
  mh0 = (((V10l >>> 0) * (V15l >>> 0) - (ml0 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl0 = (V10l >>> 0) + (V15l >>> 0) + ((ml0 << 1) >>> 0);
  V10h = (V10h + V15h + ((mh0 << 1) | (ml0 >>> 31)) + ((rl0 / 0x100000000) | 0)) | 0;
  V10l = rl0 | 0;
  xh0 = V05h ^ V10h; xl0 = V05l ^ V10l;
  V05h = (xh0 << 1) | (xl0 >>> 31); V05l = (xh0 >>> 31) | (xl0 << 1);
  ml1 = Math.imul(V11l, V12l);
  mh1 = (((V11l >>> 0) * (V12l >>> 0) - (ml1 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl1 = (V11l >>> 0) + (V12l >>> 0) + ((ml1 << 1) >>> 0);
  V11h = (V11h + V12h + ((mh1 << 1) | (ml1 >>> 31)) + ((rl1 / 0x100000000) | 0)) | 0;
  V11l = rl1 | 0;
  xh1 = V06h ^ V11h; xl1 = V06l ^ V11l;
  V06h = (xh1 << 1) | (xl1 >>> 31); V06l = (xh1 >>> 31) | (xl1 << 1);
  ml2 = Math.imul(V08l, V13l);
  mh2 = (((V08l >>> 0) * (V13l >>> 0) - (ml2 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl2 = (V08l >>> 0) + (V13l >>> 0) + ((ml2 << 1) >>> 0);
  V08h = (V08h + V13h + ((mh2 << 1) | (ml2 >>> 31)) + ((rl2 / 0x100000000) | 0)) | 0;
  V08l = rl2 | 0;
  xh2 = V07h ^ V08h; xl2 = V07l ^ V08l;
  V07h = (xh2 << 1) | (xl2 >>> 31); V07l = (xh2 >>> 31) | (xl2 << 1);
  ml3 = Math.imul(V09l, V14l);
  mh3 = (((V09l >>> 0) * (V14l >>> 0) - (ml3 >>> 0)) / 0x100000000 + 0.5) | 0;
  rl3 = (V09l >>> 0) + (V14l >>> 0) + ((ml3 << 1) >>> 0);
  V09h = (V09h + V14h + ((mh3 << 1) | (ml3 >>> 31)) + ((rl3 / 0x100000000) | 0)) | 0;
  V09l = rl3 | 0;
  xh3 = V04h ^ V09h; xl3 = V04l ^ V09l;
  V04h = (xh3 << 1) | (xl3 >>> 31); V04l = (xh3 >>> 31) | (xl3 << 1);
  x[2 * i00] = V00l; x[2 * i00 + 1] = V00h;
  x[2 * i01] = V01l; x[2 * i01 + 1] = V01h;
  x[2 * i02] = V02l; x[2 * i02 + 1] = V02h;
  x[2 * i03] = V03l; x[2 * i03 + 1] = V03h;
  x[2 * i04] = V04l; x[2 * i04 + 1] = V04h;
  x[2 * i05] = V05l; x[2 * i05 + 1] = V05h;
  x[2 * i06] = V06l; x[2 * i06 + 1] = V06h;
  x[2 * i07] = V07l; x[2 * i07 + 1] = V07h;
  x[2 * i08] = V08l; x[2 * i08 + 1] = V08h;
  x[2 * i09] = V09l; x[2 * i09 + 1] = V09h;
  x[2 * i10] = V10l; x[2 * i10 + 1] = V10h;
  x[2 * i11] = V11l; x[2 * i11 + 1] = V11h;
  x[2 * i12] = V12l; x[2 * i12 + 1] = V12h;
  x[2 * i13] = V13l; x[2 * i13 + 1] = V13h;
  x[2 * i14] = V14l; x[2 * i14 + 1] = V14h;
  x[2 * i15] = V15l; x[2 * i15 + 1] = V15h;
}

function block(x: TArg<Uint32Array>, xPos: number, yPos: number, outPos: number, needXor: boolean) {
  // Stage R = X xor Y in the destination before permuting it. This avoids rereading both source
  // blocks when folding R into the permuted scratch block below.
  if (needXor) {
    for (let i = 0; i < 256; i++) {
      const r = x[xPos + i] ^ x[yPos + i];
      A2_BUF[i] = r;
      x[outPos + i] ^= r;
    }
  } else {
    for (let i = 0; i < 256; i++) {
      const r = x[xPos + i] ^ x[yPos + i];
      A2_BUF[i] = r;
      x[outPos + i] = r;
    }
  }
  // rows (8 consecutive 16-register groups)
  for (let i = 0; i < 128; i += 16) {
    // prettier-ignore
    P(
      i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
      i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15
    );
  }
  // columns (8 strided 16-register groups)
  for (let i = 0; i < 16; i += 2) {
    // prettier-ignore
    P(
      i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
      i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113
    );
  }

  // RFC 9106 step 6: passes after the first XOR the old destination block into the new G(X, Y).
  for (let i = 0; i < 256; i++) x[outPos + i] ^= A2_BUF[i];
  clean(A2_BUF);
}

// Variable-Length Hash Function H'
// Returns bytes, not words; 1024-byte block callers explicitly reinterpret with `u32(...)`.
function Hp(A: TArg<Uint32Array>, dkLen: number): TRet<Uint8Array> {
  const A8 = u8(A);
  const T = new Uint32Array(1);
  const T8 = u8(T);
  // Argon2 H' prefixes dkLen as LE32; native Uint32Array writes would serialize as BE on s390x.
  T[0] = swap8IfBE(dkLen);
  // Fast path
  if (dkLen <= 64) return blake2b.create({ dkLen }).update(T8).update(A8).digest();
  const out = new Uint8Array(dkLen);
  let V = blake2b.create({}).update(T8).update(A8).digest();
  let pos = 0;
  // RFC 9106 Figure 8: each intermediate `V_i` contributes only `W_i`, its first 32 bytes; only
  // `V_{r+1}` is emitted in full at the remaining length.
  out.set(V.subarray(0, 32));
  pos += 32;
  // Rest blocks
  for (; dkLen - pos > 64; pos += 32) {
    const Vh = blake2b.create({}).update(V);
    Vh.digestInto(V);
    Vh.destroy();
    out.set(V.subarray(0, 32), pos);
  }
  // Last block
  out.set(blake2b(V, { dkLen: dkLen - pos }), pos);
  clean(V, T);
  // H' is byte-oriented; returning `u32(out)` would silently drop dkLen % 4 tail bytes.
  return out as TRet<Uint8Array>;
}

// Used only inside argon2Blocks!
function indexAlpha(
  r: number,
  s: number,
  laneLen: number,
  segmentLen: number,
  index: number,
  randL: number,
  sameLane: boolean = false
) {
  // RFC 9106 §3.4.2 Figures 12-13: map `J1` / `J2` into the current lane's reference area `W`.
  let area: number;
  if (r === 0) {
    if (s === 0) area = index - 1;
    else if (sameLane) area = s * segmentLen + index - 1;
    else area = s * segmentLen + (index == 0 ? -1 : 0);
  } else if (sameLane) area = laneLen - segmentLen + index - 1;
  else area = laneLen - segmentLen + (index == 0 ? -1 : 0);
  const startPos = r !== 0 && s !== ARGON2_SYNC_POINTS - 1 ? (s + 1) * segmentLen : 0;
  // Use the same exact-high recovery as G. `areaHigh` is floor(|W| * J1^2/2^32 / 2^32).
  const randLow = Math.imul(randL, randL);
  const randHigh = (((randL >>> 0) * (randL >>> 0) - (randLow >>> 0)) / 0x100000000 + 0.5) | 0;
  const areaLow = Math.imul(area, randHigh);
  const areaHigh = (((area >>> 0) * (randHigh >>> 0) - (areaLow >>> 0)) / 0x100000000 + 0.5) | 0;
  const rel = area - 1 - areaHigh;
  return (startPos + rel) % laneLen;
}

/** Argon2 cost, output, and optional secret/personalization inputs. */
export type ArgonOpts = {
  /** Time cost measured in iterations. */
  t: number;
  /** Memory cost in kibibytes. */
  m: number;
  /** Parallelization parameter. */
  p: number;
  /** Argon2 version number. Defaults to `0x13`. */
  version?: number;
  /** Optional secret key mixed into initialization. */
  key?: KDFInput;
  /** Optional personalization string or bytes. */
  personalization?: KDFInput;
  /** Desired output length in bytes. RFC 9106 §3.1 requires `T` in the 4..(2^32 - 1) range. */
  dkLen?: number;
  /** Max scheduler block time in milliseconds for the async variants. */
  asyncTick?: number;
  /** Maximum temporary memory budget in bytes. */
  maxmem?: number;
  /**
   * Optional progress callback invoked during long-running derivations.
   * @param progress - completion fraction in the `0..1` range
   */
  onProgress?: (progress: number) => void;
};

// Exclusive `2^32` sentinel used by `isU32(...)`, not the inclusive maximum u32 value.
const maxUint32 = Math.pow(2, 32);
// Validate safe JS integers in `[0, 2^32 - 1]`.
function isU32(num: number) {
  return Number.isSafeInteger(num) && num >= 0 && num < maxUint32;
}

function argon2Opts(opts: TArg<ArgonOpts>) {
  opts = checkOpts({}, opts);
  const merged: any = {
    version: 0x13,
    dkLen: 32,
    maxmem: maxUint32 - 1,
    asyncTick: 10,
  };
  // Unknown keys are copied through unchanged here and later ignored unless
  // destructuring consumes them.
  for (let [k, v] of Object.entries(opts)) if (v !== undefined) merged[k] = v;

  const { dkLen, p, m, t, version, onProgress, asyncTick } = merged;
  // RFC 9106 §3.1: tag length `T` MUST be an integer number of bytes from 4 to 2^32-1.
  if (!isU32(dkLen) || dkLen < 4) throw new Error('"dkLen" must be 4..');
  if (!isU32(p) || p < 1 || p >= Math.pow(2, 24)) throw new Error('"p" must be 1..2^24');
  if (!isU32(m)) throw new Error('"m" must be 0..2^32');
  if (!isU32(t) || t < 1) throw new Error('"t" (iterations) must be 1..2^32');
  if (onProgress !== undefined && typeof onProgress !== 'function')
    throw new Error('"onProgress" must be a function');
  anumber(asyncTick, 'asyncTick');
  /*
  Memory size m MUST be an integer number of kibibytes from 8*p
  to 2^(32)-1. The actual number of blocks is m', which is m
  rounded down to the nearest multiple of 4*p.
  */
  if (!isU32(m) || m < 8 * p) throw new Error('"m" (memory) must be at least 8*p bytes');
  // Accept legacy `0x10` for compatibility even though RFC 9106 profiles standardize `0x13`.
  if (version !== 0x10 && version !== 0x13)
    throw new Error('"version" must be 0x10 or 0x13, got ' + version);
  return merged;
}

function argon2Init(
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  type: Types,
  opts: TArg<ArgonOpts>
) {
  password = kdfInputToBytes(password, 'password');
  salt = kdfInputToBytes(salt, 'salt');
  if (!isU32(password.length)) throw new Error('"password" must be less of length 1..4Gb');
  // RFC 9106 §3.1 only requires S <= 2^32-1 bytes and says 16 bytes is RECOMMENDED for password
  // hashing; this library intentionally takes the stricter common >=8-byte salt path.
  if (!isU32(salt.length) || salt.length < 8) throw new Error('"salt" must be of length 8..4Gb');
  if (!Object.values(AT).includes(type)) throw new Error('"type" was invalid');
  let { p, dkLen, m, t, version, key, personalization, maxmem, onProgress, asyncTick } =
    argon2Opts(opts);
  // Validation
  key = abytesOrZero(key, 'key');
  personalization = abytesOrZero(personalization, 'personalization');
  // H_0 = H^(64)(LE32(p) || LE32(T) || LE32(m) || LE32(t) ||
  //       LE32(v) || LE32(y) || LE32(length(P)) || P ||
  //       LE32(length(S)) || S ||  LE32(length(K)) || K ||
  //       LE32(length(X)) || X)
  const h = blake2b.create();
  const BUF = new Uint32Array(1);
  const BUF8 = u8(BUF);
  for (let item of [p, dkLen, m, t, version, type]) {
    // RFC 9106 H0 encodes these scalars as LE32, so normalize the host word before exposing bytes.
    BUF[0] = swap8IfBE(item);
    h.update(BUF8);
  }
  for (let i of [password, salt, key, personalization]) {
    BUF[0] = swap8IfBE(i.length); // BUF is u32 array, this is valid once normalized to LE bytes
    h.update(BUF8).update(i);
  }
  // Reserve two extra LE32 words after the 64-byte `H_0` so Figures 3-4 can append
  // `LE32(0 or 1) || LE32(i)` in place for the lane-starting blocks.
  const H0 = new Uint32Array(18);
  const H0_8 = u8(H0);
  h.digestInto(H0_8);
  // 256 u32 = 1024 (BLOCK_SIZE), fills A2_BUF on processing

  // Params
  const lanes = p;
  // m' = 4 * p * floor (m / 4p)
  const mP = 4 * p * Math.floor(m / (ARGON2_SYNC_POINTS * p));
  //q = m' / p columns
  const laneLen = Math.floor(mP / p);
  const segmentLen = Math.floor(laneLen / ARGON2_SYNC_POINTS);
  // `maxmem` is documented in bytes; compare against the actual 1024-byte block allocation.
  const memUsed = mP * 1024;
  if (!isU32(maxmem)) throw new Error('"maxmem" expected <2**32, got ' + maxmem);
  if (memUsed > maxmem)
    throw new Error('"maxmem" limit was hit: memUsed(mP*1024)=' + memUsed + ', maxmem=' + maxmem);
  const B = new Uint32Array(memUsed / 4);
  // Fill first blocks
  for (let l = 0; l < p; l++) {
    const i = 256 * laneLen * l;
    // B[i][0] = H'^(1024)(H_0 || LE32(0) || LE32(i))
    H0[17] = swap8IfBE(l);
    H0[16] = swap8IfBE(0);
    B.set(swap32IfBE(u32(Hp(H0, 1024))), i);
    // B[i][1] = H'^(1024)(H_0 || LE32(1) || LE32(i))
    H0[16] = swap8IfBE(1);
    B.set(swap32IfBE(u32(Hp(H0, 1024))), i + 256);
  }
  let perBlock = () => {};
  if (onProgress) {
    // The first segment of the first pass skips two preinitialized blocks per lane.
    const totalBlock = t * ARGON2_SYNC_POINTS * p * segmentLen - 2 * p;
    // Invoke callback if progress changes from 10.01 to 10.02
    // Allows to draw smooth progress bar on up to 8K screen
    const callbackPer = Math.max(Math.floor(totalBlock / 10000), 1);
    let blockCnt = 0;
    perBlock = () => {
      blockCnt++;
      if (onProgress && (!(blockCnt % callbackPer) || blockCnt === totalBlock))
        onProgress(blockCnt / totalBlock);
    };
  }
  clean(BUF, H0);
  return { type, mP, p, t, version, B, laneLen, lanes, segmentLen, dkLen, perBlock, asyncTick };
}

function argon2Output(
  B: TArg<Uint32Array>,
  p: number,
  laneLen: number,
  dkLen: number
): TRet<Uint8Array> {
  const B_final = new Uint32Array(256);
  for (let l = 0; l < p; l++)
    for (let j = 0; j < 256; j++) B_final[j] ^= B[256 * (laneLen * l + laneLen - 1) + j];
  // RFC 9106 steps 7-8 feed the byte string `C` into `H'^T(C)`, so normalize the xor'ed words
  // back to spec byte order before `Hp(...)` reinterprets them as bytes.
  const res = Hp(swap32IfBE(B_final), dkLen);
  // Wipe both the xor scratch and the full working matrix once final digest bytes exist.
  // JS cleanup is still only best-effort, but this local buffer is no longer needed here.
  clean(B, B_final);
  return res;
}

/**
 * Fills every Argon2 block for all passes / slices / lanes, yielding once per
 * 32 processed blocks so callers control pacing: the sync driver just drains the
 * generator, while the async driver awaits `nextTick()` between time slices.
 */
function* argon2Blocks(ctx: ReturnType<typeof argon2Init>): Generator<void, void> {
  const { type, mP, p, t, version, B, laneLen, lanes, segmentLen, perBlock } = ctx;
  // [address, input, zero_block] format so we can pass single U32 to block function
  const address = new Uint32Array(3 * 256);
  address[256 + 6] = mP;
  address[256 + 8] = t;
  address[256 + 10] = type;
  for (let r = 0; r < t; r++) {
    // RFC 9106 step 6 applies the XOR-on-later-passes rule only for version `0x13`; legacy
    // `0x10` keeps the older overwrite behavior used by the v16 test vectors.
    const needXor = r !== 0 && version === 0x13;
    address[256 + 0] = r;
    for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
      address[256 + 4] = s;
      // RFC 9106 §3.4.1.3: Argon2id uses Argon2i's data-independent `J1` / `J2` generation only
      // in pass 0, slices 0 and 1; Argon2i uses it in every segment.
      const dataIndependent = type == AT.Argon2i || (type == AT.Argon2id && r === 0 && s < 2);
      for (let l = 0; l < p; l++) {
        address[256 + 2] = l;
        address[256 + 12] = 0;
        let startPos = 0;
        if (r === 0 && s === 0) {
          startPos = 2;
          if (dataIndependent) {
            address[256 + 12]++;
            block(address, 256, 2 * 256, 0, false);
            block(address, 0, 2 * 256, 0, false);
          }
        }
        // current block position
        let offset = l * laneLen + s * segmentLen + startPos;
        for (let index = startPos; index < segmentLen; index++, offset++) {
          perBlock();
          // Previous block position: wraps to the lane's last block only at lane start,
          // which can happen here only for the first block of slice 0 on passes > 0.
          const prev = offset % laneLen ? offset - 1 : offset + laneLen - 1;
          let randL, randH;
          if (dataIndependent) {
            let i128 = index % 128;
            // RFC 9106 §3.4.1.2: each 1024-byte address block yields 128 `(J1, J2)` pairs, so
            // regenerate it whenever the segment index crosses a multiple of 128.
            if (i128 === 0) {
              address[256 + 12]++;
              block(address, 256, 2 * 256, 0, false);
              block(address, 0, 2 * 256, 0, false);
            }
            randL = address[2 * i128];
            randH = address[2 * i128 + 1];
          } else {
            const T = 256 * prev;
            randL = B[T];
            randH = B[T + 1];
          }
          // Address-block path selects `J1` / `J2`, then maps them to the reference
          // lane/block per RFC 9106 §3.4.
          const refLane = r === 0 && s === 0 ? l : randH % lanes;
          const refPos = indexAlpha(r, s, laneLen, segmentLen, index, randL, refLane == l);
          const refBlock = laneLen * refLane + refPos;
          // B[i][j] = G(B[i][j-1], B[l][z])
          block(B, 256 * prev, 256 * refBlock, offset * 256, needXor);
          // Yielding per block costs ~3% of runtime for generator resumes; every 32 blocks
          // (~50us of work) still paces the async driver far below its default 10ms tick.
          if ((index & 31) === 31) yield;
        }
      }
    }
  }
  clean(address);
}

function argon2(
  type: Types,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): TRet<Uint8Array> {
  const ctx = argon2Init(password, salt, type, opts);
  const blocks = argon2Blocks(ctx);
  while (!blocks.next().done) {}
  return argon2Output(ctx.B, ctx.p, ctx.laneLen, ctx.dkLen);
}

/**
 * Argon2d GPU-resistant version.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2d.
 * ```ts
 * argon2d('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 * @example
 * Derive a key with optional secret and scheduler controls.
 * ```ts
 * const progressLog: number[] = [];
 * argon2d('password', 'salt1234', {
 *   t: 1,
 *   m: 8,
 *   p: 1,
 *   dkLen: 32,
 *   version: 0x13,
 *   key: 'secret',
 *   personalization: 'application',
 *   maxmem: 1024 * 1024,
 *   asyncTick: 1,
 *   onProgress(progress) {
 *     progressLog.push(progress);
 *   },
 * });
 * ```
 */
export const argon2d = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): TRet<Uint8Array> => argon2(AT.Argon2d, password, salt, opts);
/**
 * Argon2i side-channel-resistant version.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2i.
 * ```ts
 * argon2i('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2i = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): TRet<Uint8Array> => argon2(AT.Argon2i, password, salt, opts);
/**
 * Argon2id, combining i+d, the most popular version from RFC 9106.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2id.
 * ```ts
 * argon2id('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2id = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): TRet<Uint8Array> => argon2(AT.Argon2id, password, salt, opts);

async function argon2Async(
  type: Types,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): Promise<TRet<Uint8Array>> {
  const ctx = argon2Init(password, salt, type, opts);
  const blocks = argon2Blocks(ctx);
  let ts = Date.now();
  while (!blocks.next().done) {
    // Date.now() is not monotonic. If the clock goes backwards,
    // still yield control.
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < ctx.asyncTick) continue;
    await nextTick();
    ts += diff;
  }
  return argon2Output(ctx.B, ctx.p, ctx.laneLen, ctx.dkLen);
}

/**
 * Argon2d async GPU-resistant version.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Promise resolving to derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2d asynchronously.
 * ```ts
 * await argon2dAsync('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 * @example
 * Derive a key asynchronously with optional secret and scheduler controls.
 * ```ts
 * await argon2dAsync('password', 'salt1234', {
 *   t: 1,
 *   m: 8,
 *   p: 1,
 *   dkLen: 32,
 *   version: 0x13,
 *   key: 'secret',
 *   personalization: 'application',
 *   maxmem: 1024 * 1024,
 *   asyncTick: 1,
 *   onProgress(progress) {
 *     if (progress > 1) throw new Error('invalid progress');
 *   },
 * });
 * ```
 */
export const argon2dAsync = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): Promise<TRet<Uint8Array>> => argon2Async(AT.Argon2d, password, salt, opts);
/**
 * Argon2i async side-channel-resistant version.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Promise resolving to derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2i asynchronously.
 * ```ts
 * await argon2iAsync('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2iAsync = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): Promise<TRet<Uint8Array>> => argon2Async(AT.Argon2i, password, salt, opts);
/**
 * Argon2id async, combining i+d, the most popular version from RFC 9106.
 * @param password - password or input key material
 * @param salt - unique salt value
 * @param opts - Argon2 cost and optional tuning parameters. See {@link ArgonOpts}.
 * @returns Promise resolving to derived key bytes.
 * @throws If the Argon2 input or cost parameters are invalid. {@link Error}
 * @example
 * Derive a key with Argon2id asynchronously.
 * ```ts
 * await argon2idAsync('password', 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32 });
 * ```
 */
export const argon2idAsync = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<ArgonOpts>
): Promise<TRet<Uint8Array>> => argon2Async(AT.Argon2id, password, salt, opts);
