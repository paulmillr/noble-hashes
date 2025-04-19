// Utilities to generate IV for SHA2 (sha256, sha512...)
// IV = initial value = initial state
// Check out [RFC 4634](https://datatracker.ietf.org/doc/html/rfc4634) and
// [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

function sqrt(n) {
  // floor(sqrt(n)) using Newton's method
  if (n < 0n) throw new Error('sqrt <0 unsupported');
  if (n < 2n) return n;
  let x0 = n >> 1n;
  let x1 = (x0 + n / x0) >> 1n; // init guess: n>>1
  while (x1 < x0) {
    x0 = x1;
    x1 = (x0 + n / x0) >> 1n;
  }
  return x0;
}
const bits = 64;
const scale = 1n << BigInt(bits); // 2^bits
const factor = 1n << BigInt(2 * bits); // 2^(2*bits)
const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
const sqrts = primes.map((p) => {
  const pBI = BigInt(p);
  // floor(sqrt(p) * 2^bits) = integerSqrt(p * 2^(2*bits))
  const scaledSqrt = sqrt(pBI * factor);
  const intSqrt = sqrt(pBI); // floor(sqrt(p))
  return scaledSqrt - intSqrt * scale; // fractional part * 2^bits
});
const SHA256_IV = sqrts.slice(0, 8).map((n) => n >> 32n); // first 32bit
const SHA224_IV = sqrts.slice(8, 16).map((n) => n & 0xffffffffn); // second 32bit
const SHA512_IV = sqrts.slice(0, 8);
const SHA384_IV = sqrts.slice(8, 16);

// The SHA-512/t IV generation function
// FIPS 180-4
// SHA512_IV is XORed with 0xa5a5a5a5a5a5a5a5, then used as "intermediary" IV of SHA512/t.
// Then t() hashes string to produce result IV.
import * as u64 from '../../esm/_u64.js';
import { SHA512 } from '../../esm/sha2.js';
function splitIntoOne(lst, le = false) {
  let AhAl = new Uint32Array(lst.length * 2);
  for (let i = 0; i < lst.length; i++) {
    const { h, l } = u64.fromBig(lst[i], le);
    AhAl[2 * i] = h;
    AhAl[2 * i + 1] = l;
    // [Ah[i], Al[i]] = [h, l];
  }
  return AhAl;
}

const SHA_T = splitIntoOne(SHA512_IV.map((n) => n ^ 0xa5a5a5a5a5a5a5a5n));
class SHA512_T extends SHA512 {
  Ah = SHA_T[0] | 0;
  Al = SHA_T[1] | 0;
  Bh = SHA_T[2] | 0;
  Bl = SHA_T[3] | 0;
  Ch = SHA_T[4] | 0;
  Cl = SHA_T[5] | 0;
  Dh = SHA_T[6] | 0;
  Dl = SHA_T[7] | 0;
  Eh = SHA_T[8] | 0;
  El = SHA_T[9] | 0;
  Fh = SHA_T[10] | 0;
  Fl = SHA_T[11] | 0;
  Gh = SHA_T[12] | 0;
  Gl = SHA_T[13] | 0;
  Hh = SHA_T[14] | 0;
  Hl = SHA_T[15] | 0;
  constructor() {
    super(64);
  }
}
const ivT = (mode) => new BigUint64Array(new SHA512_T().update(mode).digest().buffer);
const SHA512_256_IV = ivT('SHA-512/256');
const SHA512_224_IV = ivT('SHA-512/224');

console.log({
  SHA256_IV,
  SHA224_IV,
  SHA512_IV,
  SHA384_IV,
  SHA512_256_IV,
  SHA512_224_IV,
});
