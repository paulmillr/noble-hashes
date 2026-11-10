import { readFileSync } from 'node:fs';

// Independent check of the SHA-384 / SHA-512 round constants that `src/sha2.ts` derives at import.
// Three sources must agree on all 80 words:
//   1. the table printed in FIPS 180-4 section 4.2.3 (below),
//   2. a binary-search cube root here, sharing no code with the library,
//   3. the derivation block of `src/sha2.ts`, extracted and evaluated as is.
// Run with `--check` (also the default); `--print` prints the split high/low tables.

// prettier-ignore
const FIPS = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const MASK32 = 0xffffffffn;

function integerRoot(n, degree) {
  let bits = 0;
  for (let x = n; x; x >>= 1n) bits++;
  let low = 0n;
  let high = 1n << BigInt(Math.ceil(bits / degree) + 1);
  while (low + 1n < high) {
    const mid = (low + high) >> 1n;
    if (mid ** BigInt(degree) <= n) low = mid;
    else high = mid;
  }
  return low;
}

function firstPrimes(count) {
  const out = [];
  for (let n = 2; out.length < count; n++) {
    let prime = true;
    for (let d = 2; d * d <= n; d++) {
      if (n % d === 0) {
        prime = false;
        break;
      }
    }
    if (prime) out.push(n);
  }
  return out;
}

// floor(cuberoot(p) * 2^64) is cuberoot(p * 2^192). Subtract the integer part to retain the
// first 64 fractional bits required by FIPS 180-4 section 4.2.3.
const SCALE = 1n << 64n;
const K = firstPrimes(80).map((p) => {
  const scaled = integerRoot(BigInt(p) << 192n, 3);
  return scaled - integerRoot(BigInt(p), 3) * SCALE;
});

// The library block is plain JS (no type syntax), so it can run unmodified.
function libraryConstants() {
  const source = readFileSync(new URL('../../src/sha2.ts', import.meta.url), 'utf8');
  const beginMarker = '// BEGIN derived SHA-512 constants';
  const endMarker = '// END derived SHA-512 constants';
  const begin = source.indexOf(beginMarker);
  const end = source.indexOf(endMarker, begin);
  if (begin < 0 || end < 0) throw new Error('src/sha2.ts SHA-512 constant block not found');
  const block = source.slice(begin + beginMarker.length, end);
  const words = new Function(`${block}; return SHA512_K;`)();
  if (!(words instanceof Uint32Array) || words.length !== 160)
    throw new Error('src/sha2.ts SHA-512 constants have unexpected shape');
  // Interleaved halves: words[2 * t] high, words[2 * t + 1] low.
  return Array.from(
    { length: 80 },
    (_, t) => (BigInt(words[2 * t]) << 32n) | BigInt(words[2 * t + 1])
  );
}

function check() {
  const lib = libraryConstants();
  if (FIPS.length !== 80) throw new Error('FIPS table must have 80 words');
  for (let t = 0; t < 80; t++) {
    if (K[t] !== FIPS[t]) throw new Error(`cube-root derivation differs from FIPS at t=${t}`);
    if (lib[t] !== FIPS[t]) throw new Error(`src/sha2.ts constant differs from FIPS at t=${t}`);
  }
}

if (process.argv[2] === '--print') {
  const hex = (n) => `0x${n.toString(16).padStart(8, '0')}`;
  for (const [name, high] of [
    ['SHA512_Kh', true],
    ['SHA512_Kl', false],
  ]) {
    const words = K.map((n) => (high ? n >> 32n : n & MASK32));
    console.log(`${name}:`);
    for (let i = 0; i < 80; i += 8)
      console.log(
        '  ' +
          words
            .slice(i, i + 8)
            .map(hex)
            .join(', ') +
          ','
      );
  }
} else {
  check();
  console.log('SHA-512 round constants: FIPS table, cube-root derivation and src/sha2.ts agree');
}
