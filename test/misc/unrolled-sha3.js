/** Generates the plane-by-plane Keccak-p[1600] permutation in src/sha3.ts. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const START = '// BEGIN generated SHA3 permutation';
const END = '// END generated SHA3 permutation';

// FIPS 202 round constants, written as ordinary 64-bit hex for independent verification.
const OFFICIAL_IOTA = [
  '0000000000000001',
  '0000000000008082',
  '800000000000808a',
  '8000000080008000',
  '000000000000808b',
  '0000000080000001',
  '8000000080008081',
  '8000000000008009',
  '000000000000008a',
  '0000000000000088',
  '0000000080008009',
  '000000008000000a',
  '000000008000808b',
  '800000000000008b',
  '8000000000008089',
  '8000000000008003',
  '8000000000008002',
  '8000000000000080',
  '000000000000800a',
  '800000008000000a',
  '8000000080008081',
  '8000000000008080',
  '0000000080000001',
  '8000000080008008',
].map((n) => BigInt(`0x${n}`));

// FIPS 202 Algorithm 5 rc(): generate Iota constants from the 8-bit LFSR.
function iotas() {
  const out = [];
  let R = 1n;
  for (let round = 0; round < 24; round++) {
    let value = 0n;
    for (let j = 0; j < 7; j++) {
      R = ((R << 1n) ^ ((R >> 7n) * 0x71n)) % 256n;
      if (R & 2n) value ^= 1n << ((1n << BigInt(j)) - 1n);
    }
    out.push(value);
  }
  assert.deepEqual(out, OFFICIAL_IOTA);
  return out;
}

// FIPS 202 section 3.2.2: the 24 non-(0,0) lanes form one Pi cycle, while the
// triangular numbers give the matching Rho offsets.
function schedules() {
  const pi = [];
  const rot = [];
  for (let round = 0, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    pi.push(2 * (5 * y + x));
    rot.push((((round + 1) * (round + 2)) / 2) % 64);
  }
  assert.deepEqual(
    pi,
    [20, 14, 22, 34, 36, 6, 10, 32, 16, 42, 48, 8, 30, 46, 38, 26, 24, 4, 40, 28, 44, 18, 12, 2]
  );
  assert.deepEqual(
    rot,
    [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
  );
  return { pi, rot };
}

// Rho offsets by lane: walking the Pi cycle from lane (1, 0), the t-th visited lane rotates by
// rot[t], and pi[t] is the word index that lane moves to. Lane (0, 0) is not rotated.
function rhoOffsets(pi, rot) {
  const R = Array.from({ length: 5 }, () => Array(5).fill(0));
  const seen = new Set(['0,0']);
  for (let t = 0, x = 1, y = 0; t < 24; t++) {
    R[x][y] = rot[t];
    seen.add(`${x},${y}`);
    const lane = pi[t] / 2;
    [x, y] = [lane % 5, Math.floor(lane / 5)];
  }
  assert.equal(seen.size, 25);
  // FIPS 202 Table 2 spot checks: r[x][y] for (1,0), (0,1), (4,4), (2,3), (3,4).
  assert.deepEqual([R[1][0], R[0][1], R[4][4], R[2][3], R[3][4]], [1, 36, 14, 15, 56]);
  return R;
}

const mod5 = (n) => ((n % 5) + 5) % 5;
// Lane (x, y) occupies words 2 * (x + 5 * y) (low half) and 2 * (x + 5 * y) + 1 (high half).
const word = (x, y) => 2 * (x + 5 * y);
// Low and high words of a 64-bit left rotation of the lane held in locals `l`, `h`.
const rot64 = (l, h, s) => {
  if (s === 32) return [h, l];
  if (s > 32) {
    const q = s - 32;
    return [`((${h} << ${q}) | (${l} >>> ${32 - q}))`, `((${l} << ${q}) | (${h} >>> ${32 - q}))`];
  }
  return [`((${l} << ${s}) | (${h} >>> ${32 - s}))`, `((${h} << ${s}) | (${l} >>> ${32 - s}))`];
};

// One plane-by-plane round from `src` to `dst`. On entry c0..c9 hold the Theta column parities
// of `src`; on exit they hold the column parities of `dst` (early parity for the next round).
function round(R, src, dst, iota) {
  const out = ['// Theta θ column effects, from the parities carried in c0..c9'];
  for (let x = 0; x < 5; x++) {
    const n = 2 * mod5(x + 1);
    const p = 2 * mod5(x - 1);
    out.push(`d${2 * x} = ((c${n} << 1) | (c${n + 1} >>> 31)) ^ c${p};`);
    out.push(`d${2 * x + 1} = ((c${n + 1} << 1) | (c${n} >>> 31)) ^ c${p + 1};`);
  }
  for (let y = 0; y < 5; y++) {
    // Pi π fills output lane (x, y) from input lane (x + 3y, x); Theta and Rho ρ apply on load.
    out.push(`// Plane y=${y}: Theta, Rho ρ and Pi π into e0..e9, then Chi χ into ${dst}`);
    for (let x = 0; x < 5; x++) {
      const sx = mod5(x + 3 * y);
      const w = word(sx, x);
      const r = R[sx][x];
      if (r === 0) {
        out.push(`e${2 * x} = ${src}[${w}] ^ d${2 * sx}; e${2 * x + 1} = ${src}[${w + 1}] ^ d${2 * sx + 1};`);
        continue;
      }
      const [lo, hi] = rot64('l', 'h', r);
      out.push(`l = ${src}[${w}] ^ d${2 * sx}; h = ${src}[${w + 1}] ^ d${2 * sx + 1};`);
      out.push(`e${2 * x} = ${lo}; e${2 * x + 1} = ${hi};`);
    }
    for (let x = 0; x < 5; x++) {
      const a = 2 * x;
      const b = 2 * mod5(x + 1);
      const c = 2 * mod5(x + 2);
      const w = word(x, y);
      const op = y === 0 ? '=' : '^=';
      // Iota ι folds into lane (0, 0).
      const iLo = y === 0 && x === 0 ? ` ^ SHA3_IOTA_LO[${iota}]` : '';
      const iHi = y === 0 && x === 0 ? ` ^ SHA3_IOTA_HI[${iota}]` : '';
      out.push(`v = e${a} ^ (~e${b} & e${c})${iLo}; ${dst}[${w}] = v; c${a} ${op} v;`);
      out.push(`v = e${a + 1} ^ (~e${b + 1} & e${c + 1})${iHi}; ${dst}[${w + 1}] = v; c${a + 1} ${op} v;`);
    }
  }
  return out;
}

const locals = (p, from) =>
  Array.from({ length: 5 }, (_, i) => `${p}${from + i}: number`).join(', ');
const indent = (n, lines) => lines.map((line) => ' '.repeat(n) + line);

// Emulates the load-time Iota loop emitted below with the same Number arithmetic, so the
// generator checks it against the official constants before emitting it.
function iotaWords() {
  const lo = new Int32Array(24);
  const hi = new Int32Array(24);
  for (let round = 0, R = 1; round < 24; round++) {
    for (let j = 0; j < 7; j++) {
      R = ((R << 1) ^ ((R >> 7) * 0x71)) & 0xff;
      if (R & 2) {
        if (j < 6) lo[round] ^= 1 << ((1 << j) - 1);
        else hi[round] ^= 1 << 31;
      }
    }
  }
  return { lo, hi };
}

function generate() {
  const constants = iotas();
  const { lo, hi } = iotaWords();
  assert.deepEqual(
    Array.from(lo, (n) => n >>> 0),
    constants.map((n) => Number(n & 0xffffffffn))
  );
  assert.deepEqual(
    Array.from(hi, (n) => n >>> 0),
    constants.map((n) => Number((n >> 32n) & 0xffffffffn))
  );
  const { pi, rot } = schedules();
  const R = rhoOffsets(pi, rot);
  const parity = [];
  for (let x = 0; x < 10; x++)
    parity.push(`c${x} = s[${x}] ^ s[${x + 10}] ^ s[${x + 20}] ^ s[${x + 30}] ^ s[${x + 40}];`);
  // Both round bodies read `a` and write `b`, so they are the same text: the minifier gives the
  // block-scoped aliases the same names, and gzip stores the second body as back-references.
  const body = round(R, 'a', 'b', 'round');
  return [
    START,
    '// Generated by test/misc/unrolled-sha3.js. Do not edit by hand.',
    '// Every typed array read here is an Int32Array: JSC can speculate that Uint32Array loads fit',
    '// in int32 and then keep deoptimizing on words with bit 31 set. XOR results are identical.',
    '// FIPS 202 Algorithm 5 rc(): an 8-bit LFSR with feedback mask 0x71. Round-constant bit 2^j - 1',
    '// (j = 0..6) is bit 0, 1, 3, 7, 15 or 31 of the low word, or bit 31 of the high word for j = 6.',
    'const SHA3_IOTA_LO = /* @__PURE__ */ new Int32Array(24);',
    'const SHA3_IOTA_HI = /* @__PURE__ */ new Int32Array(24);',
    'for (let round = 0, R = 1; round < 24; round++) {',
    '  for (let j = 0; j < 7; j++) {',
    '    R = ((R << 1) ^ ((R >> 7) * 0x71)) & 0xff;',
    '    if (R & 2) {',
    '      if (j < 6) SHA3_IOTA_LO[round] ^= 1 << ((1 << j) - 1);',
    '      else SHA3_IOTA_HI[round] ^= 1 << 31;',
    '    }',
    '  }',
    '}',
    '// Rounds alternate between the caller state and this buffer. The permutation never runs',
    '// caller code, so sharing it is reentrancy-safe; it is zeroed before every return.',
    'const SHA3_SCRATCH = /* @__PURE__ */ new Int32Array(50);',
    '',
    '// prettier-ignore',
    'function keccakP1600(s: TArg<Int32Array>, rounds: number): void {',
    '  const t = SHA3_SCRATCH;',
    '  let h: number, l: number, v: number;',
    ...['c', 'd', 'e'].flatMap((p) => [`  let ${locals(p, 0)};`, `  let ${locals(p, 5)};`]),
    ...indent(2, parity),
    '  // Rounds run in pairs s -> t -> s; an odd count replaces the first half with a copy.',
    '  // Both halves read `a` and write `b`: identical text, so gzip stores the second half as a',
    '  // back-reference. The aliases are block-scoped constants and cost nothing at run time.',
    '  const start = 24 - rounds;',
    '  for (let round = start & ~1; round < 24; round++) {',
    '    if (round < start) t.set(s);',
    '    else {',
    '      const a = s, b = t;',
    ...indent(6, body),
    '    }',
    '    round++;',
    '    {',
    '      const a = t, b = s;',
    ...indent(6, body),
    '    }',
    '  }',
    '  for (let i = 0; i < 50; i++) t[i] = 0;',
    '}',
    END,
  ].join('\n');
}

const generated = generate();
if (process.argv[2] === '--check') {
  const source = readFileSync(new URL('../../src/sha3.ts', import.meta.url), 'utf8');
  const start = source.indexOf(START);
  const end = source.indexOf(END, start);
  assert.notEqual(start, -1, `missing source marker: ${START}`);
  assert.notEqual(end, -1, `missing source marker: ${END}`);
  assert.equal(source.slice(start, end + END.length), generated);
  console.log('src/sha3.ts permutation matches generator');
} else if (process.argv.length === 2) {
  console.log(generated);
} else {
  console.error('Usage: node test/misc/unrolled-sha3.js [--check]');
  process.exitCode = 1;
}
