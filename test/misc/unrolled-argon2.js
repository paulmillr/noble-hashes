/** Generates the loop-form interleaved Argon2 permutation in src/argon2.ts. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const START = '// BEGIN generated Argon2 permutation';
const END = '// END generated Argon2 permutation';

// RFC 9106 Figure 18 runs the column G's G(0,4,8,12)..G(3,7,11,15), then the diagonal G's
// G(0,5,10,15)..G(3,4,9,14). We emit only the column half, as four interleaved chains over fixed
// locals, and run it twice: between the halves, rows 1..3 of the 4x4 word matrix rotate left by
// 1..3 slots (plain local moves), so the same code computes the diagonal G's.
const chains = [
  [0, 4, 8, 12],
  [1, 5, 9, 13],
  [2, 6, 10, 14],
  [3, 7, 11, 15],
];
// [target, operand, rotated, rotation]
const steps = [
  [0, 1, 3, 32],
  [2, 3, 1, 24],
  [0, 1, 3, 16],
  [2, 3, 1, 63],
];

const n = (i) => `${i}`.padStart(2, '0');
const V = (i, half) => `V${n(i)}${half}`;
const names = 'ABCD';
const IND = '    ';

function rotate(i, chain, bits) {
  const h = V(i, 'h');
  const l = V(i, 'l');
  if (bits === 32) return `${h} = xl${chain}; ${l} = xh${chain};`;
  if (bits === 24)
    return `${h} = (xh${chain} >>> 24) | (xl${chain} << 8); ${l} = (xh${chain} << 8) | (xl${chain} >>> 24);`;
  if (bits === 16)
    return `${h} = (xh${chain} >>> 16) | (xl${chain} << 16); ${l} = (xh${chain} << 16) | (xl${chain} >>> 16);`;
  return `${h} = (xh${chain} << 1) | (xl${chain} >>> 31); ${l} = (xh${chain} >>> 31) | (xl${chain} << 1);`;
}

function genStep(chain, positions, [target, operand, rotated, bits]) {
  const Al = V(positions[target], 'l');
  const Ah = V(positions[target], 'h');
  const Bl = V(positions[operand], 'l');
  const Bh = V(positions[operand], 'h');
  const Rl = V(positions[rotated], 'l');
  const Rh = V(positions[rotated], 'h');
  return `${IND}ml${chain} = Math.imul(${Al}, ${Bl});
${IND}mh${chain} = (((${Al} >>> 0) * (${Bl} >>> 0) - (ml${chain} >>> 0)) / 0x100000000 + 0.5) | 0;
${IND}rl${chain} = (${Al} >>> 0) + (${Bl} >>> 0) + ((ml${chain} << 1) >>> 0);
${IND}${Ah} = (${Ah} + ${Bh} + ((mh${chain} << 1) | (ml${chain} >>> 31)) + ((rl${chain} / 0x100000000) | 0)) | 0;
${IND}${Al} = rl${chain} | 0;
${IND}xh${chain} = ${Rh} ^ ${Ah}; xl${chain} = ${Rl} ^ ${Al};
${IND}${rotate(positions[rotated], chain, bits)}`;
}

function genHalf() {
  const out = [];
  for (let s = 0; s < steps.length; s++) {
    const [target, operand, rotated, bits] = steps[s];
    const A = names[target];
    const B = names[operand];
    const R = names[rotated];
    out.push(
      `${IND}// step ${s + 1}: ${A} += ${B} + 2*${A}l${B}l; ${R} = rotr64(${R}^${A}, ${bits}) - all 4 chains`
    );
    for (let chain = 0; chain < 4; chain++) out.push(genStep(chain, chains[chain], steps[s]));
  }
  return out.join('\n');
}

// Rotate the four slots of matrix row `row` left by `k` (slot j takes slot j + k), reusing xl0.
function rotateRow(row, k) {
  const out = [];
  for (const half of ['l', 'h']) {
    const s = (j) => V(4 * row + (j % 4), half);
    if (k === 2)
      out.push(
        `xl0 = ${s(0)}; ${s(0)} = ${s(2)}; ${s(2)} = xl0; xl0 = ${s(1)}; ${s(1)} = ${s(3)}; ${s(3)} = xl0;`
      );
    else if (k === 1)
      out.push(
        `xl0 = ${s(0)}; ${s(0)} = ${s(1)}; ${s(1)} = ${s(2)}; ${s(2)} = ${s(3)}; ${s(3)} = xl0;`
      );
    else
      out.push(
        `xl0 = ${s(3)}; ${s(3)} = ${s(2)}; ${s(2)} = ${s(1)}; ${s(1)} = ${s(0)}; ${s(0)} = xl0;`
      );
  }
  return out.map((l) => IND + l).join('\n');
}

// u32 offset of the low half of word `w` (0..15) inside one P() group, relative to its base.
// Row groups are 32 consecutive u32. Column groups take two adjacent registers (four u32) from
// each of the eight rows, so word pairs sit 32 u32 apart.
const rowOff = (w) => 2 * w;
const colOff = (w) => (w >> 1) * 32 + 2 * (w & 1);
const at = (base, off) => (off ? `${base} + ${off}` : base);
// Both iterations end with the row rotation, so row r ends rotated left by 2r: word 4r + k sits in
// slot 4r + ((k - 2r) mod 4). Rows 0 and 2 are back in place; rows 1 and 3 have their halves swapped.
const slot = (w) => 4 * (w >> 2) + (((((w & 3) - 2 * (w >> 2)) % 4) + 4) % 4);

function generate() {
  const words = Array.from({ length: 16 }, (_, w) => w);
  const decl = words.map((w) => `${V(w, 'l')} = 0, ${V(w, 'h')} = 0`);
  const rowLoads = words.map((w) => {
    const [l, h] = [rowOff(w), rowOff(w) + 1];
    return `    ${V(w, 'l')} = x[${at('a', l)}] ^ x[${at('b', l)}]; ${V(w, 'h')} = x[${at('a', h)}] ^ x[${at('b', h)}];`;
  });
  const colLoads = words.map((w) => {
    const [l, h] = [colOff(w), colOff(w) + 1];
    return `    ${V(w, 'l')} = T[${at('t', l)}] | 0; ${V(w, 'h')} = T[${at('t', h)}] | 0;`;
  });
  const rowStores = words.map((w) => {
    const [l, h] = [rowOff(w), rowOff(w) + 1];
    return `    T[${at('t', l)}] = ${V(slot(w), 'l')}; T[${at('t', h)}] = ${V(slot(w), 'h')};`;
  });
  const colStores = words.map((w) => {
    const st = (off, v) => `x[${at('o', off)}] ^= x[${at('a', off)}] ^ x[${at('b', off)}] ^ ${v};`;
    return `    ${st(colOff(w), V(slot(w), 'l'))} ${st(colOff(w) + 1, V(slot(w), 'h'))}`;
  });
  return `${START}
// Generated by test/misc/unrolled-argon2.js. Do not edit by hand.
// prettier-ignore
function P(x: TArg<Uint32Array>, a: number, b: number, o: number, t: number, row: boolean) {
  const T = A2_BUF;
  // No-op for valid offsets (< 2^30), but lets the JIT drop int32 overflow checks on index sums.
  a &= 0x3fffffff; b &= 0x3fffffff; o &= 0x3fffffff; t &= 0xff;
  let ${decl.slice(0, 8).join(', ')},
      ${decl.slice(8).join(', ')};
  if (row) {
${rowLoads.join('\n')}
  } else {
    // Mixed Uint32Array loads and int32 xors would merge into a non-int32 type; keep int32.
${colLoads.join('\n')}
  }
  let ml0 = 0, mh0 = 0, rl0 = 0, xl0 = 0, xh0 = 0,
      ml1 = 0, mh1 = 0, rl1 = 0, xl1 = 0, xh1 = 0,
      ml2 = 0, mh2 = 0, rl2 = 0, xl2 = 0, xh2 = 0,
      ml3 = 0, mh3 = 0, rl3 = 0, xl3 = 0, xh3 = 0;
  // i = 0: G(0, 4, 8, 12), G(1, 5, 9, 13), G(2, 6, 10, 14), G(3, 7, 11, 15), four chains interleaved;
  // rows 1..3 then rotate left by 1..3 so that, for i = 1, the same slots hold the diagonals
  // G(0, 5, 10, 15), G(1, 6, 11, 12), G(2, 7, 8, 13), G(3, 4, 9, 14).
  for (let i = 0; i < 2; i++) {
${genHalf()}
    // rows 1..3: rotate left by 1, 2, 3 slots
${rotateRow(1, 1)}
${rotateRow(2, 2)}
${rotateRow(3, 3)}
  }
  // Row r is now rotated left by 2r slots (rows 1 and 3 have swapped halves); stores undo that.
  if (row) {
${rowStores.join('\n')}
  } else {
${colStores.join('\n')}
  }
}
${END}`;
}

const generated = generate();
if (process.argv[2] === '--check') {
  const source = readFileSync(new URL('../../src/argon2.ts', import.meta.url), 'utf8');
  const start = source.indexOf(START);
  const end = source.indexOf(END, start);
  assert.notEqual(start, -1, `missing source marker: ${START}`);
  assert.notEqual(end, -1, `missing source marker: ${END}`);
  assert.equal(source.slice(start, end + END.length), generated);
  console.log('src/argon2.ts permutation matches generator');
} else if (process.argv.length === 2) {
  console.log(generated);
} else {
  console.error('Usage: node test/misc/unrolled-argon2.js [--check]');
  process.exitCode = 1;
}
