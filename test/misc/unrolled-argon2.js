/** Generates the interleaved Argon2 permutation in src/argon2.ts. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Four independent G chains per half of RFC 9106 Figure 18.
const halves = [
  [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
  ],
  [
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
  ],
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
  return `  ml${chain} = Math.imul(${Al}, ${Bl});
  mh${chain} = (((${Al} >>> 0) * (${Bl} >>> 0) - (ml${chain} >>> 0)) / 0x100000000 + 0.5) | 0;
  rl${chain} = (${Al} >>> 0) + (${Bl} >>> 0) + ((ml${chain} << 1) >>> 0);
  ${Ah} = (${Ah} + ${Bh} + ((mh${chain} << 1) | (ml${chain} >>> 31)) + ((rl${chain} / 0x100000000) | 0)) | 0;
  ${Al} = rl${chain} | 0;
  xh${chain} = ${Rh} ^ ${Ah}; xl${chain} = ${Rl} ^ ${Al};
  ${rotate(positions[rotated], chain, bits)}`;
}

function genHalf(chains, half) {
  const out = [
    `  // ${half ? 'Second' : 'First'} half: ${chains.map((g) => `G(${g.join(', ')})`).join(', ')}, four chains interleaved.`,
  ];
  for (let s = 0; s < steps.length; s++) {
    const [target, operand, rotated, bits] = steps[s];
    const A = names[target];
    const B = names[operand];
    const R = names[rotated];
    out.push(
      `  // step ${s + 1}: ${A} += ${B} + 2*${A}l${B}l; ${R} = rotr64(${R}^${A}, ${bits}) - all 4 chains`
    );
    for (let chain = 0; chain < 4; chain++) out.push(genStep(chain, chains[chain], steps[s]));
  }
  return out.join('\n');
}

function generate() {
  const params = Array.from({ length: 16 }, (_, i) => `i${n(i)}: number`).join(', ');
  const loads = Array.from(
    { length: 16 },
    (_, i) => `  let ${V(i, 'l')} = x[2 * i${n(i)}], ${V(i, 'h')} = x[2 * i${n(i)} + 1];`
  ).join('\n');
  const stores = Array.from(
    { length: 16 },
    (_, i) => `  x[2 * i${n(i)}] = ${V(i, 'l')}; x[2 * i${n(i)} + 1] = ${V(i, 'h')};`
  ).join('\n');
  return `// prettier-ignore
function P(
  ${params},
) {
  const x = A2_BUF;
${loads}
  let ml0 = 0, mh0 = 0, rl0 = 0, xl0 = 0, xh0 = 0,
      ml1 = 0, mh1 = 0, rl1 = 0, xl1 = 0, xh1 = 0,
      ml2 = 0, mh2 = 0, rl2 = 0, xl2 = 0, xh2 = 0,
      ml3 = 0, mh3 = 0, rl3 = 0, xl3 = 0, xh3 = 0;
${halves.map(genHalf).join('\n')}
${stores}
}`;
}

const generated = generate();
if (process.argv[2] === '--check') {
  const source = readFileSync(new URL('../../src/argon2.ts', import.meta.url), 'utf8');
  const start = source.indexOf('// prettier-ignore\nfunction P(');
  const end = source.indexOf('\n\nfunction block', start);
  assert.equal(source.slice(start, end), generated);
  console.log('src/argon2.ts permutation matches generator');
} else if (process.argv.length === 2) {
  console.log(generated);
} else {
  console.error('Usage: node test/misc/unrolled-argon2.js [--check]');
  process.exitCode = 1;
}
