/**
 * Generates the two-round loop BLAKE3 compression in src/blake3.ts.
 *
 * The 16 state words and 16 message words stay in locals. ROUNDS_PER_ITERATION rounds are spelled
 * out inside a loop: round k of an iteration reads the message locals through MSG_PERMUTATION^k,
 * and the iteration ends by applying MSG_PERMUTATION^ROUNDS_PER_ITERATION to the locals, the way
 * the official reference implementation permutes its message array between rounds. The remaining
 * 7 % ROUNDS_PER_ITERATION rounds follow the loop. There is no schedule table and no typed-array
 * message read inside a round.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const START = '// BEGIN generated BLAKE3 compression';
const END = '// END generated BLAKE3 compression';

const ROUNDS = 7;
// 1 is the smallest form, 7 is the full unroll. 2 (three spelled-out rounds, counting the tail)
// keeps JavaScriptCore's large-input speed close to the full unroll at about a third of its size.
const ROUNDS_PER_ITERATION = 2;
const ITERATIONS = Math.floor(ROUNDS / ROUNDS_PER_ITERATION);
const TAIL_ROUNDS = ROUNDS % ROUNDS_PER_ITERATION;

// BLAKE3's message permutation is applied between each of seven rounds.
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const OFFICIAL_SCHEDULES = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
  [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
  [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
  [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
  [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
  [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// MSG_PERMUTATION composed k times: schedule position i of round k reads local m<result[i]>.
function permutationPower(k) {
  let out = Array.from({ length: 16 }, (_, i) => i);
  for (let j = 0; j < k; j++) out = MSG_PERMUTATION.map((i) => out[i]);
  return out;
}

// Cycles of the in-place update "new m[i] = old m[P[i]]"; each needs only one temporary.
function cycles(P) {
  const seen = new Set();
  const out = [];
  for (let start = 0; start < 16; start++) {
    if (seen.has(start) || P[start] === start) continue;
    const cycle = [];
    for (let i = start; !seen.has(i); i = P[i]) {
      seen.add(i);
      cycle.push(i);
    }
    out.push(cycle);
  }
  return out;
}

const STEP = permutationPower(ROUNDS_PER_ITERATION);
const STEP_CYCLES = cycles(STEP);

// Execute the emitted shape symbolically: every round must read the official schedule.
function verifySchedules() {
  const held = Array.from({ length: 16 }, (_, i) => i); // held[n] = message word in local m<n>
  const read = (k) => permutationPower(k).map((n) => held[n]);
  let round = 0;
  for (let iteration = 0; iteration < ITERATIONS; iteration++) {
    for (let k = 0; k < ROUNDS_PER_ITERATION; k++)
      assert.deepEqual(read(k), OFFICIAL_SCHEDULES[round++]);
    for (const cycle of STEP_CYCLES) {
      const t = held[cycle[0]];
      for (let i = 0; i < cycle.length - 1; i++) held[cycle[i]] = held[cycle[i + 1]];
      held[cycle[cycle.length - 1]] = t;
    }
  }
  for (let k = 0; k < TAIL_ROUNDS; k++) assert.deepEqual(read(k), OFFICIAL_SCHEDULES[round++]);
  assert.equal(round, ROUNDS);
}

// Four column Gs followed by four diagonal Gs. Each G is emitted in full before the next one.
const G_INDICES = [
  [0, 4, 8, 12],
  [1, 5, 9, 13],
  [2, 6, 10, 14],
  [3, 7, 11, 15],
  [0, 5, 10, 15],
  [1, 6, 11, 12],
  [2, 7, 8, 13],
  [3, 4, 9, 14],
];

function genG([a, b, c, d], mx, my, pad) {
  return `${pad}v${a} = (v${a} + v${b} + m${mx}) | 0; v${d} ^= v${a}; v${d} = (v${d} >>> 16) | (v${d} << 16);
${pad}v${c} = (v${c} + v${d}) | 0; v${b} ^= v${c}; v${b} = (v${b} >>> 12) | (v${b} << 20);
${pad}v${a} = (v${a} + v${b} + m${my}) | 0; v${d} ^= v${a}; v${d} = (v${d} >>> 8) | (v${d} << 24);
${pad}v${c} = (v${c} + v${d}) | 0; v${b} ^= v${c}; v${b} = (v${b} >>> 7) | (v${b} << 25);`;
}

// `label` names the round; `k` selects which power of the permutation its message reads use.
function genRound(k, label, pad) {
  const order = permutationPower(k);
  const out = [`${pad}// ${label}: ${order.join(', ')}`, `${pad}// columns`];
  for (let i = 0; i < 4; i++) out.push(genG(G_INDICES[i], order[2 * i], order[2 * i + 1], pad));
  out.push(`${pad}// diagonals`);
  for (let i = 4; i < 8; i++) out.push(genG(G_INDICES[i], order[2 * i], order[2 * i + 1], pad));
  return out.join('\n');
}

function genPermute(pad) {
  return STEP_CYCLES.map((cycle) => {
    const moves = [`t = m${cycle[0]}`];
    for (let i = 0; i < cycle.length - 1; i++) moves.push(`m${cycle[i]} = m${cycle[i + 1]}`);
    moves.push(`m${cycle[cycle.length - 1]} = t`);
    return `${pad}${moves.join('; ')};`;
  }).join('\n');
}

function generate() {
  verifySchedules();
  const messages = Array.from(
    { length: 16 },
    (_, i) => `m${i} = msg[offset${i ? ` + ${i}` : ''}] | 0`
  );
  const messageLoads = [];
  for (let i = 0; i < messages.length; i += 4) {
    messageLoads.push(`  let ${messages.slice(i, i + 4).join(', ')};`);
  }
  const loopRounds = [];
  for (let k = 0; k < ROUNDS_PER_ITERATION; k++)
    loopRounds.push(genRound(k, `Round ${ROUNDS_PER_ITERATION} * i${k ? ` + ${k}` : ''}`, '    '));
  const tailRounds = [];
  for (let k = 0; k < TAIL_ROUNDS; k++)
    tailRounds.push(genRound(k, `Round ${ROUNDS_PER_ITERATION * ITERATIONS + k}`, '  '));
  return `${START}
// Generated by test/misc/unrolled-blake3.js. Do not edit by hand.
// prettier-ignore
function b3Compress(
  msg: TArg<Uint32Array>,
  offset: number,
  cv: TArg<Uint32Array>,
  t0: number,
  t1: number,
  blockLen: number,
  flags: number,
  out?: TArg<Uint32Array>
) {
  let v0 = cv[0] | 0, v1 = cv[1] | 0, v2 = cv[2] | 0, v3 = cv[3] | 0;
  let v4 = cv[4] | 0, v5 = cv[5] | 0, v6 = cv[6] | 0, v7 = cv[7] | 0;
${messageLoads.join('\n')}
  let v8 = B3_IV[0] | 0, v9 = B3_IV[1] | 0, v10 = B3_IV[2] | 0, v11 = B3_IV[3] | 0;
  let v12 = t0 | 0, v13 = t1 | 0, v14 = blockLen | 0, v15 = flags | 0;
  // Message indices below name the locals a round reads, not the original message words: after
  // each iteration the locals are permuted so that the same code reads the next rounds' schedule.
  for (let i = 0, t = 0; i < ${ITERATIONS}; i++) {
${loopRounds.join('\n')}
    // Apply the message permutation ${['', 'once', 'twice'][ROUNDS_PER_ITERATION] || `${ROUNDS_PER_ITERATION} times`}, one temporary per cycle.
${genPermute('    ')}
  }
${tailRounds.length ? tailRounds.join('\n') + '\n' : ''}  // \`out\` must not overlap \`cv\`: the second output half rereads the input CV.
  const dst = out || cv;
  dst[0] = v0 ^ v8; dst[1] = v1 ^ v9; dst[2] = v2 ^ v10; dst[3] = v3 ^ v11;
  dst[4] = v4 ^ v12; dst[5] = v5 ^ v13; dst[6] = v6 ^ v14; dst[7] = v7 ^ v15;
  if (out) {
    out[8] = v8 ^ cv[0]; out[9] = v9 ^ cv[1]; out[10] = v10 ^ cv[2]; out[11] = v11 ^ cv[3];
    out[12] = v12 ^ cv[4]; out[13] = v13 ^ cv[5]; out[14] = v14 ^ cv[6]; out[15] = v15 ^ cv[7];
  }
}
${END}`;
}

const generated = generate();
if (process.argv[2] === '--check') {
  const source = readFileSync(new URL('../../src/blake3.ts', import.meta.url), 'utf8');
  const start = source.indexOf(START);
  const end = source.indexOf(END, start);
  assert.notEqual(start, -1, `missing source marker: ${START}`);
  assert.notEqual(end, -1, `missing source marker: ${END}`);
  assert.equal(source.slice(start, end + END.length), generated);
  console.log('src/blake3.ts compression matches generator');
} else if (process.argv.length === 2) {
  console.log(generated);
} else {
  console.error('Usage: node test/misc/unrolled-blake3.js [--check]');
  process.exitCode = 1;
}
