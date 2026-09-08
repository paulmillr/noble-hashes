import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { RANDOM } from './generator.ts';
import { HASHES } from './hashes.test.ts';
import { PLATFORMS } from './platform.ts';
import { stats } from './utils.ts';

// Wall-clock timings include time when the process is descheduled. On a busy CI runner that can
// make a larger input look disproportionately slow, so measure CPU time spent by this process.
const getCpuTime = () => {
  const { user, system } = process.cpuUsage();
  return user + system;
};
const MIN_SAMPLE_TIME = 10_000; // 10ms in the microseconds returned by process.cpuUsage().
const DEFAULT_PLATFORM = PLATFORMS.noble || Object.values(PLATFORMS)[0];
const BT = { describe, it };

let timingSink = 0;
function linear(buf) {
  let acc = 0;
  for (let i = 0; i < buf.length; i++) acc ^= buf[i];
  timingSink ^= acc;
}
function quadratic(buf) {
  let acc = 0;
  for (let i = 0; i < buf.length; i++)
    for (let j = 0; j < buf.length; j++) acc ^= (buf[i] + j) & 0xff;
  timingSink ^= acc;
}

async function medianTime(callback, samples = 5) {
  let runs = 1;
  while (true) {
    const started = getCpuTime();
    for (let i = 0; i < runs; i++) await callback();
    if (getCpuTime() - started >= MIN_SAMPLE_TIME) break;
    runs *= 2;
  }
  const timings = [];
  for (let i = 0; i < samples; i++) {
    const started = getCpuTime();
    for (let j = 0; j < runs; j++) await callback();
    timings.push((getCpuTime() - started) / runs);
  }
  return stats(timings).median;
}

// Estimate the exponent in T(N)=O(N^exponent) with a least-squares fit over geometric sizes.
// Large enough inputs make call/JIT overhead negligible; serial registration avoids worker noise.
async function complexityExponent(callback, sizes) {
  for (const size of sizes) await callback(RANDOM.subarray(0, size));
  const points = [];
  for (const size of sizes) {
    const time = await medianTime(() => callback(RANDOM.subarray(0, size)));
    points.push([Math.log(size), Math.log(time)]);
  }
  const xAvg = stats(points.map(([x]) => x)).avg;
  const yAvg = stats(points.map(([, y]) => y)).avg;
  let covariance = 0;
  let variance = 0;
  for (const [x, y] of points) {
    covariance += (x - xAvg) * (y - yAvg);
    variance += (x - xAvg) ** 2;
  }
  return { exponent: covariance / variance, points };
}

async function assertAtMostLinear(callback, sizes) {
  const { exponent, points } = await complexityExponent(callback, sizes);
  eql(
    exponent >= 0 && exponent <= 1.6,
    true,
    `expected exponent in 0..1.6, got ${exponent}: ${JSON.stringify(points)}`
  );
}

export function test(
  variant = 'noble',
  platform = DEFAULT_PLATFORM,
  hashes = HASHES,
  { describe, it } = BT
) {
  const { scrypt } = platform;
  const serial = it.serial || it;
  const run = () => {
    serial('complexity classifier distinguishes O(N) and O(N²)', async () => {
      await assertAtMostLinear(linear, [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024]);
      await rejects(() => assertAtMostLinear(quadratic, [512, 1024, 2048, 4096]));
    });

    for (const name of ['SHA256', 'SHA3_256', 'BLAKE3']) {
      const hash = hashes[name];
      if (!hash) continue;
      serial(`DoS: ${name}`, () =>
        assertAtMostLinear(hash.fn, [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024])
      );
    }

    serial('DoS: scrypt', () =>
      assertAtMostLinear(
        (buf) => scrypt(buf, buf, { N: 64, r: buf.length / 1024, p: 1, dkLen: 32 }),
        [1024, 2048, 4096, 8192]
      )
    );
  };
  return variant === 'noble' ? run() : describe(`DoS (${variant})`, run);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
