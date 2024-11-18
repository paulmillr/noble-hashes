const { deepStrictEqual, rejects, throws } = require('assert');
const { should } = require('micro-should');
const { RANDOM } = require('./generator');
const { HASHES } = require('./hashes.test');
const { stats } = require('./utils');
const { sha256 } = require('../sha256');
const { hmac } = require('../hmac');
const { hkdf } = require('../hkdf');
const { pbkdf2, pbkdf2Async } = require('../pbkdf2');
const { scrypt, scryptAsync } = require('../scrypt');
const { createView } = require('../utils');

const getTime = () => Number(process.hrtime.bigint());

// Median execution time for callback (reduce noise)
async function bench(callback, iters = 10) {
  const timings = [];
  for (let i = 0; i < iters; i++) {
    const ts = getTime();
    let val = callback();
    if (val instanceof Promise) await val;
    timings.push(getTime() - ts);
  }
  return stats(timings).median;
}
// Handle flaky tests. If complexity test passed even 1 of 5 attempts, then its ok.
// Only when all attempts failed, test is failed.
const retry =
  (callback, retries = 5) =>
  async () => {
    for (let i = 0; i < retries - 1; i++) {
      try {
        return await callback();
      } catch (e) {}
    }
    // last attempt, throw exception if failed
    return await callback();
  };

// O(N)
function linear(buf) {
  for (let i = 0; i < buf.length; i++);
}
// O(128*1024*N)
function linearConst(buf) {
  for (let i = 0; i < buf.length; i++) for (let j = 0; j < 16 * 1024; j++);
}
// O(N*log2(N))
function log2(buf) {
  for (let i = 0; i < buf.length; i++) for (let j = 0; j < Math.log2(buf.length); j++);
}
// O(N*log10(N))
function log10(buf) {
  for (let i = 0; i < buf.length; i++) for (let j = 0; j < Math.log10(buf.length); j++);
}
// O(N^2)
function quadratic(buf) {
  for (let i = 0; i < buf.length; i++) for (let j = 0; j < buf.length; j++);
}
// Should be around 0.1, but its significantly depends on environment, GC, other processes that run in parallel. Which makes tests too flaky.
const MARGIN = (() => {
  const timings = [];
  for (let i = 0; i < 5; i++) {
    let ts = getTime();
    linearConst(1024);
    timings.push((getTime() - ts) / 1024);
  }
  const diff = Math.max(...stats(timings).difference.map((i) => Math.abs(i)));
  return Math.max(1, diff);
})();

console.log(`Time margin: ${MARGIN}`);

const SMALL_BUF = new Uint8Array(1024);
// Check that there is linear relation between input size and running time of callback
async function isLinear(callback, iters = 128) {
  // Warmup && trigger JIT
  for (let i = 0; i < 1024; i++) await callback(SMALL_BUF);
  // Measure difference between relative execution time (per byte)
  const timings = [];
  for (let i = 1; i < iters; i++) {
    const buf = RANDOM.subarray(0, 1024 * i);
    const time = await bench(() => callback(buf));
    timings.push(time / buf.length); // time per byte
  }
  // Median of differences. Should be close to zero for linear functions (+/- some noise).
  const medianDifference = stats(stats(timings.map((i) => i)).difference).median;
  console.log({ medianDifference });
  deepStrictEqual(
    medianDifference < MARGIN,
    true,
    `medianDifference(${medianDifference}) should be less than ${MARGIN}`
  );
}

// Verify that it correctly detects functions with quadratic complexity
should(
  'detect quadratic functions',
  retry(async () => {
    // 16 iters since quadratic is very slow
    console.log('Linear');
    await isLinear((buf) => linear(buf), 16);
    console.log('Linear const');
    await isLinear((buf) => linearConst(buf), 16);
    // Very close to linear, not much impact
    console.log('Log2');
    await isLinear((buf) => log2(buf), 16);
    console.log('Log10');
    await isLinear((buf) => log10(buf), 16);
    console.log('Quadratic');
    await rejects(() => isLinear((buf) => quadratic(buf), 16));
    // Function itself is linear if we look on password/salt only, but there is quadratic relation
    // between salt / pass length and iterations which makes function quadratic if we look at all inputs.
    // Correct function should have time complexity like:
    // C1*N + C2*M, where C1 and C2 is some constants, N and M is input
    // However this implementation has time complexity like:
    // (C1*N) * (C2*M) which is quadratic
    console.log('PBKDF2 with DOS support');
    await rejects(() => isLinear((buf) => pbkdf2DOS(sha256, buf, buf, buf.length), 16));
  })
);

function pbkdf2DOS(hash, password, salt, c) {
  const PBKDF_CNT = new Uint8Array(4);
  const dkLen = 32;
  const DK = new Uint8Array(dkLen);
  const outputLen = 32;
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += outputLen) {
    const Ti = DK.subarray(pos, pos + outputLen);
    createView(PBKDF_CNT).setInt32(0, ti, false);
    let u = hmac.create(hash, password).update(salt).update(PBKDF_CNT).digest();
    Ti.set(u.subarray(0, Ti.length));
    for (let ui = 1; ui < c; ui++) {
      u = hmac(hash, password, u);
      for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
    }
  }
  return DK;
}

should('DoS: pbkdfDOS returns correct result', () => {
  const password = new Uint8Array([1, 2, 3]);
  const salt = new Uint8Array([4, 5, 6]);
  deepStrictEqual(
    pbkdf2(sha256, password, salt, { dkLen: 32, c: 1024 }),
    pbkdf2DOS(sha256, password, salt, 1024)
  );
});

for (const h in HASHES) {
  const hash = HASHES[h];
  should(
    `DoS: ${h}`,
    retry(async () => {
      await isLinear((buf) => hash.fn(buf));
    })
  );
}

should(
  `DoS: pbkdf2`,
  retry(async () => {
    await isLinear((buf) => pbkdf2(sha256, buf, buf, { c: buf.length, dkLen: 32 }));
  })
);

should(
  `DoS: pbkdf2Async`,
  retry(async () => {
    await isLinear((buf) => pbkdf2Async(sha256, buf, buf, { c: buf.length, dkLen: 32 }));
  })
);

should(
  `DoS: hkdf`,
  retry(async () => {
    await isLinear((buf) => hkdf(sha256, buf, buf, buf, 32));
  })
);

should(
  `DoS: scrypt`,
  retry(async () => {
    await isLinear((buf) => scrypt(buf, buf, { N: 1024, r: buf.length / 1024, p: 2, dkLen: 64 }));
  })
);

should(
  `DoS: scryptAsync`,
  retry(async () => {
    await isLinear((buf) =>
      scryptAsync(buf, buf, { N: 1024, r: buf.length / 1024, p: 2, dkLen: 64 })
    );
  })
);

// takes ~20min
if (require.main === module) should.run();
