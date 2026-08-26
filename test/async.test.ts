import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { pathToFileURL } from 'node:url';
import * as utils from '../src/utils.ts';
import { PLATFORMS } from './platform.ts';

// Collect statistic about block of event loop by sync code
class LoopWatcher {
  start = Date.now();
  done = false;
  max = 0;
  n = 0;
  sum = 0;
  constructor() {
    (async () => {
      let ts = Date.now();
      for (;;) {
        if (this.done) break;
        const diff = Date.now() - ts;
        this.max = Math.max(this.max, diff);
        this.sum += diff;
        this.n++;
        ts = Date.now();
        await utils.nextTick();
      }
    })();
  }
  info(stop) {
    if (stop) this.end();
    // Unfortunately there is going on (GC, JIT, etc), so we cannot force limits on maximum counter (will cause flaky tests)
    return { avg: this.sum / this.n, max: this.max, total: Date.now() - this.start };
  }
  end() {
    this.done = true;
    return this;
  }
}

const PWD = new Uint8Array([1, 2, 3]);
const SALT = new Uint8Array([4, 5, 6]);
const BT = { describe, it };
const DEFAULT = PLATFORMS.noble || Object.values(PLATFORMS)[0];
const DEFAULT_PROGRESS = {
  scrypt: DEFAULT.scrypt,
  scryptAsync: DEFAULT.scryptAsync,
};

export function test(
  variant = 'noble',
  { argon2idAsync, sha256, scrypt, scryptAsync, pbkdf2Async } = DEFAULT,
  { describe, it } = BT,
  PROGRESS = DEFAULT_PROGRESS
) {
  const KDFS = {
    Scrypt: (ms) => scryptAsync(PWD, SALT, { N: 2 ** 18, r: 8, p: 1, asyncTick: ms }),
    // The iteration count must make the whole run take longer than `asyncTick`
    // (checkTiming asserts `total > ms`), so it scales with the tick size.
    PBKDF2: (ms) =>
      pbkdf2Async(sha256, PWD, SALT, {
        c: ms >= 100 ? 2 ** 18 : ms >= 50 ? 2 ** 17 : 2 ** 16,
        asyncTick: ms,
      }),
  };
  const PARALLEL_KDFS = {
    Scrypt: (ms) => scryptAsync(PWD, SALT, { N: 2 ** 15, r: 8, p: 1, asyncTick: ms }),
    PBKDF2: KDFS.PBKDF2,
  };
  const checkTiming = async (fn, ms) => {
    let w = new LoopWatcher();
    try {
      await fn(ms);
      const info = w.info(true);
      // console.log('\tKDF took', info);
      // The interval includes both our synchronous work and host scheduling delay. Under parallel
      // test workers, the latter can exceed a timer tick even when the KDF yields on time.
      const schedulingJitter = Math.max(10, ms / 4);
      eql(info.avg < ms + schedulingJitter, true, 'avg');
      eql(info.total > ms, true, 'total');
    } finally {
      w.end();
    }
  };
  const checkParallel = async (kdf) => {
    // Run 10 async jobs in parallel and verify that there is no corruption of internal state.
    const fn = PARALLEL_KDFS[kdf];
    const exp = Uint8Array.from(await fn(10)); // Make sure that there is no way to change output
    const res = await Promise.all(Array.from({ length: 10 }, () => fn(1)));
    for (let val of res) eql(val, exp);
  };
  const checkScryptProgress = async (fn) => {
    let t = [];
    await fn('', '', {
      N: 2 ** 18,
      r: 8,
      p: 1,
      onProgress: (per) => t.push(per),
    });
    eql(t.length > 1, true, 'progress callback count');
    eql(t.at(-1), 1, 'final progress');
    for (let i = 0; i < t.length; i++) {
      eql(t[i] > 0 && t[i] <= 1, true, `progress range at ${i}`);
      if (i) eql(t[i] > t[i - 1], true, `progress monotonicity at ${i}`);
    }
  };
  const checkHostYield = async (name, fn) => {
    let timerFired = false;
    const timer = new Promise<void>((resolve) =>
      setTimeout(() => {
        timerFired = true;
        resolve();
      }, 0)
    );
    await fn();
    const firedDuringKdf = timerFired;
    await timer; // Do not leave a pending timer behind when the assertion fails.
    eql(firedDuringKdf, true, `${name} did not yield to the host event loop`);
  };

  describe(`async (${variant})`, () => {
    it.serial('Scrypt timing, parallel, progress', async () => {
      for (let ms of [10, 25, 50, 100]) await checkTiming(KDFS.Scrypt, ms);
      await checkParallel('Scrypt');
      await checkScryptProgress(PROGRESS.scrypt);
      await checkScryptProgress(PROGRESS.scryptAsync);
    });

    for (let ms of [10, 25, 50, 100]) {
      it.serial(`PBKDF2 (${ms}ms)`, async () => {
        await checkTiming(KDFS.PBKDF2, ms);
      });
    }
    it.serial('PBKDF2 parallel', async () => {
      await checkParallel('PBKDF2');
    });
    it.serial('KDFs yield to timers', async () => {
      await checkHostYield('PBKDF2', () =>
        pbkdf2Async(sha256, PWD, SALT, { c: 3, dkLen: 32, asyncTick: 0 })
      );
      await checkHostYield('scrypt', () =>
        scryptAsync(PWD, SALT, { N: 16, r: 1, p: 1, dkLen: 32, asyncTick: 0 })
      );
      if (argon2idAsync)
        await checkHostYield('Argon2', () =>
          argon2idAsync(PWD, 'salt1234', { t: 1, m: 8, p: 1, dkLen: 32, asyncTick: 0 })
        );
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) test();
it.runWhen(import.meta.url);
