import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { pbkdf2Async } from '../src/pbkdf2.ts';
import { scrypt, scryptAsync } from '../src/scrypt.ts';
import { sha256 } from '../src/sha2.ts';
import * as utils from '../src/utils.ts';

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
const KDFS = {
  Scrypt: (ms) => scryptAsync(PWD, SALT, { N: 2 ** 18, r: 8, p: 1, asyncTick: ms }),
  PBKDF2: (ms) => pbkdf2Async(sha256, PWD, SALT, { c: 2 ** 19, asyncTick: ms }),
};

describe('async', () => {
  for (let kdf in KDFS) {
    for (let ms of [10, 25, 50, 100]) {
      should(`${kdf} (${ms}ms)`, async () => {
        let w = new LoopWatcher();
        await KDFS[kdf](ms);
        const info = w.info(true);
        // console.log('\tKDF took', info);
        // we compare avg with exepcted+2ms to avoid flaky tests
        eql(info.avg < ms + 2, true, 'avg');
        eql(info.total > ms, true, 'total');
      });
    }
    should(`${kdf} parallel`, async () => {
      // Run 10 async job in parallel and verify that there is no corruption of internal state
      const exp = Uint8Array.from(await KDFS[kdf](10)); // Make sure that there is no way to change output
      const res = await Promise.all(Array.from({ length: 10 }, (i) => KDFS[kdf](1)));
      for (let val of res) eql(val, exp);
    });
  }

  should('scrypt progreessCallback', () => {
    let t = [];
    scrypt('', '', { N: 2 ** 18, r: 8, p: 1, onProgress: (per) => t.push(per) });
    // Should be called ~10k
    eql(t.length, 10083);
    // Should be exact numbers
    eql(
      t.slice(0, 5),
      [
        0.00009918212890625, 0.0001983642578125, 0.00029754638671875, 0.000396728515625,
        0.00049591064453125,
      ]
    );
    // Should end with 1
    eql(
      t.slice(-5),
      [0.9996566772460938, 0.999755859375, 0.9998550415039062, 0.9999542236328125, 1]
    );
  });

  should('scryptAsync progreessCallback', async () => {
    let t = [];
    await scryptAsync('', '', { N: 2 ** 18, r: 8, p: 1, onProgress: (per) => t.push(per) });
    // Should be called ~10k
    eql(t.length, 10083);
    // Should be exact numbers
    eql(
      t.slice(0, 5),
      [
        0.00009918212890625, 0.0001983642578125, 0.00029754638671875, 0.000396728515625,
        0.00049591064453125,
      ]
    );
    // Should end with 1
    eql(
      t.slice(-5),
      [0.9996566772460938, 0.999755859375, 0.9998550415039062, 0.9999542236328125, 1]
    );
  });
});

should.runWhen(import.meta.url);
