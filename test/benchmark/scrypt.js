import compare from 'micro-bmark/compare.js';
import crypto from 'node:crypto';
// Noble
import { scrypt, scryptAsync } from '../../scrypt.js';
// Others
import {
  deriveKey as stableScrypt,
  deriveKeyNonBlocking as stableScryptAsync,
} from '@stablelib/scrypt';
import wasm from 'hash-wasm';
import _scryptAsync from 'scrypt-async';
import scryptjs from 'scrypt-js';

function scryptAsyncSync(iters) {
  let res = undefined; // workaround for bad scrypt api
  _scryptAsync(password, salt, { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' }, (key) => {
    res = key;
  });
  return res;
}

const [password, salt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];

const SCRYPT = {
  sync: {
    node: (iters) =>
      crypto.scryptSync(password, salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }),
    'scrypt-async': (iters) => scryptAsyncSync(iters),
    'scrypt-js': (iters) => scryptjs.syncScrypt(password, salt, iters, 8, 1, 32),
    stablelib: (iters) => stableScrypt(password, salt, iters, 8, 1, 32),
    noble: (iters) => scrypt(password, salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
  async: {
    node: (iters) =>
      new Promise((resolve) =>
        crypto.scrypt(password, salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }, resolve)
      ),
    'hash-wasm': async (iters) =>
      await wasm.scrypt({
        password: 'password',
        salt,
        costFactor: iters,
        blockSize: 8,
        parallelism: 1,
        hashLength: 32,
        outputType: 'binary',
      }),
    'scrypt-async': (iters) =>
      new Promise((resolve) =>
        _scryptAsync(
          password,
          salt,
          { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' },
          resolve
        )
      ),
    'scrypt-js': (iters) => scryptjs.scrypt(password, salt, iters, 8, 1, 32),
    stablelib: (iters) => stableScryptAsync(password, salt, iters, 8, 1, 32),
    noble: (iters) => scryptAsync(password, salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
};

async function main() {
  // basic: node scrypt.js
  // full: MBENCH_DIMS='p,r,iters,sync,library' node scrypt.js
  await compare(
    'Scrypt',
    {
      iters: {
        2: 2,
        '2^10': 2 ** 10,
        '2^14': 2 ** 14,
        '2^16': 2 ** 16,
        '2^18': 2 ** 18,
      },
      r: { 8: 8, 4: 4, 1: 1 },
      p: { 1: 1, 2: 2, 4: 4 },
    },
    SCRYPT,
    {
      libDims: ['sync', 'library'],
      defaults: { library: 'noble', r: 8, p: 1 },
      samples: (iters) => {
        if (iters <= 2) return 10_000;
        if (iters <= 2 ** 10) return 1_000;
        if (iters <= 2 ** 14) return 10;
        return 5;
      },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
