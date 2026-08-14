import compare from '@paulmillr/jsbt/benchmark-compare.js';
import * as wasm from 'hash-wasm';
import { argon2id } from '../../src/argon2.ts';

const password = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
const salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

const KDF = {
  argon2id: {
    'hash-wasm': (iters, mem) =>
      wasm.argon2id({
        password,
        salt,
        iterations: iters,
        parallelism: 1,
        hashLength: 32,
        memorySize: mem,
        outputType: 'binary',
      }),
    noble: (iters, mem) => argon2id(password, salt, { t: iters, m: mem, p: 1, dkLen: 32 }),
  },
};

async function main() {
  // Usage:
  //   node argon.ts
  //   JSBT_ORDER='algorithm,iters,memory,library' node argon.ts
  await compare('Argon', KDF, {
    levels: ['algorithm', 'library'],
    inputs: {
      iters: [3],
      memory: { '64MB': 64 * 1024, '128MB': 128 * 1024, '256MB': 256 * 1024, '1GB': 1024 * 1024 },
    },
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
