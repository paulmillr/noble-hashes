import * as wasm from 'hash-wasm';
import compare from 'micro-bmark/compare.js';
import { argon2id } from '../../argon2.js';

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
  // basic: node argon.js
  // full: MBENCH_DIMS='algorithm,iters,memory,library' node argon.js
  await compare(
    'Argon',
    {
      iters: { 1: 1, 4: 4, 8: 8 },
      memory: { '256KB': 256, '64MB': 64 * 1024, '256MB': 256 * 1024, '1GB': 1 * 1024 * 1024 },
    },
    KDF,
    {
      libDims: ['algorithm', 'library'],
      defaults: { library: 'noble', memory: '256KB' },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  console.log(1);
  main();
}
