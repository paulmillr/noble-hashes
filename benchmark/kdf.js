import { compare, compareMatrix, mark, utils } from 'micro-bmark';
import crypto from 'node:crypto';
// Noble
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { hkdf } from '@noble/hashes/hkdf';
import { scrypt, scryptAsync } from '@noble/hashes/scrypt';
// Others

import stable256 from '@stablelib/sha256';
import { deriveKey as stablePBKDF2 } from '@stablelib/pbkdf2';
import {
  deriveKey as stableScrypt,
  deriveKeyNonBlocking as stableScryptAsync,
} from '@stablelib/scrypt';
import { HKDF as stableHKDF } from '@stablelib/hkdf';
import stable512 from '@stablelib/sha512';
import _scryptAsync from 'scrypt-async';
import scryptjs from 'scrypt-js';
import wasm from 'hash-wasm';
import { argon2id } from '@noble/hashes/argon2';

function scryptAsyncSync(iters) {
  let res = undefined; // workaround for bad scrypt api
  _scryptAsync(
    k_password,
    k_salt,
    { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' },
    (key) => {
      res = key;
    }
  );
  return res;
}

const [k_password, k_salt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
const KDF_ITERS = [
  // [10000, 2],
  // [1000, 2 ** 10],
  [10, 2 ** 14],
  [5, 2 ** 16],
  [5, 2 ** 18],
  // [1, 2 ** 21] // crashes for non-noble
];

const A_password = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
const A_salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

const KDF = {
  'pbkdf2(sha256)': {
    node: (iters) => crypto.pbkdf2Sync(k_password, k_salt, iters, 32, 'sha256'),
    webcrypto: async (iters) => {
      const key = await globalThis.crypto.subtle.importKey('raw', k_password, 'PBKDF2', false, [
        'deriveBits',
      ]);
      return await globalThis.crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: k_salt, iterations: iters },
        key,
        32 * 8
      );
    },
    webcrypto: async (iters) => {
      const key = await globalThis.crypto.subtle.importKey('raw', k_password, 'PBKDF2', false, [
        'deriveBits',
      ]);
      return await globalThis.crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-512', salt: k_salt, iterations: iters },
        key,
        64 * 8
      );
    },
    'hash-wasm': (iters) =>
      wasm.pbkdf2({
        password: 'password',
        salt: k_salt,
        iterations: iters,
        hashLength: 32,
        hashFunction: wasm.createSHA256(),
        outputType: 'binary',
      }),
    stablelib: (iters) => stablePBKDF2(stable256.SHA256, k_password, k_salt, iters, 32),
    noble: (iters) => pbkdf2(sha256, k_password, k_salt, { c: iters, dkLen: 32 }),
    'noble (async)': (iters) => pbkdf2Async(sha256, k_password, k_salt, { c: iters, dkLen: 32 }),
  },
  'pbkdf2(sha512)': {
    node: (iters) => crypto.pbkdf2Sync(k_password, k_salt, iters, 64, 'sha512'),
    'hash-wasm': (iters) =>
      wasm.pbkdf2({
        password: 'password',
        salt: k_salt,
        iterations: iters,
        hashLength: 64,
        hashFunction: wasm.createSHA512(),
        outputType: 'binary',
      }),
    stablelib: (iters) => stablePBKDF2(stable512.SHA512, k_password, k_salt, iters, 64),
    noble: (iters) => pbkdf2(sha512, k_password, k_salt, { c: iters, dkLen: 64 }),
    'noble (async)': (iters) => pbkdf2Async(sha512, k_password, k_salt, { c: iters, dkLen: 64 }),
  },
  'scrypt(r: 8, p: 1, n:': {
    node: (iters) =>
      crypto.scryptSync(k_password, k_salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }),
    'scrypt-async': (iters) => scryptAsyncSync(iters),
    'scrypt-js': (iters) => scryptjs.syncScrypt(k_password, k_salt, iters, 8, 1, 32),
    stablelib: (iters) => stableScrypt(k_password, k_salt, iters, 8, 1, 32),
    noble: (iters) => scrypt(k_password, k_salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
  'scrypt_async(r: 8, p: 1, n:': {
    node: (iters) =>
      new Promise((resolve) =>
        crypto.scrypt(k_password, k_salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }, resolve)
      ),
    'hash-wasm': async (iters) =>
      await wasm.scrypt({
        password: 'password',
        salt: k_salt,
        costFactor: iters,
        blockSize: 8,
        parallelism: 1,
        hashLength: 32,
        outputType: 'binary',
      }),
    // 'hash-wasm': (iters) =>
    'scrypt-async': (iters) =>
      new Promise((resolve) =>
        _scryptAsync(
          k_password,
          k_salt,
          { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' },
          resolve
        )
      ),
    'scrypt-js': (iters) => scryptjs.scrypt(k_password, k_salt, iters, 8, 1, 32),
    stablelib: (iters) => stableScryptAsync(k_password, k_salt, iters, 8, 1, 32),
    noble: (iters) => scryptAsync(k_password, k_salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
};

// const HKDF = {
//   'hkdf(sha256)': {
//     node: (len) => crypto.hkdfSync('sha256', k_password, k_salt, new Uint8Array(), len),
//     stable: (len) => new stableHKDF(stable256.SHA256, k_password, k_salt, undefined).expand(len),
//     noble: (len) => hkdf(sha256, k_salt, k_password, undefined, len),
//   },
//   // 'hkdf(sha512)': {
//   //   node: (len) => crypto.hkdfSync('sha512', password, salt, new Uint8Array(), len),
//   //   stable: (len) => new stableHKDF(stable512.SHA512, password, salt, undefined).expand(len),
//   //   noble: (len) => hkdf(sha512, salt, password, undefined, len),
//   // },
// };

const A_KDF = {
  argon2id: {
    'hash-wasm': (iters, mem) =>
      wasm.argon2id({
        password: A_password,
        salt: A_salt,
        iterations: iters,
        parallelism: 1,
        hashLength: 32,
        memorySize: mem,
        outputType: 'binary',
      }),
    noble: (iters, mem) => argon2id(A_password, A_salt, { t: iters, m: mem, p: 1, dkLen: 32 }),
  },
};

async function main() {
  await compareMatrix('hkdf(sha256)', [{'32B': 32, '64B': 64, '256B': 256}], {
    samples: 100_000,
    node: (len) => {
      return crypto.hkdfSync('sha256', k_password, k_salt, new Uint8Array(), len);
    },
    stable: (len) => new stableHKDF(stable256.SHA256, k_password, k_salt, undefined).expand(len),
    noble: (len) => hkdf(sha256, k_salt, k_password, undefined, len),
  });

  for (let [k, libs] of Object.entries(KDF)) {
    await compareMatrix(k, [{'2**14': 2 ** 14, '2**16': 2**16, '2**18': 2 ** 18}],
    libs);
  }

  await compareMatrix('argon2id', [
    {'i: 1': 1, 'i: 4': 4, 'i: 8': 8},
    {'256KB': 256, '64MB': 64 * 1024, '256MB': 256 * 1024}
  ], {
    samples: (iters, mem, lib) => mem > 10_000 ? 3 : 1500,
    'hash-wasm': (iters, mem) =>
      wasm.argon2id({
        password: A_password,
        salt: A_salt,
        iterations: iters,
        parallelism: 1,
        hashLength: 32,
        memorySize: mem,
        outputType: 'binary',
      }),
    noble: (iters, mem) => argon2id(A_password, A_salt, { t: iters, m: mem, p: 1, dkLen: 32 }),
  });
  // Log current RAM
  utils.logMem();
}

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
