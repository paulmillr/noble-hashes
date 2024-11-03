import bench from 'micro-bmark';
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
const { run, mark } = bench; // or bench.mark

function scryptAsyncSync(iters) {
  let res = undefined; // workaround for bad scrypt api
  _scryptAsync(password, salt, { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' }, (key) => {
    res = key;
  });
  return res;
}

const ONLY_NOBLE = process.argv[2] === 'noble';
const [password, salt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
const KDF_ITERS = [
  // [10000, 2],
  // [1000, 2 ** 10],
  [10, 2 ** 14],
  [5, 2 ** 16],
  [5, 2 ** 18],
  // [1, 2 ** 21] // crashes for non-noble
];

const KDF = {
  'PBKDF2-HMAC-SHA256': {
    node: (iters) => crypto.pbkdf2Sync(password, salt, iters, 32, 'sha256'),
    'hash-wasm': (iters) =>
      wasm.pbkdf2({
        password: 'password',
        salt,
        iterations: iters,
        hashLength: 32,
        hashFunction: wasm.createSHA256(),
        outputType: 'binary',
      }),
    stablelib: (iters) => stablePBKDF2(stable256.SHA256, password, salt, iters, 32),
    noble: (iters) => pbkdf2(sha256, password, salt, { c: iters, dkLen: 32 }),
    'noble (async)': (iters) => pbkdf2Async(sha256, password, salt, { c: iters, dkLen: 32 }),
    webcrypto: async (iters) => {
      const key = await globalThis.crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
      return await globalThis.crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iters }, key, 32 * 8);
    },
  },
  'PBKDF2-HMAC-SHA512': {
    node: (iters) => crypto.pbkdf2Sync(password, salt, iters, 64, 'sha512'),
    'hash-wasm': (iters) =>
      wasm.pbkdf2({
        password: 'password',
        salt,
        iterations: iters,
        hashLength: 64,
        hashFunction: wasm.createSHA512(),
        outputType: 'binary',
      }),
    stablelib: (iters) => stablePBKDF2(stable512.SHA512, password, salt, iters, 64),
    noble: (iters) => pbkdf2(sha512, password, salt, { c: iters, dkLen: 64 }),
    'noble (async)': (iters) => pbkdf2Async(sha512, password, salt, { c: iters, dkLen: 64 }),
    webcrypto: async (iters) => {
      const key = await globalThis.crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
      return await globalThis.crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512', salt: salt, iterations: iters }, key, 64 * 8);
    },
  },
  'Scrypt r: 8, p: 1, n:': {
    node: (iters) =>
      crypto.scryptSync(password, salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }),
    'scrypt-async': (iters) => scryptAsyncSync(iters),
    'scrypt-js': (iters) => scryptjs.syncScrypt(password, salt, iters, 8, 1, 32),
    stablelib: (iters) => stableScrypt(password, salt, iters, 8, 1, 32),
    noble: (iters) => scrypt(password, salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
  'Scrypt Async r: 8, p: 1, n:': {
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
    // 'hash-wasm': (iters) =>
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

const HKDF_EXPAND = [
  [100000, 32],
  [100000, 64],
  [25000, 256],
];
const HKDF = {
  'HKDF-SHA256': {
    node: (len) => crypto.hkdfSync('sha256', password, salt, new Uint8Array(), len),
    stable: (len) => new stableHKDF(stable256.SHA256, password, salt, undefined).expand(len),
    noble: (len) => hkdf(sha256, salt, password, undefined, len),
  },
  // 'HKDF-SHA512': {
  //   node: (len) => crypto.hkdfSync('sha512', password, salt, new Uint8Array(), len),
  //   stable: (len) => new stableHKDF(stable512.SHA512, password, salt, undefined).expand(len),
  //   noble: (len) => hkdf(sha512, salt, password, undefined, len),
  // },
};

export const main = () =>
  run(async () => {
    for (let [k, libs] of Object.entries(HKDF)) {
      if (!ONLY_NOBLE) console.log(`==== ${k} ====`);
      for (const [samples, len] of HKDF_EXPAND) {
        for (const [lib, fn] of Object.entries(libs)) {
          if (ONLY_NOBLE && lib !== 'noble') continue;
          let title = `${k} ${len}`;
          if (!ONLY_NOBLE) title += ` ${lib}`;
          await mark(title, samples, () => fn(len));
        }
        if (!ONLY_NOBLE) console.log();
      }
    }
    for (let [k, libs] of Object.entries(KDF)) {
      if (!ONLY_NOBLE) console.log(`==== ${k} ====`);
      for (const [samples, iters] of KDF_ITERS) {
        for (const [lib, fn] of Object.entries(libs)) {
          if (ONLY_NOBLE && lib !== 'noble') continue;
          let title = `${k} ${iters}`;
          if (!ONLY_NOBLE) title += ` ${lib}`;
          await mark(title, samples, () => fn(iters));
        }
        if (!ONLY_NOBLE) console.log();
      }
    }
    // Log current RAM
    bench.utils.logMem();
  });

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
