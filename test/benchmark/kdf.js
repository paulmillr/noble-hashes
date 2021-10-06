const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
// Noble
const { sha256 } = require('../../lib/sha256');
const { sha512 } = require('../../lib/sha512');
const { pbkdf2, pbkdf2Async } = require('../../lib/pbkdf2');
const { hkdf } = require('../../lib/hkdf');
const { scrypt, scryptAsync } = require('../../lib/scrypt');
// Others

const stable256 = require('@stablelib/sha256');
const { deriveKey: stablePBKDF2 } = require('@stablelib/pbkdf2');
const {
  deriveKey: stableScrypt,
  deriveKeyNonBlocking: stableScryptAsync,
} = require('@stablelib/scrypt');
const { HKDF: stableHKDF } = require('@stablelib/hkdf');
const stable512 = require('@stablelib/sha512');
const _scryptAsync = require('scrypt-async');
const { syncScrypt: scryptJsSync, scrypt: scryptJsAsync } = require('scrypt-js');

function scryptAsyncSync(iters) {
  let res = undefined; // workaround for bad scrypt api
  _scryptAsync(password, salt, { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' }, (key) => {
    res = key;
  });
  return res;
}

// buffer title, sample count, data
const buffers = {
  '32 B': [200000, new Uint8Array(32).fill(1)],
  '64 B': [200000, new Uint8Array(64).fill(1)],
  '1 KB': [50000, new Uint8Array(1024).fill(2)],
  '8 KB': [6250, new Uint8Array(1024 * 8).fill(3)],
  // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  '1 MB': [250, new Uint8Array(1024 * 1024).fill(4)],
};

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
    stable: (iters) => stablePBKDF2(stable256.SHA256, password, salt, iters, 32),
    noble: (iters) => pbkdf2(sha256, password, salt, { c: iters, dkLen: 32 }),
    nobleAsync: (iters) => pbkdf2Async(sha256, password, salt, { c: iters, dkLen: 32 }),
  },
  'PBKDF2-HMAC-SHA512': {
    node: (iters) => crypto.pbkdf2Sync(password, salt, iters, 64, 'sha512'),
    stable: (iters) => stablePBKDF2(stable512.SHA512, password, salt, iters, 64),
    noble: (iters) => pbkdf2(sha512, password, salt, { c: iters, dkLen: 64 }),
    nobleAsync: (iters) => pbkdf2Async(sha512, password, salt, { c: iters, dkLen: 64 }),
  },
  'Scrypt r: 8, p: 1, n:': {
    node: (iters) =>
      crypto.scryptSync(password, salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }),
    scryptAsync: (iters) => scryptAsyncSync(iters),
    scryptJs: (iters) => scryptJsSync(password, salt, iters, 8, 1, 32),
    stable: (iters) => stableScrypt(password, salt, iters, 8, 1, 32),
    noble: (iters) => scrypt(password, salt, { N: iters, r: 8, p: 1, dkLen: 32 }),
  },
  ScryptAsync: {
    node: (iters) =>
      new Promise((resolve) =>
        crypto.scrypt(password, salt, 32, { N: iters, r: 8, p: 1, maxmem: 1024 ** 4 }, resolve)
      ),
    scryptAsync: (iters) =>
      new Promise((resolve) =>
        _scryptAsync(
          password,
          salt,
          { N: iters, r: 8, p: 1, dkLen: 32, encoding: 'binary' },
          resolve
        )
      ),
    scryptJs: (iters) => scryptJsAsync(password, salt, iters, 8, 1, 32),
    stable: (iters) => stableScryptAsync(password, salt, iters, 8, 1, 32),
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

const main = () =>
  run(async () => {
    for (let [k, libs] of Object.entries(HKDF)) {
      console.log(`==== ${k} ====`);
      for (const [samples, len] of HKDF_EXPAND) {
        for (const [lib, fn] of Object.entries(libs))
          await mark(`${k} ${len} ${lib}`, samples, () => fn(len));
        console.log();
      }
    }
    for (let [k, libs] of Object.entries(KDF)) {
      console.log(`==== ${k} ====`);
      for (const [samples, iters] of KDF_ITERS) {
        for (const [lib, fn] of Object.entries(libs))
          await mark(`${k} ${iters} ${lib}`, samples, () => fn(iters));
        console.log();
      }
    }
    // Log current RAM
    bench.logMem();
  });

module.exports = { main };
if (require.main === module) main();
