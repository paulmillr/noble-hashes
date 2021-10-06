const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
// Noble
const { sha256 } = require('../../lib/sha256');
const { sha512 } = require('../../lib/sha512');
const { sha3_256 } = require('../../lib/sha3');
const { blake2s } = require('../../lib/blake2s');
const { blake2b } = require('../../lib/blake2b');
const { hmac } = require('../../lib/hmac');
const { ripemd160 } = require('../../lib/ripemd160');
// Others

const stable256 = require('@stablelib/sha256');
const stableHmac = require('@stablelib/hmac');
const fastsha256 = require('fast-sha256').hash;
const stable512 = require('@stablelib/sha512');
const stable3 = require('@stablelib/sha3');
const stableBlake2s = require('@stablelib/blake2s');
const stableBlake2b = require('@stablelib/blake2b');
const jssha3 = require('js-sha3');
const noble_ripemd160 = require('noble-ripemd160');

const HASHES = {
  SHA256: {
    node: (buf) => crypto.createHash('sha256').update(buf).digest(),
    stable: (buf) => stable256.hash(buf),
    fast: (buf) => fastsha256.hash(buf),
    noble: (buf) => sha256(buf),
  },
  SHA512: {
    node: (buf) => crypto.createHash('sha512').update(buf).digest(),
    stable: (buf) => stable512.hash(buf),
    noble: (buf) => sha512(buf),
  },
  SHA3: {
    node: (buf) => crypto.createHash('sha3-256').update(buf).digest(),
    stable: (buf) => new stable3.SHA3256().update(buf).digest(),
    jssha: (buf) => jssha3.sha3_256.create().update(buf).digest(),
    noble: (buf) => sha3_256(buf),
  },
  BLAKE2s: {
    node: (buf) => crypto.createHash('blake2s256').update(buf).digest(),
    stable: (buf) => new stableBlake2s.BLAKE2s().update(buf).digest(),
    noble: (buf) => blake2s(buf),
  },
  BLAKE2b: {
    node: (buf) => crypto.createHash('blake2b512').update(buf).digest(),
    stable: (buf) => new stableBlake2b.BLAKE2b().update(buf).digest(),
    noble: (buf) => blake2b(buf),
  },
  'HMAC-SHA256': {
    node: (buf) => crypto.createHmac('sha256', buf).update(buf).digest(),
    stable: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    noble: (buf) => hmac(sha256, buf, buf),
  },
  RIPEMD160: {
    node: (buf) => crypto.createHash('ripemd160').update(buf).digest(),
    'noble-ripemd160': (buf) => new noble_ripemd160.RIPEMD160().update(buf).digest(),
    noble: (buf) => ripemd160(buf),
  },
};

// buffer title, sample count, data
const buffers = {
  '32 B': [200000, new Uint8Array(32).fill(1)],
  // '64 B': [200000, new Uint8Array(64).fill(1)],
  // '1 KB': [50000, new Uint8Array(1024).fill(2)],
  // '8 KB': [6250, new Uint8Array(1024 * 8).fill(3)],
  // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  // '1 MB': [250, new Uint8Array(1024 * 1024).fill(4)],
};

const main = () =>
  run(async () => {
    for (let [k, libs] of Object.entries(HASHES)) {
      console.log(`==== ${k} ====`);
      for (const [size, [samples, buf]] of Object.entries(buffers)) {
        for (const [lib, fn] of Object.entries(libs)) {
          // if (lib !== 'noble') continue;
          await mark(`${k} ${size} ${lib}`, samples, () => fn(buf));
        }
        console.log();
      }
    }
    // Log current RAM
    bench.logMem();
  });

module.exports = { main };
if (require.main === module) main();
