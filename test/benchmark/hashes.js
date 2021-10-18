const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
// Noble
const { sha256 } = require('../../lib/sha256');
const { sha512, sha512_256, sha384 } = require('../../lib/sha512');
const { sha3_256, keccak_256 } = require('../../lib/sha3');
const { blake2s } = require('../../lib/blake2s');
const { blake2b } = require('../../lib/blake2b');
const { hmac } = require('../../lib/hmac');
const { ripemd160 } = require('../../lib/ripemd160');
// Others

const createHash = require('create-hash/browser');
const createHmac = require('create-hmac/browser');
const stable256 = require('@stablelib/sha256');
const stableHmac = require('@stablelib/hmac');
const fastsha256 = require('fast-sha256').hash;
const stable384 = require('@stablelib/sha384');
const stable512 = require('@stablelib/sha512');
const stable512_256 = require('@stablelib/sha512_256');
const stable3 = require('@stablelib/sha3');
const stableBlake2s = require('@stablelib/blake2s');
const stableBlake2b = require('@stablelib/blake2b');
const jssha3 = require('js-sha3');
const noble_ripemd160 = require('noble-ripemd160');


const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);

const HASHES = {
  SHA256: {
    node: (buf) => crypto.createHash('sha256').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha256').update(buf).digest(),
    stablelib: (buf) => stable256.hash(buf),
    'fast-sha256': (buf) => fastsha256.hash(buf),
    noble: (buf) => sha256(buf),
  },
  SHA384: {
    node: (buf) => crypto.createHash('sha384').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha384').update(buf).digest(),
    stablelib: (buf) => stable384.hash(buf),
    noble: (buf) => sha384(buf),
  },
  SHA512: {
    node: (buf) => crypto.createHash('sha512').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable512.hash(buf),
    noble: (buf) => sha512(buf),
  },
  'SHA512-256': {
    node: (buf) => crypto.createHash('sha512-256').update(buf).digest(),
    stablelib: (buf) => new stable512_256.SHA512_256().update(buf).digest(),
    noble: (buf) => sha512_256(buf),
  },
  'SHA3-256': {
    node: (buf) => crypto.createHash('sha3-256').update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    noble: (buf) => sha3_256(buf),
  },
  'keccak-256': {
    'js-sha3': (buf) => wrapBuf(jssha3.keccak_256.create().update(buf).arrayBuffer()),
    noble: (buf) => keccak_256(buf),
  },
  BLAKE2s: {
    node: (buf) => crypto.createHash('blake2s256').update(buf).digest(),
    stablelib: (buf) => new stableBlake2s.BLAKE2s().update(buf).digest(),
    noble: (buf) => blake2s(buf),
  },
  BLAKE2b: {
    node: (buf) => crypto.createHash('blake2b512').update(buf).digest(),
    stablelib: (buf) => new stableBlake2b.BLAKE2b().update(buf).digest(),
    noble: (buf) => blake2b(buf),
  },
  'HMAC-SHA256': {
    node: (buf) => crypto.createHmac('sha256', buf).update(buf).digest(),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    noble: (buf) => hmac(sha256, buf, buf),
  },
  RIPEMD160: {
    node: (buf) => crypto.createHash('ripemd160').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
    'noble-ripemd160': (buf) => new noble_ripemd160.RIPEMD160().update(buf).digest(),
    noble: (buf) => ripemd160(buf),
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [200000, new Uint8Array(32).fill(1)],
  // '64B': [200000, new Uint8Array(64).fill(1)],
  // '1KB': [50000, new Uint8Array(1024).fill(2)],
  // '8KB': [6250, new Uint8Array(1024 * 8).fill(3)],
  // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  // '1MB': [250, new Uint8Array(1024 * 1024).fill(4)],
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
