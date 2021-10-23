const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
// Noble
const { sha256 } = require('../../lib/sha256');
const { sha384, sha512 } = require('../../lib/sha512');
const { sha3_256 } = require('../../lib/sha3');
const { k12, m14 } = require('../../lib/sha3-addons');
const { blake2b } = require('../../lib/blake2b');
const { blake2s } = require('../../lib/blake2s');
const { blake3 } = require('../../lib/blake3');
const { ripemd160 } = require('../../lib/ripemd160');
const { hmac } = require('../../lib/hmac');

// Others
const createHash = require('create-hash/browser');
const createHmac = require('create-hmac/browser');
const stable256 = require('@stablelib/sha256');
const stableHmac = require('@stablelib/hmac');
const fastsha256 = require('fast-sha256').hash;
const stable2_384 = require('@stablelib/sha384');
const stable2_512 = require('@stablelib/sha512');
const stable3 = require('@stablelib/sha3');
const stableb2b = require('@stablelib/blake2b');
const stableb2s = require('@stablelib/blake2s');
const jssha3 = require('js-sha3');

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
    stablelib: (buf) => stable2_384.hash(buf),
    noble: (buf) => sha384(buf),
  },
  SHA512: {
    node: (buf) => crypto.createHash('sha512').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable2_512.hash(buf),
    noble: (buf) => sha512(buf),
  },
  'SHA3-256, keccak256, shake256': {
    node: (buf) => crypto.createHash('sha3-256').update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    noble: (buf) => sha3_256(buf),
  },
  Kangaroo12: { noble: (buf) => k12(buf) },
  Marsupilami14: { noble: (buf) => m14(buf) },
  BLAKE2b: {
    node: (buf) => crypto.createHash('blake2b512').update(buf).digest(),
    stablelib: (buf) => new stableb2b.BLAKE2b().update(buf).digest(),
    noble: (buf) => blake2b(buf),
  },
  BLAKE2s: {
    node: (buf) => crypto.createHash('blake2s256').update(buf).digest(),
    stablelib: (buf) => new stableb2s.BLAKE2s().update(buf).digest(),
    noble: (buf) => blake2s(buf),
  },
  BLAKE3: {
    noble: (buf) => blake3(buf),
  },
  RIPEMD160: {
    node: (buf) => crypto.createHash('ripemd160').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
    noble: (buf) => ripemd160(buf),
  },
  'HMAC-SHA256': {
    node: (buf) => crypto.createHmac('sha256', buf).update(buf).digest(),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    noble: (buf) => hmac(sha256, buf, buf),
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
