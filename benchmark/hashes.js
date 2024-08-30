import { mark, utils } from 'micro-bmark';
// Noble
import { sha256, sha384, sha512 } from '@noble/hashes/sha2';
// import { sha224, sha512_256, sha512_384 } from '@noble/hashes/sha2';
import { sha3_256 } from '@noble/hashes/sha3';
import { k12, m14 } from '@noble/hashes/sha3-addons';
import { blake2b } from '@noble/hashes/blake2b';
import { blake2s } from '@noble/hashes/blake2s';
import { blake3 } from '@noble/hashes/blake3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';

// Others
import { createHash as crypto_createHash, createHmac as crypto_createHmac } from 'node:crypto';
import createHash from 'create-hash/browser.js';
import createHmac from 'create-hmac/browser.js';
import stable256 from '@stablelib/sha256';
import stableHmac from '@stablelib/hmac';
import { hash as fastsha256 } from 'fast-sha256';
import stable2_384 from '@stablelib/sha384';
import stable2_512 from '@stablelib/sha512';
import stable3 from '@stablelib/sha3';
import stableb2b from '@stablelib/blake2b';
import stableb2s from '@stablelib/blake2s';
import jssha3 from 'js-sha3';
import nobleUnrolled from 'unrolled-nbl-hashes-sha3';
import { SHA3 as _SHA3 } from 'sha3';
import wasm_ from 'hash-wasm';

const wasm = {};
const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);
const ONLY_NOBLE = process.argv[2] === 'noble';

const HASHES = {
  SHA256: {
    node: (buf) => crypto_createHash('sha256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha256.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha256').update(buf).digest(),
    stablelib: (buf) => stable256.hash(buf),
    'fast-sha256': (buf) => fastsha256.hash(buf),
    noble: (buf) => sha256(buf),
  },
  SHA384: {
    node: (buf) => crypto_createHash('sha384').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha384').update(buf).digest(),
    stablelib: (buf) => stable2_384.hash(buf),
    noble: (buf) => sha384(buf),
  },
  SHA512: {
    node: (buf) => crypto_createHash('sha512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha512.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable2_512.hash(buf),
    noble: (buf) => sha512(buf),
  },
  'SHA3-256, keccak256, shake256': {
    node: (buf) => crypto_createHash('sha3-256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha3.init().update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    sha3: (buf) => new _SHA3(256).update(Buffer.from(buf)).digest(),
    'noble (unrolled)': (buf) => nobleUnrolled.sha3_256(buf),
    noble: (buf) => sha3_256(buf),
  },
  Kangaroo12: { noble: (buf) => k12(buf) },
  Marsupilami14: { noble: (buf) => m14(buf) },
  BLAKE2b: {
    node: (buf) => crypto_createHash('blake2b512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2b.init().update(buf).digest(),
    stablelib: (buf) => new stableb2b.BLAKE2b().update(buf).digest(),
    noble: (buf) => blake2b(buf),
  },
  BLAKE2s: {
    node: (buf) => crypto_createHash('blake2s256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2s.init().update(buf).digest(),
    stablelib: (buf) => new stableb2s.BLAKE2s().update(buf).digest(),
    noble: (buf) => blake2s(buf),
  },
  BLAKE3: {
    'hash-wasm': (buf) => wasm.blake3.init().update(buf).digest(),
    noble: (buf) => blake3(buf),
  },
  RIPEMD160: {
    node: (buf) => crypto_createHash('ripemd160').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
    noble: (buf) => ripemd160(buf),
  },
  'HMAC-SHA256': {
    node: (buf) => crypto_createHmac('sha256', buf).update(buf).digest(),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    noble: (buf) => hmac(sha256, buf, buf),
  },
};

// buffer title, sample count, data
const buffers = {
  '32B': [500000, new Uint8Array(32).fill(1)],
  // '64B': [200000, new Uint8Array(64).fill(1)],
  // '1KB': [50000, new Uint8Array(1024).fill(2)],
  // '8KB': [6250, new Uint8Array(1024 * 8).fill(3)],
  // // Slow, but 100 doesn't show difference, probably opt doesn't happen or something
  // '1MB': [250, new Uint8Array(1024 * 1024).fill(4)],
};

async function main() {
  if (!ONLY_NOBLE) {
    wasm.sha256 = await wasm_.createSHA256();
    wasm.sha512 = await wasm_.createSHA512();
    wasm.sha3 = await wasm_.createSHA3();
    wasm.blake2b = await wasm_.createBLAKE2b();
    wasm.blake2s = await wasm_.createBLAKE2s();
    wasm.blake3 = await wasm_.createBLAKE3();
  }
  for (let [k, libs] of Object.entries(HASHES)) {
    if (!ONLY_NOBLE) console.log(`==== ${k} ====`);
    for (const [size, [samples, buf]] of Object.entries(buffers)) {
      for (const [lib, fn] of Object.entries(libs)) {
        if (ONLY_NOBLE && lib !== 'noble') continue;
        // if (lib !== 'noble') continue;
        let title = `${k} ${size}`;
        if (!ONLY_NOBLE) title += ` ${lib}`;
        await mark(title, samples, () => fn(buf));
      }
      if (!ONLY_NOBLE) console.log();
    }
  }
  // Log current RAM
  utils.logMem();
}


// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
