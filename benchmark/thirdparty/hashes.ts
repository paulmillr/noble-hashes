import compare from '@paulmillr/jsbt/benchmark-compare.js';
import { blake256, blake512 } from '../../src/blake1.ts';
import { blake2b, blake2s } from '../../src/blake2.ts';
import { blake3 } from '../../src/blake3.ts';
import { hmac } from '../../src/hmac.ts';
import { ripemd160 } from '../../src/legacy.ts';
import { sha256, sha512 } from '../../src/sha2.ts';
import { kt128 } from '../../src/sha3-addons.ts';
import { sha3_256 } from '../../src/sha3.ts';

// Others
import stableb2b from '@stablelib/blake2b';
import stableb2s from '@stablelib/blake2s';
import { HKDF as stableHKDF } from '@stablelib/hkdf';
import stableHmac from '@stablelib/hmac';
import stable256 from '@stablelib/sha256';
import stable3 from '@stablelib/sha3';
import { default as stable2_512, default as stable512 } from '@stablelib/sha512';
import { blake3 as awasmJs, ripemd160 as awasmRipemd160Js } from '@awasm/noble/js.js';
import { blake3 as awasmWasm } from '@awasm/noble/wasm.js';
import { blake3 as awasmWasmThreads } from '@awasm/noble/wasm_threads.js';
import _blakehash from 'blake-hash/js.js';
import createHash from 'create-hash/browser.js';
import createHmac from 'create-hmac/browser.js';
import { hash as fastsha256 } from 'fast-sha256';
import wasm_ from 'hash-wasm';
import jssha3 from 'js-sha3';
import {
  createHash as crypto_createHash,
  createHmac as crypto_createHmac,
  hkdfSync,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SHA3 as _SHA3 } from 'sha3';
import { hkdf } from '../../src/hkdf.ts';

// blake3-bao exposes a single stateful module. Load it into two separate
// closures so the JS and WASM SIMD implementations can be benchmarked together.
const BLAKE3_BAO_CODE = readFileSync(
  new URL('./node_modules/blake3-bao/blake3.js', import.meta.url),
  'utf8'
);
const loadBlake3Bao = () => {
  const exports = {};
  // eslint-disable-next-line no-new-func
  new Function('exports', BLAKE3_BAO_CODE)(exports);
  return exports;
};
const blake3BaoJs = loadBlake3Bao();
const blake3BaoWasm = loadBlake3Bao();

const wasm = {};
const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);

const blake_hash = (name) => {
  return (buf) => {
    const h = _blakehash(name);
    h.update(Buffer.from(buf));
    return Uint8Array.from(h.digest());
  };
};

// benchmark-compare discovers one shared library order across every algorithm.
// Fill in unavailable implementations with undefined to keep node and webcrypto last.
const orderLibraries = (hashes) => {
  const last = new Set(['node', 'webcrypto']);
  const libraries = new Set();
  for (const implementations of Object.values(hashes)) {
    for (const library of Object.keys(implementations)) {
      if (!last.has(library)) libraries.add(library);
    }
  }
  for (const library of last) libraries.add(library);
  return Object.fromEntries(
    Object.entries(hashes).map(([algorithm, implementations]) => [
      algorithm,
      Object.fromEntries(Array.from(libraries, (library) => [library, implementations[library]])),
    ])
  );
};

const HASHES = orderLibraries({
  sha256: {
    noble: (buf) => sha256(buf),
    'hash-wasm': (buf) => wasm.sha256.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha256').update(buf).digest(),
    stablelib: (buf) => stable256.hash(buf),
    'fast-sha256': (buf) => fastsha256.hash(buf),
    node: (buf) => crypto_createHash('sha256').update(buf).digest(),
    webcrypto: (buf) => globalThis.crypto.subtle.digest('SHA-256', buf),
  },
  sha512: {
    noble: (buf) => sha512(buf),
    'hash-wasm': (buf) => wasm.sha512.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable2_512.hash(buf),
    node: (buf) => crypto_createHash('sha512').update(buf).digest(),
    webcrypto: (buf) => globalThis.crypto.subtle.digest('SHA-512', buf),
  },
  sha3_256: {
    noble: (buf) => sha3_256(buf),
    'hash-wasm': (buf) => wasm.sha3.init().update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    sha3: (buf) => new _SHA3(256).update(Buffer.from(buf)).digest(),
    node: (buf) => crypto_createHash('sha3-256').update(buf).digest(),
  },
  kt128: {
    noble: (buf) => kt128(buf),
  },
  blake1_256: {
    noble: blake256,
    'blake-hash': blake_hash('blake256'),
  },
  blake1_512: {
    noble: blake512,
    'blake-hash': blake_hash('blake512'),
  },
  blake2b: {
    noble: (buf) => blake2b(buf),
    'hash-wasm': (buf) => wasm.blake2b.init().update(buf).digest(),
    stablelib: (buf) => new stableb2b.BLAKE2b().update(buf).digest(),
    node: (buf) => crypto_createHash('blake2b512').update(buf).digest(),
  },
  blake2s: {
    noble: (buf) => blake2s(buf),
    'hash-wasm': (buf) => wasm.blake2s.init().update(buf).digest(),
    stablelib: (buf) => new stableb2s.BLAKE2s().update(buf).digest(),
    node: (buf) => crypto_createHash('blake2s256').update(buf).digest(),
  },
  blake3: {
    noble: (buf) => blake3(buf),
    'hash-wasm': (buf) => wasm.blake3.init().update(buf).digest(),
    'blake3-bao-js': (buf) => blake3BaoJs.hash(buf),
    'blake3-bao-wasm': (buf) => blake3BaoWasm.hash(buf),
    'awasm-js': (buf) => awasmJs(buf),
    'awasm-wasm': (buf) => awasmWasm(buf),
    'awasm-wasm-threads': (buf) => awasmWasmThreads(buf),
  },
  ripemd160: {
    noble: (buf) => ripemd160(buf),
    'awasm-js': (buf) => awasmRipemd160Js(buf),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
    node: (buf) => crypto_createHash('ripemd160').update(buf).digest(),
  },
  hmac_sha256: {
    noble: (buf) => hmac(sha256, buf, buf),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
    node: (buf) => crypto_createHmac('sha256', buf).update(buf).digest(),
    webcrypto: async (buf) => {
      const key = await globalThis.crypto.subtle.importKey(
        'raw',
        buf,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      return await globalThis.crypto.subtle.sign('HMAC', key, buf);
    },
  },
});

async function main() {
  wasm.sha256 = await wasm_.createSHA256();
  wasm.sha512 = await wasm_.createSHA512();
  wasm.sha3 = await wasm_.createSHA3();
  wasm.blake2b = await wasm_.createBLAKE2b();
  wasm.blake2s = await wasm_.createBLAKE2s();
  wasm.blake3 = await wasm_.createBLAKE3();
  await blake3BaoWasm.initSimd();
  // Usage:
  //   node hashes.ts
  //   FILTER='blake3' node hashes.ts
  //   FILTER='library=awasm,noble;algorithm=blake3' node hashes.ts
  await compare('Hashes', HASHES, {
    levels: ['algorithm', 'library'],
    sizes: ['32B', '10MB'],
  });

  await main_hkdf();
}

async function main_hkdf() {
  // HKDF examples:
  //   FILTER='HKDF-SHA256' node hashes.ts
  const [hkpassword, hksalt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
  const HKDF = {
    'HKDF-SHA256': {
      stable: (len) => new stableHKDF(stable256.SHA256, hkpassword, hksalt, undefined).expand(len),
      noble: (len) => hkdf(sha256, hksalt, hkpassword, undefined, len),
      node: (len) => hkdfSync('sha256', hkpassword, hksalt, Uint8Array.of(), len),
    },
    'HKDF-SHA512': {
      stable: (len) => new stableHKDF(stable512.SHA512, hkpassword, hksalt, undefined).expand(len),
      noble: (len) => hkdf(sha512, hksalt, hkpassword, undefined, len),
      node: (len) => hkdfSync('sha512', hkpassword, hksalt, Uint8Array.of(), len),
    },
  };
  await compare('HKDFs', HKDF, {
    levels: ['algorithm', 'library'],
    inputs: { length: [32, 64, 256] },
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
