import compare from 'micro-bmark/compare.js';
// Noble
import { blake256, blake512 } from '../../src/blake1.ts';
import { blake2b, blake2s } from '../../src/blake2.ts';
import { blake3 } from '../../src/blake3.ts';
import { hmac } from '../../src/hmac.ts';
import { ripemd160 } from '../../src/legacy.ts';
import { sha256, sha512 } from '../../src/sha2.ts';
import { k12, m14 } from '../../src/sha3-addons.ts';
import { sha3_256 } from '../../src/sha3.ts';

// Others
import stableb2b from '@stablelib/blake2b';
import stableb2s from '@stablelib/blake2s';
import stableHmac from '@stablelib/hmac';
import stable256 from '@stablelib/sha256';
import stable3 from '@stablelib/sha3';
import stable2_512 from '@stablelib/sha512';
import _blakehash from 'blake-hash/js.js';
import createHash from 'create-hash/browser.js';
import createHmac from 'create-hmac/browser.js';
import { hash as fastsha256 } from 'fast-sha256';
import wasm_ from 'hash-wasm';
import jssha3 from 'js-sha3';
import { createHash as crypto_createHash, createHmac as crypto_createHmac } from 'node:crypto';
import { SHA3 as _SHA3 } from 'sha3';
import nobleUnrolled from 'unrolled-nbl-hashes-sha3';

const wasm = {};
const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);
const ONLY_NOBLE = process.argv[2] === 'noble';

const blake_hash = (name) => {
  return (buf) => {
    const h = _blakehash(name);
    h.update(Buffer.from(buf));
    return Uint8Array.from(h.digest());
  };
};

const HASHES = {
  sha256: {
    noble: (buf) => sha256(buf),
    node: (buf) => crypto_createHash('sha256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha256.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha256').update(buf).digest(),
    stablelib: (buf) => stable256.hash(buf),
    'fast-sha256': (buf) => fastsha256.hash(buf),
    webcrypto: (buf) => globalThis.crypto.subtle.digest('SHA-256', buf),
  },
  sha512: {
    noble: (buf) => sha512(buf),
    node: (buf) => crypto_createHash('sha512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha512.init().update(buf).digest(),
    'crypto-browserify': (buf) => createHash('sha512').update(buf).digest(),
    stablelib: (buf) => stable2_512.hash(buf),
    webcrypto: (buf) => globalThis.crypto.subtle.digest('SHA-512', buf),
  },
  sha3_256: {
    noble: (buf) => sha3_256(buf),
    'noble (unrolled)': (buf) => nobleUnrolled.sha3_256(buf),
    node: (buf) => crypto_createHash('sha3-256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.sha3.init().update(buf).digest(),
    stablelib: (buf) => new stable3.SHA3256().update(buf).digest(),
    'js-sha3': (buf) => wrapBuf(jssha3.sha3_256.create().update(buf).arrayBuffer()),
    sha3: (buf) => new _SHA3(256).update(Buffer.from(buf)).digest(),
  },
  k12: { noble: (buf) => k12(buf) },
  m14: { noble: (buf) => m14(buf) },
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
    node: (buf) => crypto_createHash('blake2b512').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2b.init().update(buf).digest(),
    stablelib: (buf) => new stableb2b.BLAKE2b().update(buf).digest(),
  },
  blake2s: {
    noble: (buf) => blake2s(buf),
    node: (buf) => crypto_createHash('blake2s256').update(buf).digest(),
    'hash-wasm': (buf) => wasm.blake2s.init().update(buf).digest(),
    stablelib: (buf) => new stableb2s.BLAKE2s().update(buf).digest(),
  },
  blake3: {
    noble: (buf) => blake3(buf),
    'hash-wasm': (buf) => wasm.blake3.init().update(buf).digest(),
  },
  ripemd160: {
    noble: (buf) => ripemd160(buf),
    node: (buf) => crypto_createHash('ripemd160').update(buf).digest(),
    'crypto-browserify': (buf) => createHash('ripemd160').update(Buffer.from(buf)).digest(),
  },
  hmac_sha256: {
    noble: (buf) => hmac(sha256, buf, buf),
    node: (buf) => crypto_createHmac('sha256', buf).update(buf).digest(),
    'crypto-browserify': (buf) => createHmac('sha256', buf).update(buf).digest(),
    stablelib: (buf) => new stableHmac.HMAC(stable256.SHA256, buf).update(buf).digest(),
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
  // Usage:
  // - noble+32B only: node hashes.js
  // - noble+diff buffers: MBENCH_DIMS='buffer' node hashes.js
  // - others + buffers: MBENCH_DIMS='buffer,algorithm,library' node hashes.js
  // - others, but algo first (like old one): MBENCH_DIMS='algorithm,buffer,library' node hashes.js
  await compare(
    'Hashes',
    {
      buffer: {
        '32B': new Uint8Array(32).fill(1),
        '64B': new Uint8Array(64).fill(1),
        '1KB': new Uint8Array(1024).fill(2),
        '8KB': new Uint8Array(1024 * 8).fill(3),
        '1MB': new Uint8Array(1024 * 1024).fill(4),
      },
    }, //
    HASHES,
    {
      libDims: ['algorithm', 'library'],
      defaults: { library: 'noble', buffer: '32B' },
      samples: (buf) => {
        if (buf.length === 32) return 500_000;
        if (buf.length === 64) return 200_000;
        if (buf.length === 1024) return 50_000;
        if (buf.length === 8 * 1024) return 6_250;
        return 250;
      },
    }
  );
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
