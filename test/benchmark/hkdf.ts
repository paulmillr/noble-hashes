import compare from 'micro-bmark/compare.js';
import crypto from 'node:crypto';
// Noble
import { hkdf } from '../../src/hkdf.ts';
import { sha256, sha512 } from '../../src/sha2.ts';
// Others
import { HKDF as stableHKDF } from '@stablelib/hkdf';
import stable256 from '@stablelib/sha256';
import stable512 from '@stablelib/sha512';

const [password, salt] = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];

const HKDF = {
  'HKDF-SHA256': {
    node: (len) => crypto.hkdfSync('sha256', password, salt, Uint8Array.of(), len),
    stable: (len) => new stableHKDF(stable256.SHA256, password, salt, undefined).expand(len),
    noble: (len) => hkdf(sha256, salt, password, undefined, len),
  },
  'HKDF-SHA512': {
    node: (len) => crypto.hkdfSync('sha512', password, salt, Uint8Array.of(), len),
    stable: (len) => new stableHKDF(stable512.SHA512, password, salt, undefined).expand(len),
    noble: (len) => hkdf(sha512, salt, password, undefined, len),
  },
};

async function main() {
  // Usage:
  // - basic: node hkdf.js
  // - sha256 only: MBENCH_FILTER=SHA256 node hkdf.js
  // - full: MBENCH_DIMS='length,algorithm,library' MBENCH_FILTER=SHA256 node hkdf.js
  await compare('Hashes', { length: { 32: 32, 64: 64, 256: 256 } }, HKDF, {
    libDims: ['algorithm', 'library'],
    defaults: { library: 'noble', buffer: '32B' },
    samples: (length) => {
      if (length <= 64) return 100_000;
      return 25_000;
    },
  });
}

import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
