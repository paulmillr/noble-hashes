import bench from '@paulmillr/jsbt/benchmark.js';
import { blake256 } from '../src/blake1.ts';
import { blake2b } from '../src/blake2.ts';
import { blake3 } from '../src/blake3.ts';
import { hmac } from '../src/hmac.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { kmac256 } from '../src/sha3-addons.ts';
import { sha3_256 } from '../src/sha3.ts';

// Incremental (multi-update) hashing: the same 1MB input absorbed through
// `.create()` + many `.update(chunk)` calls + `.digest()`.
// Chunk sizes cover the interesting engine paths:
//   63B  - unaligned, every block goes through the internal buffer (worst case)
//   256B - small aligned chunks, fast path with per-update views
//   4KB  - large chunks, amortized everything

function buf(size: number) {
  return new Uint8Array(size).fill(size % 251);
}

const MB = 1024 * 1024;
const INPUT = buf(MB);

function chunks(data: Uint8Array, size: number) {
  const out = [];
  for (let pos = 0; pos < data.length; pos += size) out.push(data.subarray(pos, pos + size));
  return out;
}

async function main() {
  const key = buf(32);
  // prettier-ignore
  const hashes = {
    sha256, sha512, sha3_256, blake256, blake2b, blake3,
  };
  const macs = {
    'hmac(sha256)': () => hmac.create(sha256, key),
    'hmac(sha512)': () => hmac.create(sha512, key),
    kmac256: () => kmac256.create(key),
  };
  for (const chunkLen of [63, 256, 4096]) {
    const parts = chunks(INPUT, chunkLen);
    console.log(`# 1MB / ${chunkLen}B chunks (${parts.length} updates)`);
    for (const title in hashes) {
      const hash = hashes[title as keyof typeof hashes];
      await bench(`${title} stream`, () => {
        const h = hash.create();
        for (const c of parts) h.update(c);
        return h.digest();
      });
    }
    for (const title in macs) {
      const create = macs[title as keyof typeof macs];
      await bench(`${title} stream`, () => {
        const h = create();
        for (const c of parts) h.update(c);
        return h.digest();
      });
    }
    console.log();
  }
}

main();
