import bench from '@paulmillr/jsbt/bench.js';
import { argon2id } from '../src/argon2.ts';
import { blake256 } from '../src/blake1.ts';
import { blake2b, blake2s } from '../src/blake2.ts';
import { blake3 } from '../src/blake3.ts';
import { hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import { md5, ripemd160, sha1 } from '../src/legacy.ts';
import { pbkdf2 } from '../src/pbkdf2.ts';
import { scrypt } from '../src/scrypt.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { kmac256, kt128, kt256, turboshake128 } from '../src/sha3-addons.ts';
import { sha3_256, sha3_512 } from '../src/sha3.ts';

function buf(size) {
  return new Uint8Array(size).fill(size % 251);
}

function chunks(buf, size) {
  const out = [];
  for (let pos = 0; pos < buf.length; pos += size) out.push(buf.subarray(pos, pos + size));
  return out;
}

function update(create, chunks) {
  const h = create();
  for (const chunk of chunks) h.update(chunk);
  return h.digest();
}

const buffers = [
  // { size: '16B', data: buf(16) }, // common block size
  { size: '32B', data: buf(32) },
  // { size: '64B', data: buf(64) },
  // { size: '1KB', data: buf(1024) },
  // { size: '8KB', data: buf(1024 * 8) },
  { size: '1MB', data: buf(1024 * 1024) },
];

async function main() {
  const d = buf(32);
  for (let i = 0; i < 1_000_000; i++) sha256(d); // warm-up

  // prettier-ignore
  const hashes = {
    sha256, sha512, sha3_256, sha3_512, kt128, kt256, turboshake128, blake256, blake2b, blake2s, blake3, ripemd160, md5, sha1
  };
  for (const { size, data } of buffers) {
    console.log('# ' + size);
    console.log('## Hash');
    for (const title in hashes) {
      const hash = hashes[title];
      await bench(title, () => hash(data), { bytes: data.byteLength });
    }
    console.log();
  }

  const updateChunks = chunks(buf(1024 * 1024), 256);
  console.log('# 1MB / 4096 updates');
  console.log('## Hash');
  for (const title in hashes) {
    const hash = hashes[title];
    await bench(title + ' update', () => update(() => hash.create(), updateChunks), {
      bytes: 1024 * 1024,
    });
  }
  console.log();

  console.log('## MAC');
  const etc = buf(32);
  await bench('hmac(sha256)', () => hmac(sha256, etc, etc));
  await bench('hmac(sha512)', () => hmac(sha512, etc, etc));
  await bench('kmac256', () => kmac256(etc, etc));
  await bench('blake3(key)', () => blake3(etc, { key: etc }));

  console.log();
  console.log('# 1MB / 4096 updates');
  console.log('## MAC');
  await bench('hmac(sha256) update', () => update(() => hmac.create(sha256, etc), updateChunks), {
    bytes: 1024 * 1024,
  });
  await bench('hmac(sha512) update', () => update(() => hmac.create(sha512, etc), updateChunks), {
    bytes: 1024 * 1024,
  });
  await bench('kmac256 update', () => update(() => kmac256.create(etc), updateChunks), {
    bytes: 1024 * 1024,
  });
  await bench('blake3(key) update', () => update(() => blake3.create({ key: etc }), updateChunks), {
    bytes: 1024 * 1024,
  });

  console.log();
  console.log('## KDF');
  const pass = buf(12);
  const salt = buf(14);
  await bench('hkdf(sha256)', () => hkdf(sha256, salt, pass, etc, 32));
  await bench('blake3(context)', () => blake3(etc, { context: etc }));
  await bench('pbkdf2(sha256, c: 2 ** 18)', () =>
    pbkdf2(sha256, pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await bench('pbkdf2(sha512, c: 2 ** 18)', () =>
    pbkdf2(sha512, pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await bench('scrypt(n: 2 ** 19, r: 8, p: 1)', () =>
    scrypt(pass, salt, { N: 2 ** 19, r: 8, p: 1, dkLen: 32 })
  );
  await bench('argon2id(t: 1, m: 128MB)', () =>
    argon2id(pass, salt, { t: 1, m: 128 * 1024, p: 1, dkLen: 32 })
  );
}
main();
