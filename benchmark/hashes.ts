import bench, { buf, section, warmup } from '@paulmillr/jsbt/benchmark.js';
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
  await warmup(() => sha256(d));

  // prettier-ignore
  const hashes = {
    sha256, sha512, sha3_256, sha3_512, kt128, kt256, turboshake128, blake256, blake2b, blake2s, blake3, ripemd160, md5, sha1
  };
  for (const { size, data } of buffers) {
    // small inputs read better as plain per-op time than as ops/sec
    section(size, size === '32B' ? { mode: 'time' } : { bytes: data });
    for (const title in hashes) {
      const hash = hashes[title];
      await bench(title, () => hash(data));
    }
    const b32 = buf(32);
    await bench('hmac(sha256)', () => hmac(sha256, b32, data));
    await bench('hmac(sha512)', () => hmac(sha512, b32, data));
    await bench('kmac256', () => kmac256(b32, data));
    await bench('blake3(key)', () => blake3(data, { key: b32 }));
  }

  section('KDF');
  const pass = buf(12);
  const salt = buf(14);
  const context = buf(32);
  await bench('hkdf(sha256)', () => hkdf(sha256, salt, pass, context, 32));
  await bench('blake3(context)', () => blake3(context, { context }));
  await bench('pbkdf2(sha256, c: 2 ** 18)', () =>
    pbkdf2(sha256, pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await bench('scrypt(n: 2 ** 19, r: 8, p: 1)', () =>
    scrypt(pass, salt, { N: 2 ** 19, r: 8, p: 1, dkLen: 32 })
  );
  await bench('argon2id(t: 1, m: 128MB)', () =>
    argon2id(pass, salt, { t: 1, m: 128 * 1024, p: 1, dkLen: 32 })
  );
}
main();
