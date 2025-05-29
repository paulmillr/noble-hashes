import { mark } from 'micro-bmark';
import { argon2id } from '../../src/argon2.ts';
import { blake256 } from '../../src/blake1.ts';
import { blake2b, blake2s } from '../../src/blake2.ts';
import { blake3 } from '../../src/blake3.ts';
import { hkdf } from '../../src/hkdf.ts';
import { hmac } from '../../src/hmac.ts';
import { ripemd160 } from '../../src/legacy.ts';
import { pbkdf2 } from '../../src/pbkdf2.ts';
import { scrypt } from '../../src/scrypt.ts';
import { sha256, sha512 } from '../../src/sha2.ts';
import { k12, kmac256, m14 } from '../../src/sha3-addons.ts';
import { sha3_256, sha3_512 } from '../../src/sha3.ts';

function buf(size) {
  return new Uint8Array(size).fill(size % 251);
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
    sha256, sha512, sha3_256, sha3_512, k12, m14, blake256, blake2b, blake2s, blake3, ripemd160,
  };
  for (const { size, data } of buffers) {
    console.log('# ' + size);
    for (const title in hashes) {
      const hash = hashes[title];
      await mark(title, () => hash(data));
    }
    console.log();
  }

  console.log('# MAC');
  const etc = buf(32);
  await mark('hmac(sha256)', 100000, () => hmac(sha256, etc, etc));
  await mark('hmac(sha512)', 100000, () => hmac(sha512, etc, etc));
  await mark('kmac256', 100000, () => kmac256(etc, etc));
  await mark('blake3(key)', 100000, () => blake3(etc, { key: etc }));

  console.log();
  console.log('# KDF');
  const pass = buf(12);
  const salt = buf(14);
  await mark('hkdf(sha256)', 100000, () => hkdf(sha256, salt, pass, etc, 32));
  await mark('blake3(context)', 100000, () => blake3(etc, { context: etc }));
  await mark('pbkdf2(sha256, c: 2 ** 18)', 10, () =>
    pbkdf2(sha256, pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await mark('pbkdf2(sha512, c: 2 ** 18)', 5, () =>
    pbkdf2(sha512, pass, salt, { c: 2 ** 18, dkLen: 32 })
  );
  await mark('scrypt(n: 2 ** 19, r: 8, p: 1)', 5, () =>
    scrypt(pass, salt, { N: 2 ** 19, r: 8, p: 1, dkLen: 32 })
  );
  await mark('argon2id(t: 1, m: 128MB)', () =>
    argon2id(pass, salt, { t: 1, m: 128 * 1024, p: 1, dkLen: 32 })
  );
}
main();
