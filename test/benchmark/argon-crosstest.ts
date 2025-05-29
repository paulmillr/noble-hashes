// Generate cross-test vectors for argon
// import { argon2i, argon2d, argon2id } from 'hash-wasm'; // Doesn't support version param (only 0x13)
import * as argon from '@node-rs/argon2';
import { pattern } from '../utils.ts';

async function main() {
  // - only raw support salt (node-rs/argon2)
  // - output bigger 4 bytes
  // - hash-wasm doesn't support version param
  //
  const algo = {
    argon2d: argon.Algorithm.Argon2d,
    argon2i: argon.Algorithm.Argon2i,
    argon2id: argon.Algorithm.Argon2id,
  };
  const versions = {
    '0x10': argon.Version.V0x10,
    '0x13': argon.Version.V0x13,
  };
  const PASSWORD = [0, 1, 32, 64, 256, 64 * 1024, 256 * 1024, 1 * 1024];
  const SALT = [8, 16, 32, 64, 256, 64 * 1024, 256 * 1024, 1 * 1024];
  const SECRET = [undefined, 0, 1, 2, 4, 8, 256, 257, 1024, 2 ** 16];
  const TIME = [1, 2, 4, 8, 256, 1024, 2 ** 16];
  const OUTPUT = [32, 4, 16, 32, 64, 128, 512, 1024];
  const P = [1, 2, 3, 4, 8, 16, 1024, 2 ** 16];
  const M = [1, 2, 3, 4, 8, 16, 1024, 2 ** 16];
  const PASS_PATTERN = new Uint8Array([1, 2, 3, 4, 5]);
  const SALT_PATTERN = new Uint8Array([6, 7, 8, 9, 10]);
  const SECRET_PATTERN = new Uint8Array([11, 12, 13, 14, 15]);
  const res = [];
  for (const a in algo) {
    for (const v in versions) {
      for (let curPos = 0; curPos < 6; curPos++) {
        const choice = (arr, i, pos) => arr[pos === curPos ? i % arr.length : 0];
        for (let i = 0; i < 15; i++) {
          const pass = pattern(PASS_PATTERN, choice(PASSWORD, i, 0));
          const salt = pattern(SALT_PATTERN, choice(SALT, i, 1));
          const sLen = choice(SECRET, i);
          const secret = sLen === undefined ? undefined : pattern(SECRET_PATTERN, sLen);
          const outputLen = choice(OUTPUT, i, 2);
          const timeCost = choice(TIME, i, 3);
          const parallelism = choice(P, i, 4);
          const memoryCost = 8 * parallelism * choice(M, i, 5);
          const opts = {
            algorithm: algo[a],
            version: versions[v],
            parallelism, // 1..255
            memoryCost, // 1..2**32-1
            timeCost, // 1..2**32-1
            outputLen, // 4..2**32-1 but will fail if too long
            secret,
            salt,
          };
          const hex = argon.hashRawSync(pass, opts).toString('hex');
          res.push(hex);
        }
      }
    }
  }
  console.log(JSON.stringify(res));
}

main();
