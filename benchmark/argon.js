import { run, mark, utils } from 'micro-bmark';
import { argon2id } from '@noble/hashes/argon2';
import * as wasm from 'hash-wasm';
// import libsodiumAll from 'libsodium-wrappers';
// const { libsodium: sodium } = libsodiumAll;

console.log(sodium)
const ONLY_NOBLE = process.argv[2] === 'noble';
const password = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
const salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

const ITERS = [1, 4, 8];
const MEMORY = [256, 64 * 1024, 256 * 1024, 1 * 1024 * 1024]; // in KB (256kb, 64mb, 256mb, 1gb)

const KDF = {
  argon2id: {
    'hash-wasm': (iters, mem) =>
      wasm.argon2id({
        password,
        salt,
        iterations: iters,
        parallelism: 1,
        hashLength: 32,
        memorySize: mem,
        outputType: 'binary',
      }),
    // sodium: (iters, mem) =>
    //   sodium.crypto_pwhash(
    //     32,
    //     password,
    //     salt,
    //     iters,
    //     mem * 1024,
    //     sodium.crypto_pwhash_ALG_ARGON2ID13
    //   ),
    noble: (iters, mem) => argon2id(password, salt, { t: iters, m: mem, p: 1, dkLen: 32 }),
  },
};

const main = () =>
  run(async () => {
    // await sodium.ready;
    for (const i of ITERS) {
      for (const m of MEMORY) {
        for (let [k, libs] of Object.entries(KDF)) {
          const title = `${k} (memory: ${m} KB, iters: ${i})`;
          if (!ONLY_NOBLE) console.log(`==== ${title} ====`);
          for (const [lib, fn] of Object.entries(libs)) {
            if (ONLY_NOBLE && lib !== 'noble') continue;
            await mark(!ONLY_NOBLE ? lib : title, 10, () => fn(i, m));
          }
          if (!ONLY_NOBLE) console.log();
        }
      }
    }
    // Log current RAM
    utils.logMem();
  });

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  console.log(1)
  main();
}
