import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import * as cryp from 'node:crypto';
import { blake2b, blake2s } from '../src/blake2.ts';
import { hkdf } from '../src/hkdf.ts';
import { pbkdf2, pbkdf2Async } from '../src/pbkdf2.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { sha3_256, sha3_512 } from '../src/sha3.ts';
import { concatBytes } from '../src/utils.ts';
import { fmt } from './utils.ts';

const { createHash, hkdfSync, pbkdf2Sync } = cryp;

const isBunDeno = Boolean(process.versions.bun || process.versions.deno);
// Random data, by using hash we trying to achieve uniform distribution of each byte values
let start = new Uint8Array([1, 2, 3, 4, 5]);
let RANDOM = Uint8Array.of();
// Fill with random data (1MB)
for (let i = 0; i < 32 * 1024; i++)
  RANDOM = concatBytes(RANDOM, (start = createHash('sha256').update(start).digest()));

const optional = (val) => [undefined, ...val];
const integer = (start, end) => Array.from({ length: end - start }, (_, j) => start + j);
const bytes = (start, end) => integer(start, end).map((i) => RANDOM.slice(0, i));

function mod(a, b) {
  const result = a % b;
  return result >= 0 ? result : b + result;
}

// When testing multiple values like N: 0..20, r: 0..4096, p: 0..4096 we cannot do exhaustive tests,
// since overall space is pretty big, however we can test each dimension separately which is ok if they
// doesn't internal dependencies on each other.
const gen = (obj) => {
  const iter = Math.max(...Object.values(obj).map((i) => i.length));
  const keys = Object.keys(obj);
  let res = [];
  for (let i = 0; i < iter; i++) {
    let val = {};
    for (let j = 0; j < keys.length; j++) {
      const k = keys[j];
      const field = obj[k];
      val[k] = field[mod(j & 1 ? i : -i, field.length)];
    }
    res.push(val);
  }
  return res;
};

function executeKDFTests(limit = true) {
  function genl(params) {
    const cases = gen(params);
    return limit ? cases.slice(0, 64) : cases;
  }

  describe('generator', () => {
    should('hkdf(sha256) generator', async () => {
      if (!hkdfSync) return;
      const cases = genl({
        // nodejs throws if dkLen=0 or ikmLen=0. However this is not enforced by spec.
        dkLen: integer(1, 4096),
        ikm: bytes(1, 4096),
        salt: optional(bytes(0, 4096)),
        info: optional(bytes(0, 1024)), // Nodejs limits length of info field to 1024 bytes which is not enforced by spec.
      });
      for (let c of cases) {
        const exp = new Uint8Array( // returns ArrayBuffer
          hkdfSync(
            'sha256',
            c.ikm,
            c.salt || new Uint8Array(32), // nodejs doesn't support optional salt
            c.info || Uint8Array.of(),
            c.dkLen
          )
        );
        eql(hkdf(sha256, c.ikm, c.salt, c.info, c.dkLen), exp, `hkdf(${c})`);
      }
    });
    should('PBKDF2(sha256) generator', async () => {
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024), // 0 disallowed in node v22
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (let c of cases) {
        if (c.dkLen === 0) continue; // Disallowed in node v22
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha256'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(sha256, c.pwd, c.salt, opt), exp, fmt`pbkdf2(sha256, ${opt})`);
        eql(await pbkdf2Async(sha256, c.pwd, c.salt, opt), exp, fmt`pbkdf2Async(sha256, ${opt})`);
      }
    });

    should('PBKDF2(sha512) generator', async () => {
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024),
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (const c of cases) {
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha512'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(sha512, c.pwd, c.salt, opt), exp, fmt`pbkdf2(sha512, ${opt})`);
        eql(await pbkdf2Async(sha512, c.pwd, c.salt, opt), exp, fmt`pbkdf2Async(sha512, ${opt})`);
      }
    });

    should('PBKDF2(sha3_256) generator', async () => {
      if (isBunDeno) return; // skip
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024),
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (let c of cases) {
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha3-256'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(sha3_256, c.pwd, c.salt, opt), exp, fmt`pbkdf2(sha3_256, ${opt})`);
        eql(
          await pbkdf2Async(sha3_256, c.pwd, c.salt, opt),
          exp,
          fmt`pbkdf2Async(sha3_256, ${opt})`
        );
      }
    });

    should('PBKDF2(sha3_512) generator', async () => {
      if (isBunDeno) return; // skip
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024),
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (let c of cases) {
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha3-512'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(sha3_512, c.pwd, c.salt, opt), exp, fmt`pbkdf2(sha3_512, ${opt})`);
        eql(
          await pbkdf2Async(sha3_512, c.pwd, c.salt, opt),
          exp,
          fmt`pbkdf2Async(sha3_512, ${opt})`
        );
      }
    });

    // Disable because openssl 3 deprecated ripemd
    // should('PBKDF2(ripemd160) generator', async () => {
    //   const cases = genl({
    //     c: integer(1, 1024),
    //     dkLen: integer(0, 1024),
    //     pwd: bytes(0, 1024),
    //     salt: bytes(0, 1024),
    //   });
    //   for (let c of cases) {
    //     const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'ripemd160'));
    //     const opt = { c: c.c, dkLen: c.dkLen };
    //     deepStrictEqual(
    //       pbkdf2(ripemd160, c.pwd, c.salt, opt),
    //       exp,
    //       fmt`pbkdf2(ripemd160, ${opt})`
    //     );
    //     deepStrictEqual(
    //       await pbkdf2Async(ripemd160, c.pwd, c.salt, opt),
    //       exp,
    //       fmt`pbkdf2Async(ripemd160, ${opt})`
    //     );
    //   }
    // });

    should('PBKDF2(blake2s) generator', async () => {
      if (isBunDeno) return; // skip
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024),
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (let c of cases) {
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'blake2s256'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(blake2s, c.pwd, c.salt, opt), exp, fmt`pbkdf2(blake2s, ${opt})`);
        eql(await pbkdf2Async(blake2s, c.pwd, c.salt, opt), exp, fmt`pbkdf2Async(blake2s, ${opt})`);
      }
    });

    should('PBKDF2(blake2b) generator', async () => {
      if (isBunDeno) return; // skip
      const cases = genl({
        c: integer(1, 1024),
        dkLen: integer(1, 1024),
        pwd: bytes(0, 1024),
        salt: bytes(0, 1024),
      });
      for (let c of cases) {
        const exp = Uint8Array.from(pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'blake2b512'));
        const opt = { c: c.c, dkLen: c.dkLen };
        eql(pbkdf2(blake2b, c.pwd, c.salt, opt), exp, fmt`pbkdf2(blake2b, ${opt})`);
        eql(await pbkdf2Async(blake2b, c.pwd, c.salt, opt), exp, fmt`pbkdf2Async(blake2b, ${opt})`);
      }
    });
  });
}

export { bytes, executeKDFTests, gen, integer, optional, RANDOM };

should.runWhen(import.meta.url);
