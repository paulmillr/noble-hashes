const crypto = require('crypto');
const assert = require('assert');
const { should } = require('micro-should');
const { sha256 } = require('../sha256');
const { sha512 } = require('../sha512');
const { blake2s } = require('../blake2s');
const { blake2b } = require('../blake2b');
const { sha3_256, sha3_512 } = require('../sha3');
const { hkdf } = require('../hkdf');
const { pbkdf2, pbkdf2Async } = require('../pbkdf2');
const { concatBytes } = require('./utils');
// Random data, by using hash we trying to achieve uniform distribution of each byte values
let start = new Uint8Array([1, 2, 3, 4, 5]);
let RANDOM = new Uint8Array();
// Fill with random data (1MB)
for (let i = 0; i < 32 * 1024; i++)
  RANDOM = concatBytes(RANDOM, (start = crypto.createHash('sha256').update(start).digest()));

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

function serializeCase(c) {
  let o = {};
  for (let k in c) {
    const v = c[k];
    if (v instanceof Uint8Array) o[k] = `Bytes(${v.length})`;
    else o[k] = v;
  }
  return JSON.stringify(o);
}

function executeKDFTests(limit = true) {
  function genl(params) {
    const cases = gen(params);
    return limit ? cases.slice(0, 64) : cases;
  }

  should('hkdf(sha256) generator', async () => {
    const cases = genl({
      // nodejs throws if dkLen=0 or ikmLen=0. However this is not enforced by spec.
      dkLen: integer(1, 4096),
      ikm: bytes(1, 4096),
      salt: optional(bytes(0, 4096)),
      info: optional(bytes(0, 1024)), // Nodejs limits length of info field to 1024 bytes which is not enforced by spec.
    });
    for (let c of cases) {
      const exp = new Uint8Array( // returns ArrayBuffer
        crypto.hkdfSync(
          'sha256',
          c.ikm,
          c.salt || new Uint8Array(32), // nodejs doesn't support optional salt
          c.info || new Uint8Array(),
          c.dkLen
        )
      );
      assert.deepStrictEqual(hkdf(sha256, c.ikm, c.salt, c.info, c.dkLen), exp, `hkdf(${c})`);
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
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha256'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(sha256, c.pwd, c.salt, opt), exp, `pbkdf2(sha256, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(sha256, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(sha256, ${opt})`
      );
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
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha512'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(sha512, c.pwd, c.salt, opt), exp, `pbkdf2(sha512, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(sha512, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(sha512, ${opt})`
      );
    }
  });

  should('PBKDF2(sha3_256) generator', async () => {
    const cases = genl({
      c: integer(1, 1024),
      dkLen: integer(1, 1024),
      pwd: bytes(0, 1024),
      salt: bytes(0, 1024),
    });
    for (let c of cases) {
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha3-256'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(sha3_256, c.pwd, c.salt, opt), exp, `pbkdf2(sha3_256, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(sha3_256, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(sha3_256, ${opt})`
      );
    }
  });

  should('PBKDF2(sha3_512) generator', async () => {
    const cases = genl({
      c: integer(1, 1024),
      dkLen: integer(1, 1024),
      pwd: bytes(0, 1024),
      salt: bytes(0, 1024),
    });
    for (let c of cases) {
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'sha3-512'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(sha3_512, c.pwd, c.salt, opt), exp, `pbkdf2(sha3_512, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(sha3_512, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(sha3_512, ${opt})`
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
  //     const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'ripemd160'));
  //     const opt = { c: c.c, dkLen: c.dkLen };
  //     assert.deepStrictEqual(
  //       pbkdf2(ripemd160, c.pwd, c.salt, opt),
  //       exp,
  //       `pbkdf2(ripemd160, ${opt})`
  //     );
  //     assert.deepStrictEqual(
  //       await pbkdf2Async(ripemd160, c.pwd, c.salt, opt),
  //       exp,
  //       `pbkdf2Async(ripemd160, ${opt})`
  //     );
  //   }
  // });

  should('PBKDF2(blake2s) generator', async () => {
    const cases = genl({
      c: integer(1, 1024),
      dkLen: integer(1, 1024),
      pwd: bytes(0, 1024),
      salt: bytes(0, 1024),
    });
    for (let c of cases) {
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'blake2s256'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(blake2s, c.pwd, c.salt, opt), exp, `pbkdf2(blake2s, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(blake2s, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(blake2s, ${opt})`
      );
    }
  });

  should('PBKDF2(blake2b) generator', async () => {
    const cases = genl({
      c: integer(1, 1024),
      dkLen: integer(1, 1024),
      pwd: bytes(0, 1024),
      salt: bytes(0, 1024),
    });
    for (let c of cases) {
      const exp = Uint8Array.from(crypto.pbkdf2Sync(c.pwd, c.salt, c.c, c.dkLen, 'blake2b512'));
      const opt = { c: c.c, dkLen: c.dkLen };
      assert.deepStrictEqual(pbkdf2(blake2b, c.pwd, c.salt, opt), exp, `pbkdf2(blake2b, ${opt})`);
      assert.deepStrictEqual(
        await pbkdf2Async(blake2b, c.pwd, c.salt, opt),
        exp,
        `pbkdf2Async(blake2b, ${opt})`
      );
    }
  });
}

module.exports = {
  optional,
  integer,
  bytes,
  gen,
  RANDOM,
  serializeCase,
  executeKDFTests,
};
