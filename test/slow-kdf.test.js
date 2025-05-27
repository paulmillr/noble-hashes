import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { scryptSync } from 'node:crypto';
import {
  argon2d,
  argon2dAsync,
  argon2i,
  argon2iAsync,
  argon2id,
  argon2idAsync,
} from '../argon2.js';
import { scrypt, scryptAsync } from '../scrypt.js';
import { bytesToHex } from '../utils.js';
import { bytes, gen, integer, serializeCase } from './generator.js';
import { json, pattern } from './utils.js';

const argon2_vectors = json('./vectors/argon2.json');

// Some vectors are very slow and are ran in slow-big.test.js.

const asyncMap = new Map([
  [argon2i, argon2iAsync],
  [argon2d, argon2dAsync],
  [argon2id, argon2idAsync],
]);

// Takes 10h
const SCRYPT_CASES = gen({
  N: integer(1, 10),
  r: integer(1, 1024),
  p: integer(1, 1024),
  dkLen: integer(0, 1024),
  pwd: bytes(0, 1024),
  salt: bytes(0, 1024),
});

for (let i = 0; i < SCRYPT_CASES.length; i++) {
  const c = SCRYPT_CASES[i];
  should(`Scrypt generator (${i}): ${serializeCase(c)}`, async () => {
    const opt = { ...c, N: 2 ** c.N };
    const exp = Uint8Array.from(scryptSync(c.pwd, c.salt, c.dkLen, { maxmem: 1024 ** 4, ...opt }));
    eql(scrypt(c.pwd, c.salt, opt), exp, `scrypt(${opt})`);
    eql(await scryptAsync(c.pwd, c.salt, opt), exp, `scryptAsync(${opt})`);
  });
}

const verySlowArgon = [
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 262144,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467',
  },
  {
    fn: argon2i,
    t: 2,
    m: 262144,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb',
  },
  {
    fn: argon2i,
    t: 2,
    m: 1048576,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'd1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 1048576,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9',
  },
  {
    fn: argon2i,
    t: 1,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'd168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf',
  },
];

for (let i = 0; i < verySlowArgon.length; i++) {
  const v = verySlowArgon[i];
  const ver = v.version || 0x13;
  const str = `m=${v.m}, t=${v.t}, p=${v.p}`;
  const title = `argon #${i} ${v.fn.name}/v${ver} ${str}`;
  should(title, () => {
    const res = bytesToHex(
      v.fn(v.password, v.salt, {
        m: v.m,
        p: v.p,
        t: v.t,
        key: v.secret,
        personalization: v.data,
        version: v.version,
      })
    );
    eql(res, v.exp);
  });
  should(`${title}: async`, async () => {
    const asyncFn = asyncMap.get(v.fn);
    const res = bytesToHex(
      await asyncFn(v.password, v.salt, {
        m: v.m,
        p: v.p,
        t: v.t,
        key: v.secret,
        personalization: v.data,
        version: v.version,
      })
    );
    eql(res, v.exp);
  });
}

describe('argon2 crosstest', () => {
  const algos = {
    argon2d: argon2d,
    argon2i: argon2i,
    argon2id: argon2id,
  };
  const versions = {
    '0x10': 0x10,
    '0x13': 0x13,
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
  const allResults = [];
  let currIndex = 0;
  for (const algoName in algos) {
    const fn = algos[algoName];
    for (const verName in versions) {
      const version = versions[verName];
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
            version,
            p: parallelism, // 1..255
            m: memoryCost, // 1..2**32-1
            t: timeCost, // 1..2**32-1
            dkLen: outputLen, // 4..2**32-1 but will fail if too long
            key: secret,
          };
          const jopts = JSON.stringify(opts);
          const vi = currIndex++;
          should(`#${vi} ${algoName}(${pass.length}, ${salt.length}, opts=${jopts})`, () => {
            const res = fn(pass, salt, opts);
            const hex = bytesToHex(res);
            eql(hex, argon2_vectors[vi]);
            allResults.push(hex);
          });
        }
      }
    }
  }
});

should.runWhen(import.meta.url);
