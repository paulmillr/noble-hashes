import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { scryptSync } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  argon2d,
  argon2dAsync,
  argon2i,
  argon2iAsync,
  argon2id,
  argon2idAsync,
} from '../src/argon2.ts';
import { bytesToHex } from '../src/utils.ts';
import { ARGON2_CASES, argon2Inputs } from './argon2-cases.ts';
import { bytes, gen, integer } from './generator.ts';
import { PLATFORMS } from './platform.ts';
import { fmt, json } from './utils.ts';

const argon2_vectors = json('./vectors/argon2.json');

// Some vectors are very slow and are ran in slow-big.test.js.
const BT = { describe, it };
const DEFAULT_PLATFORM = PLATFORMS.noble || Object.values(PLATFORMS)[0];

// Takes 10h
const SCRYPT_CASES = gen({
  N: integer(1, 10),
  r: integer(1, 1024),
  p: integer(1, 1024),
  dkLen: integer(1, 1024),
  pwd: bytes(0, 1024),
  salt: bytes(0, 1024),
});

export function testScrypt(variant = 'noble', platform = DEFAULT_PLATFORM, { it } = BT) {
  const { scrypt } = platform;
  const scryptAsync = platform.scryptAsync || scrypt.async;
  for (let i = 0; i < SCRYPT_CASES.length; i++) {
    const c = SCRYPT_CASES[i];
    it(fmt`Scrypt generator (${i}, ${variant}): ${c}`, async () => {
      const opt = { ...c, N: 2 ** c.N };
      const exp = Uint8Array.from(
        scryptSync(c.pwd, c.salt, c.dkLen, { maxmem: 1024 ** 4, ...opt })
      );
      eql(scrypt(c.pwd, c.salt, opt), exp, fmt`scrypt(${opt})`);
      eql(await scryptAsync(c.pwd, c.salt, opt), exp, fmt`scryptAsync(${opt})`);
    });
  }
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

export function testArgon(variant = 'noble', platform = DEFAULT_PLATFORM, { describe, it } = BT) {
  const {
    argon2d: platformArgon2d,
    argon2i: platformArgon2i,
    argon2id: platformArgon2id,
  } = platform;
  const fnMap = new Map([
    // Key these maps by the imported noble functions from this file, not by the injected platform.
    // Reused hosts like awasm pass different function objects, so using `platform.argon2*` as the
    // map key breaks the async lookup and falls through to missing `.async` methods.
    [argon2i, platformArgon2i],
    [argon2d, platformArgon2d],
    [argon2id, platformArgon2id],
  ]);
  const asyncMap = new Map([
    [argon2i, platform.argon2iAsync || argon2iAsync],
    [argon2d, platform.argon2dAsync || argon2dAsync],
    [argon2id, platform.argon2idAsync || argon2idAsync],
  ]);
  for (let i = 0; i < verySlowArgon.length; i++) {
    const v = verySlowArgon[i];
    const fn = fnMap.get(v.fn) || v.fn;
    const ver = v.version || 0x13;
    const str = `m=${v.m}, t=${v.t}, p=${v.p}`;
    const title = `argon(${variant}) #${i} ${fn.name}/v${ver} ${str}`;
    it(title, () => {
      const res = bytesToHex(
        fn(v.password, v.salt, {
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
    it(`${title}: async`, async () => {
      const asyncFn = asyncMap.get(v.fn) || fn.async;
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

  describe(`argon2 crosstest (${variant})`, () => {
    const algos = {
      argon2d: platformArgon2d,
      argon2i: platformArgon2i,
      argon2id: platformArgon2id,
    };
    const versions = {
      '0x10': 0x10,
      '0x13': 0x13,
    };
    let currIndex = 0;
    for (const algoName in algos) {
      const fn = algos[algoName];
      for (const verName in versions) {
        const version = versions[verName];
        for (const c of ARGON2_CASES) {
          const { password, salt, secret } = argon2Inputs(c);
          const opts = { version, p: c.p, m: c.m, t: c.t, dkLen: c.dkLen, key: secret };
          const jopts = JSON.stringify(opts);
          const vi = currIndex++;
          it(`#${vi} ${algoName}(${password.length}, ${salt.length}, opts=${jopts})`, () => {
            eql(bytesToHex(fn(password, salt, opts)), argon2_vectors[vi]);
          });
        }
      }
    }
    if (currIndex !== argon2_vectors.length)
      throw new Error(
        `argon2 vector count mismatch: cases=${currIndex}, vectors=${argon2_vectors.length}`
      );
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  testScrypt();
  testArgon();
}
it.runWhen(import.meta.url);
