import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, rejects } from 'node:assert';
import { sha256, sha512 } from '../src/sha2.ts';
import { bytesToHex, randomBytes } from '../src/utils.ts';
// prettier-ignore
import { argon2d, argon2dAsync } from '../src/argon2.ts';
import { blake256 } from '../src/blake1.ts';
import { blake2b, blake2s } from '../src/blake2.ts';
import { blake3 } from '../src/blake3.ts';
import { expand, extract, hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import { md5, ripemd160, sha1 } from '../src/legacy.ts';
import { pbkdf2, pbkdf2Async } from '../src/pbkdf2.ts';
import { scrypt, scryptAsync } from '../src/scrypt.ts';
import { cshake128, HopMAC128, kmac128, kt128, parallelhash128, tuplehash128, turboshake128 } from '../src/sha3-addons.ts';
import { sha3_256, shake128 } from '../src/sha3.ts';
import { abytes, anumber } from '../src/utils.ts';
import {
  hkdf as whkdf,
  hmac as whmac,
  pbkdf2 as wpbkdf2,
  sha256 as wsha256,
  sha384 as wsha384,
  sha512 as wsha512,
} from '../src/webcrypto.ts';
// TODO: would be nice to extract types from type definitions.
const shakeOpts = { dkLen: 'number?' };
const blake2Opts = { ...shakeOpts, key: 'bytes?', salt: 'bytes?', personalization: 'bytes?' };
const blake3Opts = { ...shakeOpts, key: 'bytes?', context: 'bytes?' };
const k12Opts = { ...shakeOpts, personalization: 'bytes?' };
const cShakeOpts = { ...k12Opts, NISTfn: 'kdf?' };
const pbkdfOpts = {
  args: {
    hash: 'hash',
    password: 'kdf',
    salt: 'kdf',
    opts: { c: 'number', dkLen: 'number?', asyncTick: 'number?' },
  },
  ret: 'bytes',
};

const scryptOpts = {
  args: {
    password: 'kdf',
    salt: 'kdf',
    opts: {
      N: 'number',
      r: 'number',
      p: 'number',
      dkLen: 'number?',
      asyncTick: 'number?',
      maxmem: 'number?',
      onProgress: 'function?',
    },
  },
  ret: 'bytes',
};
const argonOpts = {
  args: {
    password: 'kdf',
    salt: 'kdf',
    opts: {
      t: 'number',
      m: { TYPE: 'number', default: 16 },
      p: 'number',
      version: 'number?',
      key: 'kdf?',
      personalization: 'kdf?',
      dkLen: 'number?',
      asyncTick: 'number?',
      maxmem: 'number?',
      onProgress: 'function?',
    },
  },
  ret: 'bytes',
};
const hashArgs = { message: 'bytes' };

const ALGO = {
  md5: { fn: md5, args: hashArgs, ret: 'bytes' },
  sha1: { fn: sha1, args: hashArgs, ret: 'bytes' },
  ripemd160: { fn: ripemd160, args: hashArgs, ret: 'bytes' },
  sha256: { fn: sha256, args: hashArgs, ret: 'bytes' },
  sha512: { fn: sha512, args: hashArgs, ret: 'bytes' },
  sha3_256: { fn: sha3_256, args: hashArgs, ret: 'bytes' },
  shake128: { fn: shake128, args: { ...hashArgs, opts: shakeOpts }, ret: 'bytes' },
  blake256: { fn: blake256, args: { ...hashArgs, opts: { salt: 'bytes?' } }, ret: 'bytes' },
  blake2s: { fn: blake2s, args: { ...hashArgs, opts: blake2Opts }, ret: 'bytes' },
  blake2b: { fn: blake2b, args: { ...hashArgs, opts: blake2Opts }, ret: 'bytes' },
  blake3: { fn: blake3, args: { ...hashArgs, opts: blake3Opts }, ret: 'bytes' },
  kt128: { fn: kt128, args: { ...hashArgs, opts: k12Opts }, ret: 'bytes' },
  cshake128: { fn: cshake128, args: { ...hashArgs, opts: cShakeOpts }, ret: 'bytes' },
  turboshake128: {
    fn: turboshake128,
    args: { ...hashArgs, opts: { ...shakeOpts, D: 'number?' } },
    ret: 'bytes',
  },
  parallelhash128: {
    fn: parallelhash128,
    args: { ...hashArgs, opts: { ...k12Opts, blockLen: 'number?' } },
    ret: 'bytes',
  },
  tuplehash128: { fn: tuplehash128, args: { message: 'bytes[]' }, ret: 'bytes' },
  // Web hashes
  sha256Web: { fn: wsha256, args: hashArgs, ret: 'bytes' },
  sha384Web: { fn: wsha384, args: hashArgs, ret: 'bytes' },
  sha512Web: { fn: wsha512, args: hashArgs, ret: 'bytes' },
  // MAC
  hmac: { fn: hmac, args: { hash: 'hash', key: 'bytes', message: 'bytes' }, ret: 'bytes' },
  webHmac: { fn: whmac, args: { hash: 'whash', key: 'bytes', message: 'bytes' }, ret: 'bytes' },
  kmac128: { fn: kmac128, args: { key: 'bytes', message: 'bytes', opts: k12Opts }, ret: 'bytes' },
  hopmac128: {
    fn: HopMAC128,
    args: { key: 'bytes', message: 'bytes', personalization: 'bytes?', dkLen: 'number?' },
    ret: 'bytes',
  },
  // KDF
  // TODO: seems like bug, should we allow undefined as length?
  hkdf: {
    fn: hkdf,
    args: { hash: 'hash', ikm: 'bytes', salt: 'bytes?', info: 'bytes?', dkLen: 'number?' },
    ret: 'bytes',
  },
  hkdfWeb: {
    fn: whkdf,
    args: { hash: 'whash', ikm: 'bytes', salt: 'bytes?', info: 'bytes?', dkLen: 'number' },
    ret: 'bytes',
  },
  extract: { fn: extract, args: { hash: 'hash', ikm: 'bytes', salt: 'bytes?' }, ret: 'bytes' },
  expand: {
    fn: expand,
    args: { hash: 'hash', prk: 'bytes', info: 'bytes?', dkLen: 'number?' },
    ret: 'bytes',
  },
  pbkdf2: { fn: pbkdf2, ...pbkdfOpts },
  pbkdf2Async: { fn: pbkdf2Async, ...pbkdfOpts },
  pbkdf2Web: {
    fn: wpbkdf2,
    args: { hash: 'whash', password: 'kdf', salt: 'kdf', opts: { c: 'number', dkLen: 'number?' } },
    ret: 'bytes',
  },
  scrypt: { fn: scrypt, ...scryptOpts },
  scryptAsync: { fn: scryptAsync, ...scryptOpts },
  argon2d: { fn: argon2d, ...argonOpts },
  argon2dAsync: { fn: argon2dAsync, ...argonOpts },
};

async function getError(fn) {
  try {
    await fn();
    throw new Error('NO ERROR!');
  } catch (e) {
    return e;
  }
}
const green = (s) => `\x1b[32m${s}\x1b[0m`;

// Slightly more reasonable type-tests: we define classes of elements, then we can get 'wrong' values for class just
// by using other elements
const VALUES = {
  bool: [false, true],
  bytes: [new Uint8Array([]), new Uint8Array(10), new Uint8Array([1, 2, 3])],
  u32a: [new Uint32Array([1, 2, 3])],
  i32a: [new Int32Array([1, 2, 3])],
  u16a: [new Uint16Array([1, 2, 3])],
  i16a: [new Int16Array([1, 2, 3])],
  string: [
    '0xbe',
    ' 1 2 3 4 5',
    '010203040x',
    'abcdefgh',
    '1 2 3 4 5 ',
    'bee',
    new String('1234'),
    'test',
    // hex
    '00',
    '2345',
    '0123',
  ],
  array: [[], [1, '2', true]],
  // we can also allow null here, but should we? would be inconsistent with most of other APIs.
  optional: [undefined],
  integer: [0, 1, -0.0],
  float: [0.1234, 1.0000000000001, 10e9999],
  bigint: [100n],
  function: [() => {}, async () => {}, class Test {}],
  object: [
    new (class Test {})(),
    { a: 1, b: 2, c: 3 },
    { constructor: { name: 'Uint8Array' }, length: '1e30' },
  ],
  other: [
    null,
    NaN,
    Infinity,
    NaN,
    new Set([1, 2, 3]),
    new Map([['aa', 'bb']]),
    new Uint8ClampedArray([1, 2, 3]),
    new BigInt64Array([1n, 2n, 3n]),
    new ArrayBuffer(100),
    new DataView(new ArrayBuffer(100)),
    Symbol.for('a'),
    new Proxy(new Uint8Array(), {
      get(t, p, r) {
        if (p === 'isProxy') return true;
        return Reflect.get(t, p, r);
      },
    }),
  ],
};

function getWrongValues(...lst) {
  const res = [];
  for (const k in VALUES) {
    if (lst.includes(k)) continue;
    for (const v of VALUES[k]) res.push(v);
  }
  return res;
}

const manglers = {
  true: () => true,
  false: () => false,
  1: () => 1,
  0: () => 0,
  null: () => null,
  u8a: (x) => new Uint8Array(x.length),
  empty: () => new Uint8Array(0),
  zero: (b) => new Uint8Array(b.length),
  slice1: (b) => b.slice(1),
  array: (b) => Array.from(b),
  hex: (b) => bytesToHex(b),
  string: (s) => s.toString(),
  float: (s) => s + 0.1,
  fn: () => () => {},
};

function getManglers(...lst) {
  const res = {};
  for (const i of lst) res[i] = manglers[i];
  return res;
}

function set(obj, path, value) {
  const parts = path.split('.');
  const out = { ...obj }; // shallow copy of root
  let cur = out;

  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i];
    const val = cur[k];
    cur[k] = val && typeof val === 'object' ? { ...val } : {};
    cur = cur[k];
  }
  cur[parts[parts.length - 1]] = value;
  return out;
}

// string -> no match
// string[] -> {inner: 'string', size: ''}
// string[100] -> {inner: 'string', size: '100'}
// string[100][10] -> {inner: 'string[100]', size: '10'}
const ARRAY_RE = /^(?<inner>.+)\[(?<size>\d*)\]$/;

function parseType(t, keepUndefined = false) {
  let m;
  if (typeof t !== 'string') {
    if (t.TYPE) {
      // this pretty much for re-defining default only, can we do better?
      return { ...parseType(t.TYPE), ...t };
    } else {
      const def = {};
      const keys = {};
      for (const k in t) {
        if (t[k] === undefined) continue;
        const p = parseType(t[k]);
        if (keepUndefined || p.default !== undefined) def[k] = p.default;
        if (!p.keys) keys[k] = p;
        else {
          for (const kk in p.keys) keys[`${k}.${kk}`] = p.keys[kk];
        }
      }
      return {
        default: def,
        keys,
        check: (x) => {
          if (typeof x !== 'object' || x === null) throw new Error('not object');
          for (const k in keys) keys[k].check(x[k]);
        },
      };
    }
  } else if ((m = ARRAY_RE.exec(t))) {
    // Fix size bytes: always bytes[]? then we can check for bytes[] and remove slice mangler?
    const p = parseType(m.groups.inner);
    const manglers = getManglers('true', 'false', 'null', 'u8a');
    for (const i in p.manglers) manglers['inner_' + i] = (s) => s.map((j) => p.manglers[i](j));
    const wrong = getWrongValues('array').concat(p.wrong.map((i) => [i]));
    return {
      default: [p.default],
      manglers,
      wrong,
      check: (x) => {
        if (!Array.isArray(x)) throw new Error('not array');
        for (const i of x) p.check(i);
      },
    };
  } else if (t.endsWith('?')) {
    const p = parseType(t.substring(0, t.length - 1));
    const manglers = {};
    console.log('XXX', p);
    for (let k in p.manglers) manglers[k] = p.manglers[k].bind(null, p.default);
    return {
      default: undefined,
      manglers,
      wrong: p.wrong.filter((i) => !VALUES.optional.includes(i)),
      check: (x) => {
        if (x !== undefined) p.check(x);
      },
    };
  } else if (t === 'bytes') {
    const cur = randomBytes(10);
    const manglers = getManglers('false', 'empty', 'zero', 'slice1', 'array', 'hex');
    return { default: cur, manglers, wrong: getWrongValues('bytes'), check: abytes };
  } else if (t === 'kdf') {
    const cur = randomBytes(10);
    const manglers = getManglers('false', 'empty', 'zero', 'slice1', 'array');
    return { default: cur, manglers, wrong: getWrongValues('bytes', 'string') };
  } else if (t === 'number') {
    const manglers = getManglers('true', 'false', 'null', 'string', 'float');
    return { default: 2, manglers, wrong: getWrongValues('integer'), check: anumber };
  } else if (t === 'hash' || t === 'whash') {
    const manglers = getManglers('false', 'empty', 'fn');
    return { default: t === 'whash' ? wsha512 : sha512, manglers, wrong: getWrongValues('hash') };
  } else if (t === 'boolean') {
    const manglers = getManglers('1', '0', 'null', 'string');
    return {
      default: false,
      manglers,
      wrong: getWrongValues('boolean'),
      check: (x) => {
        if (typeof x !== 'boolean') throw new Error('not boolean');
      },
    };
  } else if (t === 'function') {
    const manglers = getManglers('true', 'false', 'null');
    return {
      default: () => {},
      manglers,
      wrong: getWrongValues('function'),
      check: (x) => {
        if (typeof x !== 'function') throw new Error('not function');
      },
    };
  }
  throw new Error('unknown type: ' + t);
}

describe('Errors (internal)', () => {
  should('array regex', () => {
    eql(ARRAY_RE.exec('string'), null);
    eql(ARRAY_RE.exec('string[]').groups.inner, 'string');
    eql(ARRAY_RE.exec('string[]').groups.size, '');
    eql(ARRAY_RE.exec('string[100]').groups.inner, 'string');
    eql(ARRAY_RE.exec('string[100]').groups.size, '100');
    eql(ARRAY_RE.exec('string[100][10]').groups.inner, 'string[100]');
    eql(ARRAY_RE.exec('string[100][10]').groups.size, '10');
    eql(ARRAY_RE.exec('T[1][2][3]').groups.inner, 'T[1][2]');
    eql(ARRAY_RE.exec('T[1][2][3]').groups.size, '3');
    eql(ARRAY_RE.exec('Type[1][2][3][4]').groups.inner, 'Type[1][2][3]');
    eql(ARRAY_RE.exec('Type[1][2][3][4]').groups.size, '4');
    eql(ARRAY_RE.exec('A$B[42]').groups.inner, 'A$B');
    eql(ARRAY_RE.exec('a_b1[2]').groups.inner, 'a_b1');
    eql(ARRAY_RE.exec('Vec<T>[32]').groups.inner, 'Vec<T>');
    eql(ARRAY_RE.exec('Option<Result<T, E>>[1]').groups.inner, 'Option<Result<T, E>>');
    eql(ARRAY_RE.exec('Map<Key, Value[3]>[4]').groups.inner, 'Map<Key, Value[3]>');
    eql(ARRAY_RE.exec('Map<Key, Value[3]>[4]').groups.size, '4');
    eql(ARRAY_RE.exec('str[ing][4]').groups.size, '4');
    eql(ARRAY_RE.exec('[10]'), null); // no inner
    eql(ARRAY_RE.exec('string[10'), null); // missing closing bracket
    eql(ARRAY_RE.exec('string10]'), null); // missing opening bracket
    eql(ARRAY_RE.exec('string[10]more'), null); // trailing characters after bracket
    eql(ARRAY_RE.exec('string [ 100 ]'), null);
    eql(ARRAY_RE.exec('foo[\t42\n]'), null);
    eql(ARRAY_RE.exec('π[2]').groups.inner, 'π');
    eql(ARRAY_RE.exec('𝑨[4]')?.groups.inner, '𝑨'); // surrogate pair test
    eql(ARRAY_RE.exec('变量[3]').groups.inner, '变量');
    eql(ARRAY_RE.exec('[][5]').groups.size, '5'); // no inner
    eql(ARRAY_RE.exec('[][5]').groups.inner, '[]'); // no inner
    eql(ARRAY_RE.exec(' [5]').groups.inner, ' '); // leading space
    eql(ARRAY_RE.exec(' [5]').groups.size, '5'); // leading space
    eql(ARRAY_RE.exec('Array[4] '), null); // trailing space
    eql(ARRAY_RE.exec('Arr[3]x'), null); // junk after closing ]
  });
  should('set', () => {
    const x = { a: 3, b: 4, d: { e: 5, f: 6, h: { x: 7 } } };
    eql(set(x, 'a', 9), { a: 9, b: 4, d: { e: 5, f: 6, h: { x: 7 } } });
    eql(set(x, 'd.e', 9), { a: 3, b: 4, d: { e: 9, f: 6, h: { x: 7 } } });
    eql(set(x, 'd.h.x', 9), { a: 3, b: 4, d: { e: 5, f: 6, h: { x: 9 } } });
    eql(x, { a: 3, b: 4, d: { e: 5, f: 6, h: { x: 7 } } });
  });
  should('parseType', () => {
    const t = {
      key: 'bytes',
      msg: 'bytes',
      opts: {
        dkLen: 'number?',
        fn: 'function',
        x: 'boolean?',
        o: {
          test: 'kdf',
        },
      },
    };
    //eql(parseType(t), {});
  });
});

should('Errors', async () => {
  const res = {}; // Record<string, [string, string][]>
  const algoNameLength = Object.keys(ALGO)
    .map((i) => i.length)
    .reduce((acc, i) => Math.max(acc, i));
  for (const name in ALGO) {
    const C = ALGO[name];
    const CE = async (s, fn) => {
      if (!res[s]) res[s] = [];
      res[s].push({ algoName: name, name: s, error: await getError(fn) });
    };
    const CEG = async (s, manglers, value, fn) => {
      for (const m in manglers) await CE(s + m, () => fn(manglers[m](value)));
    };
    const BYTES10 = randomBytes(10);
    async function processFn(C) {
      const args = parseType(C.args, true);
      const res = await C.fn(...Object.values(args.default));
      if (C.ret) pT(C.ret).check(res); // check return type
      for (const k in args.keys) {
        for (const i of args.keys[k].wrong) {
          await rejects(
            async () => C.fn(...Object.values(set(args.default, k, i))),
            `typetest ${name} ${k} ${typeof i}`
          );
        }
        await CEG(`wrong ${k}=`, args.keys[k].manglers, args.keys[k].default, (s) => {
          return C.fn(...Object.values(set(args.default, k, s)));
        });
      }
      return { defArgs: Object.values(args.default), res };
    }
    const pT = (t) => {
      const x = parseType(t);
      return {
        ...x,
        CEG: (s, fn) => CEG(s, x.manglers, x.default, fn),
      };
    };
    // TODO: maybe remove create from webhashes?
    async function hasCreate(fn, args) {
      try {
        await fn.create(...args);
        return true;
      } catch (e) {
        if (e.message !== 'not implemented') throw e;
        return false;
      }
    }
    console.log('a', name, C);
    // This is nice generic DSL, but we cannot re-use it in other libs,
    // since in other cases we need re-use items between functions (like signatures/keys).
    // In theory we can do 'output types' and then toposort,
    // but this seems like complete over-engineering:
    // - we declare list of function per algo
    // - process functions that doesn't require specific output, save that output under type name
    // - now process other function that depends on that output
    // - Something like:
    // const ALGO = {
    //   lengths: {
    //     seed: 'SEED',
    //     public: 'PUBLIC',
    //     secret: 'SECRET',
    //     signature: 'SIGNATURE', // binds to constants
    //   },
    //   keygen: {
    //     FN: true,
    //     args: { seed: 'bytes[SEED]' },
    //     ret: { publicKey: 'bytes[PUBLIC]', secretKey: 'bytes[SECRET]' },
    //     retBind: { publicKey: 'PublicKey', secretKey: 'SecretKey' }, // binds to types
    //   },
    //   sign: {
    //     FN: true,
    //     args: { message: 'bytes[]', secretKey: 'SecretKey' },
    //     ret: 'bytes[SIGNATURE]',
    //     retBind: 'Signature',
    //   },
    //   verify: {
    //     FN: true,
    //     args: { signature: 'Signature', message: 'bytes[]', publicKey: 'PublicKey' },
    //     ret: 'boolean',
    //   },
    // };
    // But for pqc we need stuff inside function too somehow? (.prehash?)
    // TODO: it would be cool to generate type tests from type definitions, but
    // not sure how feasible it is.
    // Problem that for type-testing verify, we need first process sign and before that keygen.
    // Lengths helps here, but we sometimes need full value
    // (public keys is not neccessarily all zeros!)
    // Also, this brings free type-tests with slightly nicer syntax.
    const { defArgs, res: val } = await processFn(C);
    // HASH + MAC
    if (C.fn.outputLen) eql(val.length, C.fn.outputLen);
    if (C.fn.create) {
      // TODO: do we even need this?
      const opt = defArgs[defArgs.length - 1];
      const msg = defArgs[defArgs.length - 2];
      const prefix = defArgs.slice(0, -2);
      const realArgs = [...prefix, opt];
      if (await hasCreate(C.fn, realArgs)) {
        const cc = await C.fn.create(...realArgs);
        pT('bytes').CEG(`create: wrong message=`, (s) => cc.update(s));
        pT('bytes').CEG(`digestInto: wrong dst=`, (s) => cc.digestInto(s));
      }
    }
  }
  for (const k in res) {
    console.log(green(k));
    for (const { algoName, error } of res[k])
      console.log(`- ${algoName.padEnd(algoNameLength, ' ')}: ${error.message}`);
  }
});

should.runWhen(import.meta.url);
