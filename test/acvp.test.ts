import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { hmac } from '../src/hmac.ts';
import { sha1 } from '../src/legacy.ts';
import { pbkdf2 } from '../src/pbkdf2.ts';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '../src/sha2.ts';
import {
  cshake128,
  cshake256,
  kmac128,
  kmac128xof,
  kmac256,
  kmac256xof,
  parallelhash128,
  parallelhash128xof,
  parallelhash256,
  parallelhash256xof,
  tuplehash128,
  tuplehash128xof,
  tuplehash256,
  tuplehash256xof,
} from '../src/sha3-addons.ts';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '../src/sha3.ts';
import { concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { jsonGZ } from './utils.ts';

const loadACVP = (name, gzip = true) => {
  const json = (fname) =>
    jsonGZ(`vectors/acvp-vectors/gen-val/json-files/${name}/${fname}.json${gzip ? '.gz' : ''}`);
  const prompt = json('prompt');
  const expectedResult = json('expectedResults');
  const internalProjection = json('internalProjection');
  //const registration = json('registration');
  eql(prompt.testGroups.length, expectedResult.testGroups.length);
  eql(prompt.testGroups.length, internalProjection.testGroups.length);
  const groups = [];
  for (let gid = 0; gid < prompt.testGroups.length; gid++) {
    const { tests: pTests, ...pInfo } = prompt.testGroups[gid];
    const { tests: erTests, ...erInfo } = expectedResult.testGroups[gid];
    const { tests: ipTests, ...ipInfo } = internalProjection.testGroups[gid];
    const group = { info: { p: pInfo, er: erInfo, ip: ipInfo }, tests: [] };
    eql(pTests.length, erTests.length);
    eql(pTests.length, ipTests.length);
    for (let tid = 0; tid < pTests.length; tid++) {
      group.tests.push({
        p: pTests[tid],
        er: erTests[tid],
        ip: ipTests[tid],
      });
    }
    groups.push(group);
  }
  return groups;
};

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const MC = {
  sha2: {
    standard: (info, seed, fn, opts) => {
      const res = [];
      for (let j = 0; j < 100; j++) {
        let a = seed;
        let b = seed;
        let c = seed;
        let md;
        for (let i = 0; i < 1000; i++) {
          const msg = concatBytes(a, b, c);
          md = fn(msg, opts);
          a = b;
          b = c;
          c = md;
        }
        res.push(md);
        seed = md;
      }
      return res;
    },
    alternate: (info, seed, fn, opts) => {
      const initialSeedLength = seed.length;
      const res = [];
      for (let j = 0; j < 100; j++) {
        let a = seed;
        let b = seed;
        let c = seed;
        let md;
        for (let i = 0; i < 1000; i++) {
          let msg = concatBytes(a, b, c);
          if (msg.length >= initialSeedLength) msg = msg.subarray(0, initialSeedLength);
          else msg = concatBytes(msg, new Uint8Array(initialSeedLength - msg.length));
          md = fn(msg, opts);
          a = b;
          b = c;
          c = md;
        }
        res.push(md);
        seed = md;
      }
      return res;
    },
  },
  sha3: {
    standard: (info, seed, fn, opts) => {
      const res = [];
      for (let j = 0; j < 100; j++) {
        let md = seed;
        for (let i = 0; i < 1000; i++) md = fn(md, opts);
        res.push(md);
        seed = md;
      }
      return res;
    },
    alternate: (info, seed, fn, opts) => {
      const initialSeedLength = seed.length;
      const res = [];
      for (let j = 0; j < 100; j++) {
        let md = seed;
        for (let i = 0; i < 1000; i++) {
          let msg = md;
          if (msg.length >= initialSeedLength) msg = msg.subarray(0, initialSeedLength);
          else msg = concatBytes(msg, new Uint8Array(initialSeedLength - msg.length));
          md = fn(msg, opts);
        }
        res.push(md);
        seed = md;
      }
      return res;
    },
  },
  shake: {
    standard: (info, seed, fn, opts) => {
      const minOutBytes = info.minOutLen / 8;
      const maxOutBytes = info.maxOutLen / 8;
      const range = maxOutBytes - minOutBytes + 1;
      const res = [];
      const initialSeedLength = 128 / 8;
      let outputLen = maxOutBytes;
      for (let j = 0; j < 100; j++) {
        let md = seed;
        for (let i = 0; i < 1000; i++) {
          let msg = md;
          if (msg.length >= initialSeedLength) msg = msg.subarray(0, initialSeedLength);
          else msg = concatBytes(msg, new Uint8Array(initialSeedLength - msg.length));
          md = fn(msg, { ...opts, dkLen: outputLen });
          const RightmostOutputBits = (md[md.length - 2] << 8) | md[md.length - 1];
          outputLen = minOutBytes + (RightmostOutputBits % range);
        }
        res.push(md);
        seed = md;
      }
      return res;
    },
  },
  // cshake/tuple/parallel: bit level increments :(
};

const HASHES = {
  'SHA2-224': { lib: sha224, groups: loadACVP('SHA2-224-1.0'), MC: MC.sha2 },
  'SHA2-256': { lib: sha256, groups: loadACVP('SHA2-256-1.0'), MC: MC.sha2 },
  'SHA2-384': { lib: sha384, groups: loadACVP('SHA2-384-1.0'), MC: MC.sha2 },
  'SHA2-512': { lib: sha512, groups: loadACVP('SHA2-512-1.0'), MC: MC.sha2 },
  'SHA2-512-224': { lib: sha512_224, groups: loadACVP('SHA2-512-224-1.0'), MC: MC.sha2 },
  'SHA2-512-256': { lib: sha512_256, groups: loadACVP('SHA2-512-256-1.0'), MC: MC.sha2 },
  // sha3
  'SHA3-224': { lib: sha3_224, groups: loadACVP('SHA3-224-2.0'), MC: MC.sha3 },
  'SHA3-256': { lib: sha3_256, groups: loadACVP('SHA3-256-2.0'), MC: MC.sha3 },
  'SHAKE-128': { lib: shake128, groups: loadACVP('SHAKE-128-1.0'), MC: MC.shake },
  'SHAKE-256': { lib: shake256, groups: loadACVP('SHAKE-256-1.0'), MC: MC.shake },
  'cSHAKE-128': { lib: cshake128, groups: loadACVP('cSHAKE-128-1.0') },
  'cSHAKE-256': { lib: cshake256, groups: loadACVP('cSHAKE-256-1.0') },

  'ParallelHash-128': {
    lib: parallelhash128,
    xof: parallelhash128xof,
    groups: loadACVP('ParallelHash-128-1.0'),
  },
  'ParallelHash-256': {
    lib: parallelhash256,
    xof: parallelhash256xof,
    groups: loadACVP('ParallelHash-256-1.0'),
  },
  'TupleHash-128': {
    lib: tuplehash128,
    xof: tuplehash128xof,
    groups: loadACVP('TupleHash-128-1.0'),
  },
  'TupleHash-256': {
    lib: tuplehash256,
    xof: tuplehash256xof,
    groups: loadACVP('TupleHash-256-1.0'),
  },
};

const MAC = {
  hmacSha1: { lib: hmac, hash: sha1, groups: loadACVP('HMAC-SHA-1-2.0') },
  hmacSha224: { lib: hmac, hash: sha224, groups: loadACVP('HMAC-SHA2-224-2.0') },
  hmacSha256: { lib: hmac, hash: sha256, groups: loadACVP('HMAC-SHA2-256-2.0') },
  hmacSha384: { lib: hmac, hash: sha384, groups: loadACVP('HMAC-SHA2-384-2.0') },
  hmacSha512: { lib: hmac, hash: sha512, groups: loadACVP('HMAC-SHA2-512-2.0') },
  hmacSha512_224: { lib: hmac, hash: sha512_224, groups: loadACVP('HMAC-SHA2-512-224-2.0') },
  hmacSha512_256: { lib: hmac, hash: sha512_256, groups: loadACVP('HMAC-SHA2-512-256-2.0') },
  hmacSha3_224: { lib: hmac, hash: sha3_224, groups: loadACVP('HMAC-SHA3-224-2.0') },
  hmacSha3_256: { lib: hmac, hash: sha3_256, groups: loadACVP('HMAC-SHA3-256-2.0') },
  hmacSha3_384: { lib: hmac, hash: sha3_384, groups: loadACVP('HMAC-SHA3-384-2.0') },
  hmacSha3_512: { lib: hmac, hash: sha3_512, groups: loadACVP('HMAC-SHA3-512-2.0') },
  kmac128: {
    lib: kmac128,
    xof: kmac128xof,
    groups: loadACVP('KMAC-128-1.0'),
  },
  kmac256: {
    lib: kmac256,
    xof: kmac256xof,
    groups: loadACVP('KMAC-256-1.0'),
  },
};

export function avcpTests(isSlow = false) {
  describe('AVCP' + (isSlow ? ' slow' : ''), () => {
    for (const name in HASHES) {
      const { lib, xof, groups, MC } = HASHES[name];
      should(name, () => {
        for (const { info, tests } of groups) {
          if (info.ip.outLenIncrement && info.ip.outLenIncrement % 8) continue;
          if (!isSlow && info.ip.testType === 'LDT') continue;
          for (const t of tests) {
            if (t.ip.len % 8) continue; // we don't support less than bit input
            if (t.ip.outLen && t.ip.outLen % 8) continue; // same goes for output length
            const opts = {
              personalization: t.ip.customization ? utf8ToBytes(t.ip.customization) : undefined,
              NISTfn: t.ip.functionName,
              dkLen: t.ip.outLen / 8,
              blockLen: t.ip.blockSize,
            };
            const fn = info.ip.xof ? xof : lib;
            // MonteCarlo
            if (t.ip.resultsArray) {
              if (!MC) continue;
              const mt = MC[info.ip.mctVersion || 'standard'];
              const msg = t.ip.tuple ? t.ip.tuple.map(hexToBytes) : hexToBytes(t.ip.msg);
              const res = mt(info.ip, msg, fn, opts);
              const exp = t.ip.resultsArray.map((i) => hexToBytes(i.md));
              eql(res, exp);
            } else if (t.ip.tuple) {
              const msg = t.ip.tuple.map(hexToBytes);
              eql(fn(msg, opts), hexToBytes(t.ip.md));
            } else if (t.ip.largeMsg) {
              // expansionTechnique
              // This can be like 17gb, so we cannot do this in non-stream mode
              const { content, contentLength, fullLength } = t.ip.largeMsg;
              if (contentLength % 8 || fullLength % 8) continue;
              const c = hexToBytes(content);
              const h = fn.create(opts);
              for (let left = fullLength / 8; left; ) {
                const take = Math.min(c.length, left);
                h.update(c.subarray(0, take));
                left -= take;
              }
              eql(h.digest(), hexToBytes(t.ip.md));
            } else if (t.ip.md) {
              const msg = hexToBytes(t.ip.msg);
              eql(fn(msg, opts), hexToBytes(t.ip.md));
            } else {
              throw new Error('unexpected');
            }
          }
        }
      });
    }
    for (const name in MAC) {
      should(name, () => {
        const { lib, xof, hash, groups } = MAC[name];
        for (const { info, tests } of groups) {
          for (const t of tests) {
            // skip bit level stuff
            if (t.ip.msgLen && t.ip.msgLen % 8) continue;
            if (t.ip.macLen && t.ip.macLen % 8) continue;
            if (t.ip.keyLen && t.ip.keyLen % 8) continue;
            if (t.ip.testPassed !== undefined && !t.ip.testPassed) continue;
            const msg = hexToBytes(t.ip.msg);
            const key = hexToBytes(t.ip.key);
            const fn = info.ip.xof ? xof : lib;
            const opts = {
              personalization: t.ip.customizationHex
                ? hexToBytes(t.ip.customizationHex)
                : t.ip.customization
                  ? utf8ToBytes(t.ip.customization)
                  : undefined,
              NISTfn: t.ip.functionName,
              dkLen: t.ip.macLen / 8,
            };
            const res = hash ? fn(hash, key, msg, opts) : fn(key, msg, opts);
            if (t.ip.testPassed !== undefined && !t.ip.testPassed) {
              if (equalBytes(res.subarray(0, t.ip.macLen / 8), hexToBytes(t.ip.mac)))
                throw new Error('wrong mac');
            } else {
              eql(res.subarray(0, t.ip.macLen / 8), hexToBytes(t.ip.mac));
            }
          }
        }
      });
    }
    should('pbkdf2', () => {
      const groups = loadACVP('PBKDF-1.0');
      for (const { info, tests } of groups) {
        const { lib: hash } = HASHES[info.ip.hmacAlg];
        for (const t of tests) {
          const res = pbkdf2(hash, t.ip.password, hexToBytes(t.ip.salt), {
            c: t.ip.iterationCount,
            dkLen: t.ip.keyLen / 8,
          });
          eql(res, hexToBytes(t.ip.derivedKey));
        }
      }
    });
  });
}

avcpTests();

should.runWhen(import.meta.url);
