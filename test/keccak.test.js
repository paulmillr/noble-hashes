import { deepStrictEqual, throws } from 'node:assert';
import { createHash } from 'node:crypto';
import { describe, should } from 'micro-should';
import {
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake256,
  keccak_224,
  keccak_256,
  keccak_384,
  keccak_512,
  Keccak,
} from '../esm/sha3.js';
import {
  k12,
  m14,
  cshake128,
  cshake256,
  kmac128,
  kmac256,
  kmac128xof,
  kmac256xof,
  tuplehash128,
  tuplehash128xof,
  tuplehash256,
  tuplehash256xof,
  parallelhash128,
  parallelhash128xof,
  parallelhash256,
  parallelhash256xof,
  keccakprg,
  turboshake128,
  turboshake256,
} from '../esm/sha3-addons.js';
import { bytesToHex, hexToBytes, concatBytes } from '../esm/utils.js';
import { TYPE_TEST, jsonGZ } from './utils.js';
import {
  K12_VECTORS,
  M14_VECTORS,
  CSHAKE_VESTORS,
  KMAC_VECTORS,
  TUPLE_VECTORS,
  PARALLEL_VECTORS,
  VECTORS_TURBO,
  VECTORS_K12,
} from './vectors/sha3-addons.js';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const _dirname = dirname(fileURLToPath(import.meta.url));
const isBun = !!process.versions.bun;

function getVectors(name) {
  const vectors = readFileSync(`${_dirname}/vectors/${name}.txt`, 'utf8').split('\n\n');
  const res = [];
  for (const v of vectors) {
    if (v.startsWith('#')) continue;
    const item = {};
    const args = v.split('\n').map((i) => i.split('=', 2).map((j) => j.trim()));
    for (const [arg, val] of args) if (arg) item[arg] = val;
    res.push(item);
  }
  return res;
}

const fromHex = (hex) => (hex ? hexToBytes(hex.replace(/ |\n/gm, '')) : new Uint8Array());

describe('sha3', () => {
  should('SHA3-224', () => {
    for (let v of getVectors('ShortMsgKAT_SHA3-224')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(sha3_224(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
    }
  });

  should(`SHA3-256`, () => {
    for (let v of getVectors('ShortMsgKAT_SHA3-256')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(sha3_256(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
    }
  });

  should(`SHA3-384`, () => {
    for (let v of getVectors('ShortMsgKAT_SHA3-384')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(sha3_384(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
    }
  });

  should(`SHA3-512`, () => {
    for (let v of getVectors('ShortMsgKAT_SHA3-512')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(sha3_512(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
    }
  });

  should('shake128', () => {
    for (let v of getVectors('ShortMsgKAT_SHAKE128')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(
        shake128(msg, { dkLen: 512 }),
        fromHex(v.Squeezed),
        `len=${v.Len} hex=${v.Msg}`
      );
    }
  });

  should('shake256', () => {
    for (let v of getVectors('ShortMsgKAT_SHAKE256')) {
      if (+v.Len % 8) continue; // partial bytes is not supported
      const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
      deepStrictEqual(
        shake256(msg, { dkLen: 512 }),
        fromHex(v.Squeezed),
        `len=${v.Len} hex=${v.Msg}`
      );
    }
  });

  should('shake128: dkLen', () => {
    for (const dkLen of TYPE_TEST.int) throws(() => shake128('test', { dkLen }));
  });

  should('shake128 cross-test', () => {
    if (isBun) return; // bun is buggy
    for (let i = 0; i < 4096; i++) {
      const node = Uint8Array.from(createHash('shake128', { outputLength: i }).digest());
      deepStrictEqual(shake128('', { dkLen: i }), node);
    }
  });

  should('shake256 cross-test', () => {
    if (isBun) return; // bun is buggy
    for (let i = 0; i < 4096; i++) {
      const node = Uint8Array.from(createHash('shake256', { outputLength: i }).digest());
      deepStrictEqual(shake256('', { dkLen: i }), node);
    }
  });
});

describe('sha3-addons', () => {
  should('k12', () => {
    for (let i = 0; i < K12_VECTORS.length; i++) {
      const v = K12_VECTORS[i];
      const exp = fromHex(v.exp.replace(/ /g, ''));
      let res = k12(v.msg, { personalization: v.personalization, dkLen: v.dkLen });
      if (v.last) res = res.slice(-v.last);
      deepStrictEqual(res, exp, `k12 ${i}`);
    }
  });
  should('k12: dkLen', () => {
    for (const dkLen of TYPE_TEST.int) throws(() => k12('test', { dkLen }));
  });

  should('m14', () => {
    for (let i = 0; i < K12_VECTORS.length; i++) {
      const v = K12_VECTORS[i];
      const exp = fromHex(M14_VECTORS[i].replace(/ /g, ''));
      let res = m14(v.msg, { personalization: v.personalization, dkLen: v.dkLen });
      if (v.last) res = res.slice(-v.last);
      deepStrictEqual(res, exp, `m14 ${i}`);
    }
  });
  should('cSHAKE', () => {
    for (let i = 0; i < CSHAKE_VESTORS.length; i++) {
      const v = CSHAKE_VESTORS[i];
      deepStrictEqual(
        v.fn(v.data, { personalization: v.personalization, NISTfn: v.NISTfn, dkLen: v.dkLen }),
        v.output,
        `cSHAKE ${i}`
      );
    }
  });

  should('KMAC', () => {
    for (let i = 0; i < KMAC_VECTORS.length; i++) {
      const v = KMAC_VECTORS[i];
      deepStrictEqual(
        v.fn(v.key, v.data, { personalization: v.personalization, dkLen: v.dkLen }),
        v.output,
        `KMAC ${i}`
      );
    }
  });

  should('tuplehash', () => {
    for (let i = 0; i < TUPLE_VECTORS.length; i++) {
      const v = TUPLE_VECTORS[i];
      deepStrictEqual(
        v.fn(v.data, { personalization: v.personalization, dkLen: v.dkLen }),
        v.output,
        `tuplehash ${i}`
      );
    }
  });

  should('parallelhash', () => {
    for (let i = 0; i < PARALLEL_VECTORS.length; i++) {
      const v = PARALLEL_VECTORS[i];
      deepStrictEqual(
        v.fn(v.data, { personalization: v.personalization, dkLen: v.dkLen, blockLen: v.blockLen }),
        v.output,
        `parallelhash ${i}`
      );
    }
  });

  should('keccakprg', () => {
    // Generated from test cases of KeccakPRG in XKCP
    const PRG_VECTORS = jsonGZ('vectors/sha3-addon-keccak-prg.json.gz');

    for (let i = 0; i < PRG_VECTORS.length; i++) {
      const v = PRG_VECTORS[i];
      const input = fromHex(v.input);
      const p = keccakprg(+v.capacity);
      p.feed(fromHex(v.input));
      let out = p.fetch(v.output.length / 2);
      if (out.length > 0 && out[0] & 1) {
        if (out[0] & 2) p.feed(input);
        try {
          p.forget();
        } catch (e) {}
        if (out[0] & 4) out = p.fetch(v.output.length / 2);
      }
      deepStrictEqual(out, fromHex(v.output), `prg vector ${i} failed`);
    }
  });

  should('keccakprg invalid usage', () => {
    throws(() => keccakprg(5));
    throws(() => keccakprg(1605));
    throws(() => keccakprgprg(-5));
    throws(() => keccakprg().digest());
    throws(() => keccakprg().digestInto(new Uint8Array()));
  });

  should('XOF', () => {
    const NOT_XOF = [
      sha3_224,
      sha3_256,
      sha3_384,
      sha3_512,
      keccak_224,
      keccak_256,
      keccak_384,
      keccak_512,
      parallelhash128,
      parallelhash256,
    ];
    const NOT_XOF_KMAC = [kmac128, kmac256];
    const XOF = [
      shake128,
      shake256,
      cshake128,
      cshake256,
      parallelhash128xof,
      parallelhash256xof,
      k12,
      m14,
    ];
    const XOF_KMAC = [kmac128xof, kmac256xof];
    // XOF call on non-xof variants fails
    for (let f of NOT_XOF) throws(() => f.create().xof(10), 'xof on non-xof');
    for (let f of NOT_XOF_KMAC)
      throws(() => f.create(new Uint8Array([1, 2, 3])).xof(10), 'xof on non-xof (kmac)');
    // XOF ok on xof instances
    for (let f of XOF) f.create().xof(10);
    for (let f of XOF_KMAC) f.create(new Uint8Array([1, 2, 3])).xof(10);
    for (let f of XOF) {
      throws(() => {
        const h = f.create();
        h.xof(10);
        h.digest();
      }, 'digest after XOF');
    }
    for (let f of XOF_KMAC) {
      throws(() => {
        const h = f.create(new Uint8Array([1, 2, 3]));
        h.xof(10);
        h.digest();
      }, 'digest after XOF (kmac)');
    }
    for (let f of XOF) {
      throws(() => {
        const h = f.create();
        h.digest();
        h.xof(10);
      }, 'XOF after digest');
    }
    for (let f of XOF_KMAC) {
      throws(() => {
        const h = f.create(new Uint8Array([1, 2, 3]));
        h.digest();
        h.xof(10);
      }, 'XOF after digest (kmac)');
    }
    for (let f of XOF) {
      const bigOut = f('', { dkLen: 130816 });
      const hashxof = f.create();
      const out = [];
      for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
      deepStrictEqual(concatBytes(...out), bigOut, 'xof check against fixed size');
    }
    for (let f of XOF_KMAC) {
      const bigOut = f('key', '', { dkLen: 130816 });
      const hashxof = f.create('key');
      const out = [];
      for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
      deepStrictEqual(concatBytes(...out), bigOut, 'xof check against fixed size (kmac)');
    }
  });

  should('Basic clone', () => {
    const objs = [kmac128.create('key').update('123'), keccakprg().feed('123')];
    for (const o of objs) deepStrictEqual(o.clone(), o);
    const objs2 = [
      tuplehash128.create().update('123'),
      parallelhash128.create({ blockLen: 12 }).update('123'),
    ];
    for (const o of objs2) {
      const clone = o.clone();
      delete o.update;
      delete clone.update;
      deepStrictEqual(clone, o);
    }
  });

  should('various vectors for cshake, hmac, k12, p, t', () => {
    const GEN_VECTORS = jsonGZ('vectors/sha3-addons.json.gz').v;

    const tupleData = (hex) => {
      const data = hex ? fromHex(hex) : new Uint8Array([]);
      const tuples = [];
      for (let i = 0; i < data.length; i++) tuples.push(data.slice(0, i));
      return tuples;
    };
    for (let i = 0; i < GEN_VECTORS.length; i++) {
      const v = GEN_VECTORS[i];
      const opt = {
        personalization: fromHex(v.personalization),
        NISTfn: fromHex(v.nist_fn),
        blockLen: +v.block_len,
        dkLen: v.exp.length / 2,
      };
      const fn = {
        cshake128: () => cshake128(fromHex(v.data), opt),
        cshake256: () => cshake256(fromHex(v.data), opt),
        kmac128: () => kmac128(fromHex(v.key), fromHex(v.data), opt),
        kmac256: () => kmac256(fromHex(v.key), fromHex(v.data), opt),
        k12: () => k12(fromHex(v.data), opt),
        // blake3: () => blake3(fromHex(v.data), opt),
        parallel128: () => parallelhash128(fromHex(v.data), opt),
        parallel256: () => parallelhash256(fromHex(v.data), opt),
        tuple128: () => tuplehash128(tupleData(v.data), opt),
        tuple256: () => tuplehash256(tupleData(v.data), opt),
      };
      if (v.fn_name === 'blake3') return;
      const method = fn[v.fn_name];
      let err = `(${i}): ${v.fn_name}`;
      if (!method) throw new Error('invalid fn');
      deepStrictEqual(bytesToHex(method()), v.exp, err);
    }
  });

  should('turboshake', () => {
    deepStrictEqual(
      bytesToHex(
        turboshake128(
          fromHex(
            '437eb3035217e99baea4232ea2f06c2bea1c2c49e58cc0d59762b53887bc69e952dbcfb7a43cc7c817c2d42ae68633fc0f6a9120d02b6616e52cf1074fd8d471'
          )
        )
      ),
      '8e2e8cec4b4056b7810d78da12751029ad4a5b1694d5ca82ebf8b4de9cb4596a'
    );
    deepStrictEqual(
      bytesToHex(
        turboshake256(
          fromHex(
            '51a668f743e40bdafa26502aafaf149dfec1d1780344b3a6286f6e74523c4575a057504d1508d30d326a308f149cd6faedc0a31c164faf514911020c754fef26'
          )
        )
      ),
      'f344b591079f09bc0d6e3f6277b1aab5354cfab81caf4afd37b7e7de6497632a2c4108f23331ce11de41e6a2ace2d7dcd5d8a7aef1a1c0c1c389e7dc26e0ca65'
    );
  });
  should('turboshake spec vectors', () => {
    for (const v of VECTORS_TURBO) {
      let res = v.hash(v.msg, { dkLen: v.dkLen, D: v.D });
      if (v.last) res = res.subarray(-v.last);
      deepStrictEqual(res, v.exp);
    }
  });
  should('k12 spec vectors', () => {
    for (const v of VECTORS_K12) {
      let res = v.hash(v.msg, { personalization: v.C, dkLen: v.dkLen });
      if (v.last) res = res.subarray(-v.last);
      deepStrictEqual(res, v.exp);
    }
  });
  should('turboshake domain separation byte', () => {
    for (const h of [turboshake128, turboshake256]) {
      throws(() => h('', { D: 0 }));
      throws(() => h('', { D: 0x80 }));
      h('', { D: 1 }); // doesn't throw
      h('', { D: 0x7f }); // doesn't throw
    }
  });

  should('validate Keccak construction opts', () => {
    new Keccak(144, 0x06, 224 / 8);
    throws(() => new Keccak(201, 0x06, 224 / 8));
    throws(() => new Keccak(0, 0x06, 224 / 8));
  });
});

should.runWhen(import.meta.url);
