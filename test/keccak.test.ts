import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { _KangarooTwelve, _KeccakPRG, _ParallelHash } from '../src/sha3-addons.ts';
import { bytesToHex, concatBytes, hexToBytes, swap32IfBE, u32, utf8ToBytes } from '../src/utils.ts';
import { PLATFORMS } from './platform.ts';
import { jsonGZ, pattern, TYPE_TEST } from './utils.ts';
import {
  CSHAKE_VESTORS,
  K12_VECTORS,
  KMAC_VECTORS,
  PARALLEL_VECTORS,
  TUPLE_VECTORS,
  TURBO_VECTORS,
} from './vectors-keccak.ts';

const _dirname = dirname(fileURLToPath(import.meta.url));
const isBun = !!process.versions.bun;
const EMPTY = Uint8Array.of();

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

const fromHex = (hex) => (hex ? hexToBytes(hex.replace(/ |\n/gm, '')) : EMPTY);

const BT = { describe, it };
export function test(variant: string, platform: any, { describe, it } = BT) {
  const {
    cshake128,
    cshake256,
    Keccak,
    keccakP,
    keccak_224,
    keccak_256,
    keccak_384,
    keccak_512,
    keccakprg,
    kmac128,
    kmac128xof,
    kmac256,
    kmac256xof,
    kt128,
    kt256,
    parallelhash128,
    parallelhash128xof,
    parallelhash256,
    parallelhash256xof,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    shake128,
    shake256,
    tuplehash128,
    tuplehash256,
    turboshake128,
    turboshake256,
  } = platform;
  describe(`sha3 (${variant})`, () => {
    it('SHA3-224', () => {
      for (let v of getVectors('ShortMsgKAT_SHA3-224')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : EMPTY;
        eql(sha3_224(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('SHA3-256', () => {
      for (let v of getVectors('ShortMsgKAT_SHA3-256')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : Uint8Array.of();
        eql(sha3_256(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('SHA3-384', () => {
      for (let v of getVectors('ShortMsgKAT_SHA3-384')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : Uint8Array.of();
        eql(sha3_384(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('SHA3-512', () => {
      for (let v of getVectors('ShortMsgKAT_SHA3-512')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : Uint8Array.of();
        eql(sha3_512(msg), fromHex(v.MD), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('shake128', () => {
      for (let v of getVectors('ShortMsgKAT_SHAKE128')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : Uint8Array.of();
        eql(shake128(msg, { dkLen: 512 }), fromHex(v.Squeezed), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('shake256', () => {
      for (let v of getVectors('ShortMsgKAT_SHAKE256')) {
        if (+v.Len % 8) continue; // partial bytes is not supported
        const msg = +v.Len ? fromHex(v.Msg) : Uint8Array.of();
        eql(shake256(msg, { dkLen: 512 }), fromHex(v.Squeezed), `len=${v.Len} hex=${v.Msg}`);
      }
    });

    it('shake128: dkLen', () => {
      const input = utf8ToBytes('test');
      for (const dkLen of TYPE_TEST.int) throws(() => shake128(input, { dkLen }));
    });

    it('shake128 cross-test', () => {
      if (isBun) return; // bun is buggy
      for (let i = 0; i < 4096; i++) {
        const node = Uint8Array.from(createHash('shake128', { outputLength: i }).digest());
        eql(shake128(EMPTY, { dkLen: i }), node);
      }
    });

    it('shake256 cross-test', () => {
      if (isBun) return; // bun is buggy
      for (let i = 0; i < 4096; i++) {
        const node = Uint8Array.from(createHash('shake256', { outputLength: i }).digest());
        eql(shake256(EMPTY, { dkLen: i }), node);
      }
    });
  });

  describe(`sha3-addons (${variant})`, () => {
    if (
      !cshake128 ||
      !cshake256 ||
      !Keccak ||
      !keccakprg ||
      !kmac128 ||
      !kmac128xof ||
      !kmac256 ||
      !kmac256xof ||
      !kt128 ||
      !parallelhash128 ||
      !parallelhash128xof ||
      !parallelhash256 ||
      !parallelhash256xof ||
      !tuplehash128 ||
      !tuplehash256 ||
      !turboshake128 ||
      !turboshake256
    )
      return;
    it('cSHAKE', () => {
      for (let i = 0; i < CSHAKE_VESTORS.length; i++) {
        const v = CSHAKE_VESTORS[i];
        eql(
          v.fn(v.data, {
            personalization: utf8ToBytes(v.personalization),
            NISTfn: utf8ToBytes(v.NISTfn),
            dkLen: v.dkLen,
          }),
          v.output,
          `cSHAKE ${i}`
        );
      }
    });

    it('KMAC', () => {
      for (let i = 0; i < KMAC_VECTORS.length; i++) {
        const v = KMAC_VECTORS[i];
        eql(
          v.fn(v.key, v.data, { personalization: utf8ToBytes(v.personalization), dkLen: v.dkLen }),
          v.output,
          `KMAC ${i}`
        );
      }
    });

    it('tuplehash', () => {
      for (let i = 0; i < TUPLE_VECTORS.length; i++) {
        const v = TUPLE_VECTORS[i];
        eql(
          v.fn(v.data, { personalization: utf8ToBytes(v.personalization), dkLen: v.dkLen }),
          v.output,
          `tuplehash ${i}`
        );
      }
    });

    it('parallelhash', () => {
      for (let i = 0; i < PARALLEL_VECTORS.length; i++) {
        const v = PARALLEL_VECTORS[i];
        eql(
          v.fn(v.data, {
            personalization: utf8ToBytes(v.personalization),
            dkLen: v.dkLen,
            blockLen: v.blockLen,
          }),
          v.output,
          `parallelhash ${i}`
        );
      }
    });

    it('keccakprg', () => {
      // Generated from test cases of KeccakPRG in XKCP
      const PRG_VECTORS = jsonGZ('vectors/sha3-addon-keccak-prg.json.gz');

      for (let i = 0; i < PRG_VECTORS.length; i++) {
        const v = PRG_VECTORS[i];
        const input = fromHex(v.input);
        const prg = keccakprg(+v.capacity);
        prg.addEntropy(fromHex(v.input));
        let out = prg.randomBytes(v.output.length / 2);
        if (out.length > 0 && out[0] & 1) {
          if (out[0] & 2) prg.addEntropy(input);
          if (1600 - +v.capacity < 801) throws(() => prg.clean(), /rate is too low/);
          else prg.clean();
          if (out[0] & 4) out = prg.randomBytes(v.output.length / 2);
        }
        eql(out, fromHex(v.output), `prg vector ${i} failed`);
      }
    });

    it('keccakprg invalid usage', () => {
      throws(() => keccakprg(5));
      throws(() => keccakprg(1605));
      throws(() => keccakprg(-5));
      throws(() => keccakprg().digest());
      let err: Error | undefined;
      try {
        keccakprg().digestInto(EMPTY);
      } catch (error) {
        err = error as Error;
      }
      eql(err?.message, 'digest is not allowed, use .randomBytes() instead');
    });
    it('keccakprg requires addEntropy before output', () => {
      const prg = keccakprg();
      throws(() => prg.randomBytes(1), /addEntropy\(\) must be called before randomBytes\(\)/);
      throws(() => prg.xof(1), /addEntropy\(\) must be called before randomBytes\(\)/);
      throws(
        () => prg.xofInto(new Uint8Array(1)),
        /addEntropy\(\) must be called before randomBytes\(\)/
      );
      prg.update(new Uint8Array([1, 2, 3]));
      throws(() => prg.randomBytes(1), /addEntropy\(\) must be called before randomBytes\(\)/);
      prg.addEntropy(new Uint8Array([4, 5, 6]));
      eql(prg.randomBytes(1).length, 1);
    });
    it('keccakprg addEntropy defaults to system random bytes', () => {
      const systemSeed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
      const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
      let generated: Uint8Array | undefined;
      let actual: Uint8Array | undefined;
      Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: {
          getRandomValues(out: Uint8Array) {
            generated = out;
            out.set(systemSeed);
            return out;
          },
        },
      });
      try {
        const prg = keccakprg();
        prg.addEntropy();
        actual = prg.randomBytes(32);
        prg.destroy();
      } finally {
        if (cryptoDescriptor) Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
        else delete (globalThis as any).crypto;
      }
      const explicit = keccakprg();
      explicit.addEntropy(systemSeed);
      const expected = explicit.randomBytes(32);
      explicit.destroy();
      eql(actual, expected);
      eql(generated, new Uint8Array(32));
      eql(
        systemSeed,
        Uint8Array.from({ length: 32 }, (_, i) => i + 1)
      );
    });
    it('keccakprg clean throws after destroy', () => {
      const prg = keccakprg();
      prg.addEntropy(new Uint8Array([1, 2, 3]));
      prg.destroy();
      let clean = 'ok';
      let randomBytes = 'ok';
      try {
        prg.clean();
      } catch (error) {
        clean = (error as Error).message;
      }
      try {
        prg.randomBytes(1);
      } catch (error) {
        randomBytes = (error as Error).message;
      }
      eql(
        { clean, randomBytes },
        {
          clean: 'hash was destroyed',
          randomBytes: 'hash was destroyed',
        }
      );
    });
    it('Keccak._cloneInto overwrites destination blockLen', () => {
      const src = new Keccak(136, 0x1f, 0, true);
      const dst = new Keccak(168, 0x06, 32, false);
      src.update(Uint8Array.from({ length: 91 }, (_, i) => (i * 7 + 5) & 255));
      const cloned = src._cloneInto(dst);
      eql(cloned.xof(160), src.clone().xof(160));
    });
    it('_KeccakPRG._cloneInto overwrites destination capacity-dependent state', () => {
      const src = new _KeccakPRG(254);
      src.addEntropy(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
      src.randomBytes(160);
      const expected = src.clone();
      const reused = src._cloneInto(new _KeccakPRG(262));
      eql(reused.randomBytes(16), expected.randomBytes(16));
    });

    it('keccakP: rounds', () => {
      throws(() => keccakP(new Uint32Array(50), 0));
      throws(() => keccakP(new Uint32Array(50), 25));
    });

    it('Keccak padding matches byte-level pad10*1 reference', () => {
      // Independent reference: build the padded message as explicit bytes per
      // FIPS 202 B.2 (suffix bits + first pad '1' in one byte, zeros, closing
      // '1' as 0x80 in the last rate byte) and absorb it with raw keccakP.
      // Unlike Keccak.finish(), this derives the "extra block" case from the
      // padded length itself, so it independently checks the suffix&0x80 branch.
      const spongeReference = (
        blockLen: number,
        suffix: number,
        msg: Uint8Array,
        outLen: number
      ) => {
        const state = new Uint8Array(200);
        const state32 = u32(state);
        const perm = () => {
          swap32IfBE(state32);
          keccakP(state32);
          swap32IfBE(state32);
        };
        const q = blockLen - (msg.length % blockLen);
        // If the suffix byte occupies all 8 bits of the last rate byte
        // (bit 7 set), the closing '1' of pad10*1 needs a whole extra block.
        const pad = new Uint8Array(q === 1 && (suffix & 0x80) !== 0 ? blockLen + 1 : q);
        pad[0] ^= suffix;
        pad[pad.length - 1] ^= 0x80;
        const padded = concatBytes(msg, pad);
        for (let i = 0; i < padded.length; i += blockLen) {
          for (let j = 0; j < blockLen; j++) state[j] ^= padded[i + j];
          perm();
        }
        const out = new Uint8Array(outLen);
        for (let pos = 0; pos < outLen; ) {
          const take = Math.min(blockLen, outLen - pos);
          out.set(state.subarray(0, take), pos);
          pos += take;
          if (pos < outLen) perm();
        }
        return out;
      };
      // 137 is not divisible by 4: exercises the byte-wise absorb path
      for (const blockLen of [72, 136, 137, 168]) {
        for (const suffix of [0x01, 0x06, 0x1f, 0x86, 0xff]) {
          for (let len = 0; len <= 2 * blockLen + 2; len++) {
            const msg = Uint8Array.from({ length: len }, (_, i) => (i * 0x9e + 7) & 0xff);
            const actual = new Keccak(blockLen, suffix, 32, true).update(msg).digest();
            eql(
              actual,
              spongeReference(blockLen, suffix, msg, 32),
              `blockLen=${blockLen} suffix=${suffix} len=${len}`
            );
          }
        }
      }
    });

    it('K12/ParallelHash: streaming matches one-shot across chunk boundaries', () => {
      // Official RFC 9861 / SP 800-185 vectors are single-shot; this pins the
      // internal 8192-byte (K12) and B-byte (ParallelHash) chunking under
      // partial updates, including the SingleNode -> FinalNode suffix switch.
      for (const len of [8191, 8192, 8193, 16384, 16385]) {
        const msg = pattern(0xfa, len);
        const cases = [
          [kt128, { dkLen: 32 }],
          [kt256, { dkLen: 64 }],
          [kt128, { dkLen: 32, personalization: pattern(0xfa, 41) }],
        ];
        for (const [fn, opts] of cases) {
          const exp = fn(msg, opts);
          for (const chunk of [1000, 4096, 8192]) {
            const h = fn.create(opts);
            for (let p = 0; p < len; p += chunk) h.update(msg.subarray(p, p + chunk));
            eql(h.digest(), exp, `len=${len} chunk=${chunk}`);
          }
        }
      }
      const msg = pattern(0xfa, 1000);
      for (const B of [8, 13]) {
        const opts = { blockLen: B, dkLen: 32 };
        const exp = parallelhash128(msg, opts);
        for (const chunk of [1, 7, 64, 333]) {
          const h = parallelhash128.create(opts);
          for (let p = 0; p < 1000; p += chunk) h.update(msg.subarray(p, p + chunk));
          eql(h.digest(), exp, `parallelhash B=${B} chunk=${chunk}`);
        }
      }
      // update() after digest() must throw, even with empty input
      for (const create of [() => kt128.create(), () => parallelhash128.create()]) {
        const h = create();
        h.update(msg).digest();
        throws(() => h.update(EMPTY), 'update(empty) after digest');
      }
    });

    it('sha3 update: chunked/unaligned inputs match single-shot', () => {
      const len = 3 * 136 + 29;
      const msg = Uint8Array.from({ length: len }, (_, i) => (i * 7 + 1) & 0xff);
      const exp = sha3_256(msg);
      for (let split = 0; split <= len; split += 13) {
        const h = sha3_256.create().update(msg.subarray(0, split)).update(msg.subarray(split));
        eql(h.digest(), exp, `split=${split}`);
      }
      // subarrays with unaligned byteOffset must not change results
      for (let off = 1; off < 8; off++) {
        const buf = new Uint8Array(len + off);
        buf.set(msg, off);
        eql(sha3_256(buf.subarray(off)), exp, `byteOffset=${off}`);
      }
    });

    it('sha3 digestInto only fills outputLen bytes', () => {
      const msg = Uint8Array.from([1, 2, 3]);
      const hash = sha3_256.create().update(msg);
      const out = new Uint8Array(hash.outputLen + 8).fill(0xaa);
      hash.digestInto(out);
      eql(
        out.subarray(0, hash.outputLen),
        Uint8Array.from(createHash('sha3-256').update(msg).digest())
      );
      eql(out.subarray(hash.outputLen), new Uint8Array(8).fill(0xaa));
    });

    it('XOF', () => {
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
        kt128,
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
      const key = utf8ToBytes('key');
      for (let f of XOF) {
        const bigOut = f(EMPTY, { dkLen: 130816 });
        const hashxof = f.create();
        const out = [];
        for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
        eql(concatBytes(...out), bigOut, 'xof check against fixed size');
      }
      for (let f of XOF_KMAC) {
        const bigOut = f(key, EMPTY, { dkLen: 130816 });
        const hashxof = f.create(key);
        const out = [];
        for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
        eql(concatBytes(...out), bigOut, 'xof check against fixed size (kmac)');
      }
    });

    it('Basic clone', () => {
      const a = utf8ToBytes('key');
      const b = utf8ToBytes('123');
      const prg = keccakprg();
      prg.addEntropy(b);
      const objs = [kmac128.create(a).update(b), prg];
      for (const o of objs) eql(o.clone(), o);
      const objs2 = [
        tuplehash128.create().update(b),
        parallelhash128.create({ blockLen: 12 }).update(b),
      ];
      for (const o of objs2) {
        const clone = o.clone();
        delete o.update;
        delete clone.update;
        eql(clone, o);
      }
    });
    it('_ParallelHash._cloneInto clears stale destination leaf state', () => {
      const leaf = () => cshake128.create({ dkLen: 32 });
      const src = new _ParallelHash(168, 16, leaf, false, { blockLen: 12 });
      const dst = new _ParallelHash(168, 16, leaf, false, { blockLen: 12 });
      const msg = utf8ToBytes('xyz');
      dst.update(utf8ToBytes('abc'));
      const cloned = src._cloneInto(dst);
      eql(
        cloned.update(msg).digest(),
        new _ParallelHash(168, 16, leaf, false, { blockLen: 12 }).update(msg).digest()
      );
    });
    it('_KangarooTwelve._cloneInto copies and clears reusable leaf state', () => {
      const mk = (len: number) => Uint8Array.from({ length: len }, (_, i) => (i * 11 + 7) & 0xff);
      const suffix = mk(9000);
      const sourceLengths = [10, 9000, 17000] as const;
      // Expected outputs were independently verified with XKCP and PyCryptodome primitives.
      const variants = [
        {
          source: [168, 32, 32],
          destination: [136, 64, 64],
          expected: [
            '2769d022a0cf258ba4f2e619443fa5dc9a95696a3e044777bb2860394a241e31',
            'bc413769f9c288492592e90aac29ce29cf6247f424700f57ffec46b0226bce6e',
            'fee3c1a6c66fa61ce48e8b33dd7a29a6ec338d4a40088ae776772e0f231277b9',
          ],
        },
        {
          source: [136, 64, 64],
          destination: [168, 32, 32],
          expected: [
            'c1dd86706773c0c8b274903e427d7669c5818d5d6c5a5dc79ef3077e362191d6' +
              'ecc0b482fad50c7aaa1bb806b1ac0132686b889d9e1c1ccf7881fca46cce629e',
            '2aa0331db0c37c42983d2c9b78873c1954691a4a6d22840d05e8f9e9290e796' +
              '24706719b329b56ca9897fa42b867207c9b0fe277f36e3ed290a911a420f01163',
            'cf6a5c1b991454a17f2ddb31c6b293aa1a8745879ea6ef57b4cb2515776bf08d' +
              '2763fefbd80e48869e3d6a6a0b3ef823ff68b1c8a7b9018a4b34f4caf1f68aaa',
          ],
        },
      ] as const;
      for (const { source, destination, expected } of variants) {
        for (let i = 0; i < sourceLengths.length; i++) {
          const src = new _KangarooTwelve(...source, 12, {}).update(mk(sourceLengths[i]));
          const dst = new _KangarooTwelve(...destination, 12, {}).update(mk(17000));
          eql(src._cloneInto(dst).update(suffix).digest(), hexToBytes(expected[i]));
        }
      }
    });
    it('_KangarooTwelve._cloneInto wipes replaced personalization', () => {
      for (const [blockLen, leafLen, outLen] of [
        [168, 32, 32],
        [136, 64, 64],
      ] as const) {
        const sourceInput = Uint8Array.from([1, 2, 3]);
        const source = new _KangarooTwelve(blockLen, leafLen, outLen, 12, {
          personalization: sourceInput,
        });
        const replacedInput = Uint8Array.from([9, 8, 7, 6]);
        const replaced = new _KangarooTwelve(blockLen, leafLen, outLen, 12, {
          personalization: replacedInput,
        });
        const old = (replaced as any).personalization as Uint8Array;
        source._cloneInto(replaced);
        // Replaced private storage must not retain caller bytes after becoming unreachable.
        eql(old, new Uint8Array(old.length));
        eql(sourceInput, Uint8Array.from([1, 2, 3]));
        eql(replacedInput, Uint8Array.from([9, 8, 7, 6]));

        const reusable = new _KangarooTwelve(blockLen, leafLen, outLen, 12, {
          personalization: Uint8Array.from([6, 7, 8]),
        });
        const storage = (reusable as any).personalization as Uint8Array;
        source._cloneInto(reusable);
        eql((reusable as any).personalization === storage, true);
        eql(storage, sourceInput);

        const empty = new _KangarooTwelve(blockLen, leafLen, outLen, 12, {});
        const cleared = (reusable as any).personalization as Uint8Array;
        empty._cloneInto(reusable);
        eql(cleared, new Uint8Array(cleared.length));
        eql(reusable.digest(), empty.clone().digest());
      }
    });

    it('various vectors for cshake, kmac, kt128, parallelhash, tuplehash', () => {
      const GEN_VECTORS = jsonGZ('vectors/sha3-addons.json.gz').v;

      const tupleData = (hex) => {
        const data = hex ? fromHex(hex) : Uint8Array.of();
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
          k12: () => kt128(fromHex(v.data), opt),
          // blake3: () => blake3(fromHex(v.data), opt),
          parallel128: () => parallelhash128(fromHex(v.data), opt),
          parallel256: () => parallelhash256(fromHex(v.data), opt),
          tuple128: () => tuplehash128(tupleData(v.data), opt),
          tuple256: () => tuplehash256(tupleData(v.data), opt),
        };
        if (v.fn_name === 'blake3') continue;
        const method = fn[v.fn_name];
        let err = `(${i}): ${v.fn_name}`;
        if (!method) throw new Error('invalid fn ' + v.fn_name);
        eql(bytesToHex(method()), v.exp, err);
      }
    });

    it('turboshake', () => {
      eql(
        bytesToHex(
          turboshake128(
            fromHex(
              '437eb3035217e99baea4232ea2f06c2bea1c2c49e58cc0d59762b53887bc69e952dbcfb7a43cc7c817c2d42ae68633fc0f6a9120d02b6616e52cf1074fd8d471'
            )
          )
        ),
        '8e2e8cec4b4056b7810d78da12751029ad4a5b1694d5ca82ebf8b4de9cb4596a'
      );
      eql(
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
    it('turboshake spec vectors', () => {
      for (const v of TURBO_VECTORS) {
        let res = v.hash(v.msg, { dkLen: v.dkLen, D: v.D });
        if (v.last) res = res.subarray(-v.last);
        eql(res, v.exp);
      }
    });
    it('k128, k256', () => {
      for (const v of K12_VECTORS) {
        let res = v.hash(v.msg, { dkLen: v.dkLen, D: v.D, personalization: v.C });
        if (v.last) res = res.subarray(-v.last);
        eql(res, v.exp);
      }
    });
    it('turboshake domain separation byte', () => {
      for (const h of [turboshake128, turboshake256]) {
        throws(() => h(EMPTY, { D: 0 }));
        throws(() => h(EMPTY, { D: 0x80 }));
        h(EMPTY, { D: 1 }); // doesn't throw
        h(EMPTY, { D: 0x7f }); // doesn't throw
      }
    });

    it('turboshake and k12: dkLen', () => {
      for (const h of [turboshake128, turboshake256, kt128, kt256])
        throws(() => h(EMPTY, { dkLen: 0 }));
    });
    it('ParallelHash blockLen=0', () => {
      throws(() => parallelhash128(new Uint8Array([1, 2, 3]), { blockLen: 0, dkLen: 32 }));
      throws(() => parallelhash256(new Uint8Array([1, 2, 3]), { blockLen: 0, dkLen: 64 }));
      throws(() => parallelhash128xof(new Uint8Array([1, 2, 3]), { blockLen: 0, dkLen: 32 }));
      throws(() => parallelhash256xof(new Uint8Array([1, 2, 3]), { blockLen: 0, dkLen: 64 }));
    });
    it('KangarooTwelve direct states detach personalization', () => {
      const msg = Uint8Array.from([1, 2, 3, 4, 5, 6]);
      for (const hash of [kt128, kt256]) {
        const pers = Uint8Array.from([9, 8, 7]);
        const state = hash
          .create({ personalization: pers, dkLen: hash.outputLen })
          .update(msg.subarray(0, 3));
        pers.fill(0);
        const out = state.update(msg.subarray(3)).digest();
        const exp = hash(msg, {
          personalization: Uint8Array.from([9, 8, 7]),
          dkLen: hash.outputLen,
        });
        eql(out, exp);
      }
    });
    it('KangarooTwelve clones keep personalization', () => {
      const msg = Uint8Array.from([1, 2, 3, 4, 5, 6]);
      for (const hash of [kt128, kt256]) {
        const pers = Uint8Array.from([9, 8, 7]);
        const state = hash
          .create({ personalization: pers, dkLen: hash.outputLen })
          .update(msg.subarray(0, 3));
        const clone = state.clone();
        const out1 = state.update(msg.subarray(3)).digest();
        const out2 = clone.update(msg.subarray(3)).digest();
        eql(out2, out1);

        const pers2 = Uint8Array.from([9, 8, 7]);
        const state2 = hash
          .create({ personalization: pers2, dkLen: hash.outputLen })
          .update(msg.subarray(0, 3));
        const clone2 = state2.clone();
        pers2.fill(0);
        const out3 = clone2.update(msg.subarray(3)).digest();
        const exp = hash(msg, {
          personalization: Uint8Array.from([9, 8, 7]),
          dkLen: hash.outputLen,
        });
        eql(out3, exp);
      }
    });

    it('validate Keccak construction opts', () => {
      new Keccak(144, 0x06, 224 / 8);
      throws(() => new Keccak(201, 0x06, 224 / 8));
      throws(() => new Keccak(0, 0x06, 224 / 8));
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href)
  for (const k in PLATFORMS) test(k, PLATFORMS[k]);

it.runWhen(import.meta.url);
