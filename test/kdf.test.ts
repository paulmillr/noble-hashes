import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import * as nodeCrypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { executeKDFTests, RANDOM } from './generator.ts';
import { PLATFORMS } from './platform.ts';
import { EMPTY, fmt, SPACE, TYPE_TEST } from './utils.ts';

const BT = { describe, it };

// Count all bytes passed to a hash, including work through cloned states. This makes long-key
// prehash regressions deterministic instead of relying on wall-clock timings.
function trackedHash(hash) {
  const counter = { bytes: 0 };
  class TrackedHash {
    constructor(inner = hash.create()) {
      this.inner = inner;
      this.blockLen = inner.blockLen;
      this.outputLen = inner.outputLen;
      this.canXOF = false;
    }
    update(buf) {
      counter.bytes += buf.length;
      this.inner.update(buf);
      return this;
    }
    digestInto(out) {
      this.inner.digestInto(out);
    }
    digest() {
      return this.inner.digest();
    }
    destroy() {
      this.inner.destroy();
    }
    _cloneInto(to) {
      to ||= new TrackedHash();
      this.inner._cloneInto(to.inner);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  }
  const fn = (msg) => new TrackedHash().update(msg).digest();
  fn.outputLen = hash.outputLen;
  fn.blockLen = hash.blockLen;
  fn.canXOF = false;
  fn.create = () => new TrackedHash();
  return { hash: fn, counter };
}

async function pbkdf2Work(fn, sha256, password, salt, c) {
  const tracked = trackedHash(sha256);
  const output = await fn(tracked.hash, password, salt, { c, dkLen: 32, asyncTick: 1 });
  return { bytes: tracked.counter.bytes, output };
}

export function test(variant: string, platform: any, { describe, it } = BT) {
  const { expand, hkdf, extract: hkdf_extract } = platform;
  const {
    argon2id,
    argon2idAsync,
    blake2s,
    kt128,
    kt256,
    pbkdf2,
    pbkdf2Async,
    scrypt,
    scryptAsync,
    sha256,
    sha512,
  } = platform;
  const scryptMaxmem = platform.scryptMaxmem || ((opts) => 128 * opts.r * (opts.N + opts.p + 1));
  const progress1 = async (
    run: (onProgress: (progress: number) => void) => unknown | Promise<unknown>
  ) => {
    const t: number[] = [];
    await run((progress) => t.push(progress));
    eql({ called: t.length !== 0, last: t[t.length - 1] }, { called: true, last: 1 });
  };

  // HKDF test vectors from RFC 5869
  const HKDF_VECTORS = [
    {
      hash: sha256,
      IKM: hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      salt: hexToBytes('000102030405060708090a0b0c'),
      info: hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
      L: 42,
      PRK: hexToBytes('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
      OKM: hexToBytes(
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
      ),
    },
    {
      hash: sha256,
      IKM: hexToBytes(
        '000102030405060708090a0b0c0d0e0f' +
          '101112131415161718191a1b1c1d1e1f' +
          '202122232425262728292a2b2c2d2e2f' +
          '303132333435363738393a3b3c3d3e3f' +
          '404142434445464748494a4b4c4d4e4f'
      ),
      salt: hexToBytes(
        '606162636465666768696a6b6c6d6e6f' +
          '707172737475767778797a7b7c7d7e7f' +
          '808182838485868788898a8b8c8d8e8f' +
          '909192939495969798999a9b9c9d9e9f' +
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
      ),
      info: hexToBytes(
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
          'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
          'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
          'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
          'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
      ),
      L: 82,
      PRK: hexToBytes('06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244'),
      OKM: hexToBytes(
        'b11e398dc80327a1c8e7f78c596a4934' +
          '4f012eda2d4efad8a050cc4c19afa97c' +
          '59045a99cac7827271cb41c65e590e09' +
          'da3275600c2f09b8367793a9aca3db71' +
          'cc30c58179ec3e87c14c01d5c1f3434f' +
          '1d87'
      ),
    },
    {
      hash: sha256,
      IKM: hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      salt: hexToBytes(''),
      info: hexToBytes(''),
      L: 42,
      PRK: hexToBytes('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04'),
      OKM: hexToBytes(
        '8da4e775a563c18f715f802a063c5a31' +
          'b8a11f5c5ee1879ec3454e5f3c738d2d' +
          '9d201395faa4b61a96c8'
      ),
    },
    {
      hash: sha256,
      IKM: hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      salt: undefined,
      info: undefined,
      L: 42,
      PRK: hexToBytes('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04'),
      OKM: hexToBytes(
        '8da4e775a563c18f715f802a063c5a31' +
          'b8a11f5c5ee1879ec3454e5f3c738d2d' +
          '9d201395faa4b61a96c8'
      ),
    },
  ];

  // Scrypt test vectors from RFC 7914
  const SCRYPT_VECTORS = [
    {
      P: utf8ToBytes(''),
      S: utf8ToBytes(''),
      N: 16,
      r: 1,
      p: 1,
      dkLen: 64,
      exp:
        '77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97' +
        'f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42' +
        'fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17' +
        'e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06',
    },
    {
      P: utf8ToBytes('password'),
      S: utf8ToBytes('NaCl'),
      N: 1024,
      r: 8,
      p: 16,
      dkLen: 64,
      exp:
        'fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe' +
        '7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62' +
        '2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da' +
        'c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40',
    },
    {
      P: utf8ToBytes('pleaseletmein'),
      S: utf8ToBytes('SodiumChloride'),
      N: 16384,
      r: 8,
      p: 1,
      dkLen: 64,
      exp:
        '70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb' +
        'fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2' +
        'd5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9' +
        'e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87',
    },
    {
      P: utf8ToBytes('pleaseletmein'),
      S: utf8ToBytes('SodiumChloride'),
      N: 1048576,
      r: 8,
      p: 1,
      dkLen: 64,
      maxmem: 1024 ** 4,
      exp:
        '21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81' +
        'ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47' +
        '8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3' +
        '37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4',
    },
  ];

  const PBKDF2_VECTORS = [
    // Vectors from RFC 7914 (scrypt)
    {
      hash: sha256,
      P: utf8ToBytes('passwd'),
      S: utf8ToBytes('salt'),
      c: 1,
      dkLen: 64,
      exp:
        '55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05' +
        'f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc' +
        '49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31' +
        '7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83',
    },
    {
      hash: sha256,
      P: utf8ToBytes('Password'),
      S: utf8ToBytes('NaCl'),
      c: 80000,
      dkLen: 64,
      exp:
        '4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9' +
        '64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56' +
        'a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17' +
        '6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d',
    },
  ];
  describe(`hkdf (${variant})`, () => {
    for (let i = 0; i < HKDF_VECTORS.length; i++) {
      const t = HKDF_VECTORS[i];
      it(`HKDF vector (${i})`, () => {
        const PRK = hkdf_extract(t.hash, t.IKM, t.salt);
        eql(PRK, t.PRK);
        const OKM = hkdf(t.hash, t.IKM, t.salt, t.info, t.L);
        eql(OKM, t.OKM);
      });
    }

    it('HKDF types', () => {
      const e = EMPTY.bytes;
      hkdf(sha256, e, e, e, 32);
      hkdf(sha256, e, e, e, 8160);
      throws(() => hkdf(sha256, e, e, e, 8160 + 1), `hkdf.dkLen(8160 + 1)`);
      hkdf(sha512, e, e, e, 16320);
      throws(() => hkdf(sha512, e, e, e, 16320 + 1), `hkdf.dkLen(16320 + 1)`);
      for (const t of TYPE_TEST.int) {
        throws(() => hkdf(sha256, e, e, e, t), fmt`hkdf.dkLen(${t})`);
      }
      for (const t of TYPE_TEST.bytes) {
        throws(() => hkdf(sha256, t, e, e, 32), fmt`hkdf.ikm(${t})`);
        throws(() => hkdf(sha256, e, t, e, 32), fmt`hkdf.salt(${t})`);
        throws(() => hkdf(sha256, e, e, t, 32), fmt`hkdf.info(${t})`);
      }
      throws(() => hkdf(sha256, undefined, e, e, 32), 'hkdf.ikm===undefined');
      for (const t of TYPE_TEST.hash) throws(() => hkdf(t, e, e, e, 32), fmt`hkdf(hash=${t})`);
    });
    it('HKDF expand: PRK length', () => {
      throws(() => expand(sha256, new Uint8Array(31), undefined, 32));
    });
    it('HKDF salt: undefined == empty == zeros(HashLen)', () => {
      // HMAC zero-pads its key to blockLen, so these three salts must yield
      // identical PRKs. Pins the design decision from
      // https://github.com/RustCrypto/KDFs/issues/15 (undefined is not special-
      // cased away from empty; they simply coincide for HMAC-based extract).
      const ikm = Uint8Array.from({ length: 22 }, () => 0x0b);
      const a = hkdf_extract(sha256, ikm);
      eql(hkdf_extract(sha256, ikm, Uint8Array.of()), a);
      eql(hkdf_extract(sha256, ikm, new Uint8Array(32)), a);
      eql(hkdf_extract(sha256, ikm, new Uint8Array(64)), a); // blockLen zeros too
    });
    it('HKDF cross-test with node:crypto', () => {
      if (typeof nodeCrypto.hkdfSync !== 'function') return;
      const ikm = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
      const salt = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
      const info = Uint8Array.from([1, 2, 3, 4]);
      for (const [hash, name] of [
        [sha256, 'sha256'],
        [sha512, 'sha512'],
      ]) {
        // odd lengths cross T-block boundaries; 8160 is sha256's max
        for (const len of [1, 31, 32, 33, 64, 255, 1000, 8160]) {
          const node = new Uint8Array(nodeCrypto.hkdfSync(name, ikm, salt, info, len));
          eql(hkdf(hash, ikm, salt, info, len), node, `hkdf ${name} len=${len}`);
        }
      }
    });
    if (variant === 'noble')
      it('HKDF input work is additive', () => {
        const work = (len) => {
          const tracked = trackedHash(sha256);
          const input = RANDOM.subarray(0, len);
          const output = hkdf(tracked.hash, input, input, input, 32);
          return { bytes: tracked.counter.bytes, output };
        };
        const small = work(1024);
        const large = work(64 * 1024);
        const input = RANDOM.subarray(0, 64 * 1024);
        eql(large.output, hkdf(sha256, input, input, input, 32));
        eql(large.bytes - small.bytes, 3 * (64 * 1024 - 1024));
      });
  });

  describe(`scrypt (${variant})`, () => {
    it(`Scrypt vectors`, async () => {
      for (let i = 0; i < SCRYPT_VECTORS.length; i++) {
        const t = SCRYPT_VECTORS[i];
        const exp = hexToBytes(t.exp.replace(/ /g, ''));
        eql(scrypt(t.P, t.S, t), exp, i);
        eql(await scryptAsync(t.P, t.S, t), exp, i);
      }
    });

    it('Scrypt types', async () => {
      const opt = { N: 1024, r: 8, p: 16, dkLen: 64 };
      scrypt('pwd', 'salt', opt);
      // N < 0 -> throws
      throws(() => scrypt('pwd', 'salt', { ...opt, N: -2 }), `scrypt(N=-2)`);
      await rejects(() => scryptAsync('pwd', 'salt', { ...opt, N: -2 }), `scrypt(N=-2)`);
      // N==0 -> throws (nodejs version is not, but it is against RFC)
      throws(() => scrypt('pwd', 'salt', { ...opt, N: 0 }), `scrypt(N=0)`);
      await rejects(() => scryptAsync('pwd', 'salt', { ...opt, N: 0 }), `scrypt(N=0)`);
      // N==1 -> throws
      throws(() => scrypt('pwd', 'salt', { ...opt, N: 1 }), `scrypt(N=1)`);
      // on progress callback
      throws(() => scrypt('pwd', 'salt', { ...opt, onProgress: true }));
      // P = 0
      throws(() => scrypt('pwd', 'salt', { ...opt, p: 0 }));
      await rejects(() => scryptAsync('pwd', 'salt', { ...opt, p: 0 }), `scrypt(p=0)`);
      throws(() => scrypt('pwd', 'salt', { ...opt, p: -1 }));
      throws(() => scrypt('pwd', 'salt', { ...opt, p: 2 ** 48 }));
      // dkLen
      throws(() => scrypt('pwd', 'salt', { ...opt, dkLen: -1 }));
      throws(() => scrypt('pwd', 'salt', { ...opt, dkLen: 2 ** 48 }));
      await rejects(() => scryptAsync('pwd', 'salt', { ...opt, N: 1 }), `scrypt(N=1)`);
      for (const t of TYPE_TEST.int) {
        for (const k of ['N', 'r', 'p', 'dkLen']) {
          throws(() => scrypt('pwd', 'salt', { ...opt, [k]: t }), fmt`scrypt(${k}=${t})`);
          await rejects(
            () => scryptAsync('pwd', 'salt', { ...opt, [k]: t }),
            fmt`scrypt(${k}=${t})`
          );
        }
        await rejects(
          () => scryptAsync('pwd', 'salt', { ...opt, asyncTick: t }),
          fmt`scrypt(asyncTick=${t})`
        );
      }
      for (const t of TYPE_TEST.bytes.concat([undefined])) {
        throws(() => scrypt('pwd', t, opt), fmt`scrypt(salt=${t})`);
        await rejects(() => scryptAsync('pwd', t, opt), fmt`scrypt(salt=${t})`);
        throws(() => scrypt(t, 'salt', opt), fmt`scrypt(pwd=${t})`);
        await rejects(() => scryptAsync(t, 'salt', opt), fmt`scrypt(pwd=${t})`);
      }
      for (const t of TYPE_TEST.opts) {
        throws(() => scrypt('pwd', 'salt', t), fmt`scrypt(opt=${t})`);
        await rejects(() => scryptAsync('pwd', 'salt', t), fmt`scrypt(opt=${t})`);
      }
      eql(scrypt(SPACE.str, SPACE.str, opt), scrypt(SPACE.bytes, SPACE.bytes, opt), 'scrypt.SPACE');
      eql(scrypt(EMPTY.str, EMPTY.str, opt), scrypt(EMPTY.bytes, EMPTY.bytes, opt), 'scrypt.EMPTY');
    });

    it('Scrypt maxmem', async () => {
      const opts = {
        N: 2 ** 10,
        r: 8,
        p: 16,
        dkLen: 64,
        maxmem: scryptMaxmem({ N: 2 ** 10, r: 8, p: 16 }),
      };
      scrypt('pwd', 'salt', opts);
      throws(() => scrypt('pwd', 'salt', { ...opts, maxmem: opts.maxmem - 1 }), {
        message: `"maxmem" limit was hit: memUsed(128*r*(N+p+1))=${opts.maxmem}, maxmem=${opts.maxmem - 1}`,
      });
      const maxmem2 = scryptMaxmem({ N: 2 ** 11, r: 8, p: 16 });
      throws(() => scrypt('pwd', 'salt', { ...opts, N: 2 ** 11 }), {
        message: `"maxmem" limit was hit: memUsed(128*r*(N+p+1))=${maxmem2}, maxmem=${opts.maxmem}`,
      });
    });

    if (variant === 'noble')
      it('Scrypt default maxmem accommodates N=2**20, r=8, p=1', async () => {
        const opts = { N: 2 ** 20, r: 8, p: 1 };
        const inputError = {
          name: 'TypeError',
          message: '"password" expected Uint8Array, got type=boolean',
        };
        // Invalid input fails immediately after the memory-limit check, avoiding a 1GiB allocation.
        throws(() => scrypt(true, 'salt', opts), inputError);
        await rejects(() => scryptAsync(true, 'salt', opts), inputError);

        const nextProfile = { ...opts, N: 2 ** 21 };
        const memUsed = scryptMaxmem(nextProfile);
        const defaultMaxmem = scryptMaxmem(opts);
        throws(() => scrypt('pwd', 'salt', nextProfile), {
          message: `"maxmem" limit was hit: memUsed(128*r*(N+p+1))=${memUsed}, maxmem=${defaultMaxmem}`,
        });
      });

    it('Scrypt boundary cross-test with node:crypto', async () => {
      // Runtimes without node:crypto scryptSync skip silently.
      if (typeof nodeCrypto.scryptSync !== 'function') return;
      // RFC vectors cover common parameters. These cases cheaply exercise smallest N, odd
      // BlockMix interleaving, large r/p independently, output-block edges and input lengths.
      const cases = [
        { N: 2, r: 1, p: 1, dkLen: 1, pwdLen: 0, saltLen: 0 },
        { N: 4, r: 2, p: 1, dkLen: 64, pwdLen: 3, saltLen: 4 },
        { N: 16, r: 3, p: 1, dkLen: 17, pwdLen: 3, saltLen: 4 },
        { N: 16, r: 5, p: 2, dkLen: 31, pwdLen: 3, saltLen: 4 },
        { N: 64, r: 3, p: 3, dkLen: 40, pwdLen: 3, saltLen: 4 },
        { N: 1024, r: 2, p: 2, dkLen: 33, pwdLen: 3, saltLen: 4 },
        { N: 4, r: 2, p: 1, dkLen: 31, pwdLen: 1, saltLen: 8 },
        { N: 16, r: 3, p: 2, dkLen: 32, pwdLen: 64, saltLen: 32 },
        { N: 32, r: 8, p: 3, dkLen: 33, pwdLen: 1023, saltLen: 1 },
        { N: 4, r: 127, p: 1, dkLen: 64, pwdLen: 32, saltLen: 1023 },
        { N: 4, r: 1, p: 127, dkLen: 65, pwdLen: 1023, saltLen: 32 },
        { N: 2, r: 1023, p: 1, dkLen: 127, pwdLen: 256, saltLen: 64 },
        { N: 2, r: 1, p: 1023, dkLen: 128, pwdLen: 64, saltLen: 256 },
        { N: 512, r: 8, p: 1, dkLen: 1023, pwdLen: 1023, saltLen: 1023 },
      ];
      for (const { pwdLen, saltLen, ...opts } of cases) {
        const pwd = RANDOM.subarray(0, pwdLen);
        const salt = RANDOM.subarray(RANDOM.length - saltLen);
        const node = Uint8Array.from(
          nodeCrypto.scryptSync(pwd, salt, opts.dkLen, { ...opts, maxmem: 64 * 1024 * 1024 })
        );
        eql(scrypt(pwd, salt, opts), node, fmt`scrypt(${opts})`);
        eql(await scryptAsync(pwd, salt, opts), node, fmt`scryptAsync(${opts})`);
      }
    });

    it('Scrypt rejects r=0 with clear error', async () => {
      // Previously r=0 slipped through validation (blockSize=0 made the p bound
      // Infinity) and failed later inside pbkdf2 with a confusing dkLen error.
      throws(() => scrypt('pwd', 'salt', { N: 16, r: 0, p: 1, dkLen: 32 }), /"r" expected/);
      await rejects(
        () => scryptAsync('pwd', 'salt', { N: 16, r: 0, p: 1, dkLen: 32 }),
        /"r" expected/
      );
    });
  });

  describe(`KDF (${variant})`, () => {
    if (variant === 'noble')
      it('wipes library-owned UTF-8 input copies without touching caller bytes', () => {
        const expected = {
          'pb-password-owned-marker': 2,
          'pb-salt-owned-marker': 2,
          'sc-password-owned-marker': 4,
          'sc-salt-owned-marker': 2,
          'abort-password-owned-marker': 2,
          'abort-salt-owned-marker': 2,
          'ar-password-owned-marker': 2,
          'ar-salt-owned-marker': 2,
          'ar-key-owned-marker': 2,
          'ar-pers-owned-marker': 2,
          'invalid-password-owned-marker': 2,
          'invalid-salt-owned-marker': 2,
        };
        const markers = new Set(Object.keys(expected));
        const wiped = Object.fromEntries([...markers].map((marker) => [marker, 0]));
        const fill = Uint8Array.prototype.fill;
        Uint8Array.prototype.fill = function (value, start, end) {
          if (value === 0 && this.length < 128) {
            let text = '';
            for (const byte of this) text += String.fromCharCode(byte);
            if (markers.has(text)) wiped[text]++;
          }
          return fill.call(this, value, start, end);
        };
        try {
          pbkdf2(sha256, 'pb-password-owned-marker', 'pb-salt-owned-marker', { c: 1 });
          scrypt('sc-password-owned-marker', 'sc-salt-owned-marker', { N: 16, r: 1, p: 1 });
          throws(
            () =>
              scrypt('abort-password-owned-marker', 'abort-salt-owned-marker', {
                N: 16,
                r: 1,
                p: 1,
                onProgress() {
                  throw new Error('stop');
                },
              }),
            /stop/
          );
          argon2id('ar-password-owned-marker', 'ar-salt-owned-marker', {
            t: 1,
            m: 32,
            p: 1,
            key: 'ar-key-owned-marker',
            personalization: 'ar-pers-owned-marker',
          });
          throws(
            () =>
              argon2id('invalid-password-owned-marker', 'invalid-salt-owned-marker', {
                t: 0,
                m: 32,
                p: 1,
              }),
            /"t"/
          );
        } finally {
          Uint8Array.prototype.fill = fill;
        }
        // Each conversion wipes TextEncoder's temporary and the current-realm copy. Scrypt
        // converts its password once for each of its two internal PBKDF2 invocations.
        eql(wiped, expected);

        const callerPassword = utf8ToBytes('caller-password-marker');
        const callerSalt = utf8ToBytes('caller-salt-marker');
        const callerKey = utf8ToBytes('caller-key-marker');
        const callerPers = utf8ToBytes('caller-pers-marker');
        const snapshots = [callerPassword, callerSalt, callerKey, callerPers].map((i) => i.slice());
        pbkdf2(sha256, callerPassword, callerSalt, { c: 1 });
        scrypt(callerPassword, callerSalt, { N: 16, r: 1, p: 1 });
        argon2id(callerPassword, callerSalt, {
          t: 1,
          m: 32,
          p: 1,
          key: callerKey,
          personalization: callerPers,
        });
        eql([callerPassword, callerSalt, callerKey, callerPers], snapshots);
      });

    it('progress 100%', async () => {
      const scryptOpts = { N: 16, r: 1, p: 1, dkLen: 32 };
      await progress1((onProgress) => scrypt('pwd', 'salt', { ...scryptOpts, onProgress }));
      await progress1((onProgress) => scryptAsync('pwd', 'salt', { ...scryptOpts, onProgress }));
      const argonOpts = { t: 1, m: 256, p: 1 };
      await progress1((onProgress) =>
        argon2id('password', 'diffsalt', { ...argonOpts, onProgress })
      );
      await progress1((onProgress) =>
        argon2idAsync('password', 'diffsalt', { ...argonOpts, onProgress })
      );
    });

    it('output length', async () => {
      const outlen = async (
        sync: (len: number) => Uint8Array,
        async: undefined | ((len: number) => Promise<Uint8Array>) = undefined,
        min = 1
      ) => {
        for (let len = 0; len < min; len++) {
          throws(() => sync(len));
          if (async) await rejects(() => async(len));
        }
        for (let len = min; len <= 128; len++) {
          eql(sync(len).length, len);
          if (async) eql((await async(len)).length, len);
        }
      };
      await outlen((len) => hkdf(sha256, EMPTY.bytes, EMPTY.bytes, EMPTY.bytes, len), undefined, 0);
      await outlen(
        (len) => pbkdf2(sha256, 'pwd', 'salt', { c: 1, dkLen: len }),
        (len) => pbkdf2Async(sha256, 'pwd', 'salt', { c: 1, dkLen: len })
      );
      await outlen(
        (len) => scrypt('pwd', 'salt', { N: 16, r: 1, p: 1, dkLen: len }),
        (len) => scryptAsync('pwd', 'salt', { N: 16, r: 1, p: 1, dkLen: len })
      );
      await outlen(
        (len) => argon2id('password', 'diffsalt', { t: 1, m: 256, p: 1, dkLen: len }),
        (len) => argon2idAsync('password', 'diffsalt', { t: 1, m: 256, p: 1, dkLen: len }),
        4
      );
    });
  });

  describe(`PBKDF2 (${variant})`, () => {
    for (let i = 0; i < PBKDF2_VECTORS.length; i++) {
      const t = PBKDF2_VECTORS[i];
      it(`PBKDF2 vector (${i})`, async () => {
        const exp = hexToBytes(t.exp.replace(/ /g, ''));
        eql(pbkdf2(t.hash, t.P, t.S, t), exp);
        eql(await pbkdf2Async(t.hash, t.P, t.S, t), exp);
      });
    }

    if (variant === 'noble')
      for (const [name, fn] of [
        ['pbkdf2', pbkdf2],
        ['pbkdf2Async', pbkdf2Async],
      ]) {
        it(`${name} prehashes a long password once`, async () => {
          const shortPassword = RANDOM.subarray(0, 32);
          const longPassword = RANDOM.subarray(0, 64 * 1024);
          const salt = RANDOM.subarray(128 * 1024, 129 * 1024);
          const shortOne = await pbkdf2Work(fn, sha256, shortPassword, salt, 1);
          const shortMany = await pbkdf2Work(fn, sha256, shortPassword, salt, 128);
          const longOne = await pbkdf2Work(fn, sha256, longPassword, salt, 1);
          const longMany = await pbkdf2Work(fn, sha256, longPassword, salt, 128);

          eql(shortMany.output, pbkdf2(sha256, shortPassword, salt, { c: 128, dkLen: 32 }));
          eql(longMany.output, pbkdf2(sha256, longPassword, salt, { c: 128, dkLen: 32 }));
          // Iteration work must not depend on password length.
          eql(longMany.bytes - longOne.bytes, shortMany.bytes - shortOne.bytes);
          // A key larger than blockLen is hashed once during HMAC setup.
          eql(longOne.bytes - shortOne.bytes, longPassword.length);
        });
      }

    it('PBKDF2Async absorbs byte salt before yielding', async () => {
      const cases = [
        {
          hash: sha256,
          salt: Uint8Array.of(1, 2, 3, 4),
          expected:
            '2fac29057c64f73cc15578ec5f482792f9869bd7fe1571eac74331aa35715a5e' +
            'a40c93daa5dd802eddc5b23bc4abc1342460cd84aa2e8813cfeda823e0d32095',
        },
        {
          hash: sha256,
          salt: Uint8Array.from({ length: 64 }, (_, i) => i + 1),
          expected:
            '73564b8d63bb62cc5b60265f87f4455eb783f5a881d436397c2270ea3db5e507' +
            '4b9176ee42c038d777d283314ec329a35d60b03839830d274c8d806bc499a6a1',
        },
        {
          hash: sha256,
          salt: Uint8Array.from({ length: 65 }, (_, i) => i + 1),
          expected:
            '387f239b2263251d6f081aca9957f98bbf0c44d5851730aa1952288d5f8ca794' +
            '841e3d5514fcfc86ca71b56871e47660eca3c0799a6d74e72efd34871af8eea8',
        },
        {
          hash: blake2s,
          salt: Uint8Array.from({ length: 64 }, (_, i) => i + 1),
          expected:
            '8b015dfa76a01c3d9b77632e3fdc62578dbf11c9479f88d762a4bb36096edb62' +
            '37e80ce94466de17606b156f0acfd9640ec601ee89a47494118e88306b670b99',
        },
        {
          hash: blake2s,
          salt: Uint8Array.from({ length: 65 }, (_, i) => i + 1),
          expected:
            'b79c6f6bdfda90af80aa3a8f4b6b37f9fc3c97a7d0fd128ae229281fbe29b0e8' +
            '5bbfadd5131212e2df9389659ee2abc5f519670dd2bf8052fd9feabbaae4ce3e',
        },
      ];
      for (const { hash, salt, expected } of cases) {
        const pending = pbkdf2Async(hash, 'password', salt, {
          c: 1,
          dkLen: 64,
          asyncTick: 0,
        });
        // Two output blocks force an await between U1 computations. The boundary cases also
        // exercise the private salted clone and BLAKE2's lazy pending full block.
        salt.fill(9);
        eql(await pending, hexToBytes(expected));
      }
    });
    it('PBKDF2-KT128/KT256 reuse workers across a tree-boundary salt', () => {
      const password = Uint8Array.from({ length: 3 }, (_, i) => (i * 29 + 17) & 255);
      // The HMAC inner block plus this salt lands on K12's 8192-byte tree boundary, so deriving
      // a second output block exercises the cached leaf state after the PBKDF2 worker is reset.
      // Expected outputs were independently verified with XKCP and PyCryptodome primitives.
      for (const [name, hash, expected] of [
        [
          'KT128',
          kt128,
          '81d2d71d547c3869bd484d42437c3e44ae0b76c94ea3c60f6de598b7903882ae' +
            '2080b51b559f30502ee6bd4bfd6ce9c1a813b2ea6cb975258d7cbf94c83e0bdf',
        ],
        [
          'KT256',
          kt256,
          'd4a9e74d87eb40feb3accf839885c6f78d2ddd522230528ab2001165480a1c9a' +
            '7c80f6255588961b5be102ed8dce3e0645768916f43fa3eae05453498c28a488' +
            '43ef60effd5d550abbc210c7e09b19ef76b74828a93bb9c9d0066f560fac7df2' +
            '73e15893e10eaf8e06a9f581bc042a3fca1634e27b71dc3834d05893acd538f7',
        ],
      ] as const) {
        const salt = Uint8Array.from(
          { length: 8192 - hash.blockLen },
          (_, i) => (i * 29 + 17) & 255
        );
        eql(
          pbkdf2(hash, password, salt, { c: 1, dkLen: hash.outputLen * 2 }),
          hexToBytes(expected),
          name
        );
      }
    });
    it('PBKDF2 types', async () => {
      const opts = { c: 10, dkLen: 32 };
      pbkdf2(sha256, 'pwd', 'salt', opts);
      throws(() => pbkdf2(sha256, 'pwd', 'salt', { c: 0, dkLen: 32 }), `pbkdf2(c=0)`);
      await rejects(() => pbkdf2Async(sha256, 'pwd', 'salt', { c: 0, dkLen: 32 }), `pbkdf2(c=0)`);
      const fakeHash = Object.assign((_msg: Uint8Array) => new Uint8Array([0]), {
        outputLen: 1,
        blockLen: 1,
        create() {
          throw new Error('pbkdf2 should reject dkLen before constructing PRF state');
        },
      });
      throws(
        () => pbkdf2(fakeHash as any, EMPTY.bytes, EMPTY.bytes, { c: 1, dkLen: 2 ** 40 }),
        /derived key too long/i
      );
      for (const t of TYPE_TEST.int) {
        throws(() => pbkdf2(sha256, 'pwd', 'salt', { ...opts, c: t }), fmt`pbkdf2(c=${t})`);
        await rejects(
          () => pbkdf2Async(sha256, 'pwd', 'salt', { ...opts, c: t }),
          fmt`pbkdf2(c=${t})`
        );
        throws(() => pbkdf2(sha256, 'pwd', 'salt', { ...opts, dkLen: t }), fmt`pbkdf2(dkLen=${t})`);
        await rejects(
          () => pbkdf2Async(sha256, 'pwd', 'salt', { ...opts, dkLen: t }),
          fmt`pbkdf2(dkLen=${t})`
        );
        await rejects(
          () => pbkdf2Async(sha256, 'pwd', 'salt', { ...opts, asyncTick: t }),
          fmt`pbkdf2(asyncTick=${t})`
        );
      }
      for (const t of TYPE_TEST.bytes.concat([undefined])) {
        throws(() => pbkdf2(sha256, t, 'salt', opts), fmt`pbkdf2(pwd=${t})`);
        await rejects(() => pbkdf2Async(sha256, t, 'salt', opts), fmt`pbkdf2(pwd=${t})`);
        throws(() => pbkdf2(sha256, 'pwd', t, opts), fmt`pbkdf2(salt=${t})`);
        await rejects(() => pbkdf2Async(sha256, 'pwd', t, opts), fmt`pbkdf2(salt=${t})`);
      }
      for (const t of TYPE_TEST.opts) {
        throws(() => pbkdf2(sha256, 'pwd', 'salt', t), fmt`pbkdf2(opt=${t})`);
        await rejects(() => pbkdf2Async(sha256, 'pwd', 'salt', t), fmt`pbkdf2(opt=${t})`);
      }
      for (const t of TYPE_TEST.hash) {
        throws(() => pbkdf2(t, 'pwd', 'salt', t), fmt`pbkdf2(hash=${t})`);
        await rejects(() => pbkdf2Async(t, 'pwd', 'salt', t), fmt`pbkdf2(hash=${t})`);
      }
      eql(
        pbkdf2(sha256, SPACE.str, SPACE.str, opts),
        pbkdf2(sha256, SPACE.bytes, SPACE.bytes, opts),
        'pbkdf2.SPACE'
      );
      eql(
        pbkdf2(sha256, EMPTY.str, EMPTY.str, opts),
        pbkdf2(sha256, EMPTY.bytes, EMPTY.bytes, opts),
        'pbkdf2.EMPTY'
      );
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  for (const k in PLATFORMS) test(k, PLATFORMS[k]);
  for (const k in PLATFORMS) executeKDFTests(k, PLATFORMS[k], true);
}

it.runWhen(import.meta.url);
