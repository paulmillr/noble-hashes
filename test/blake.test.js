const { deepStrictEqual, throws } = require('assert');
const { describe, should } = require('micro-should');
const { blake2b } = require('../blake2b');
const { blake2s } = require('../blake2s');
const { TYPE_TEST, pattern, concatBytes } = require('./utils');
const blake2_vectors = require('./vectors/blake2-kat.json');
const blake2_python = require('./vectors/blake2-python.json');
const blake3_vectors = require('./vectors/blake3.json');
const { blake3 } = require('../blake3');
const { hexToBytes, bytesToHex } = require('../utils');

should('Blake2 vectors', () => {
  for (const v of blake2_vectors) {
    const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
    if (!hash) continue;
    const [input, exp] = [v.in, v.out].map(hexToBytes);
    const key = v.key ? hexToBytes(v.key) : undefined;
    deepStrictEqual(hash(input, { key }), exp);
  }
});
// NodeJS blake2 doesn't support personalization and salt, so we generated vectors using python: see vectors/blake2-gen.py
should('Blake2 python', () => {
  for (const v of blake2_python) {
    const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
    const opt = { dkLen: v.dkLen };
    if (v.person) opt.personalization = hexToBytes(v.person);
    if (v.salt) opt.salt = hexToBytes(v.salt);
    if (v.key) opt.key = hexToBytes(v.key);
    deepStrictEqual(bytesToHex(hash('data', opt)), v.digest);
  }
});

should('BLAKE2s: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) throws(() => blake2s('test', { dkLen }));
  throws(() => blake2s('test', { dkLen: 33 }));
});

should('BLAKE2b: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) throws(() => blake2b('test', { dkLen }));
  throws(() => blake2b('test', { dkLen: 65 }));
});

should(`BLAKE2s: key`, () => {
  for (const key of TYPE_TEST.bytes) throws(() => blake2s.fn('data', { key }));
  throws(() => blake2s.fn('data', { key: new Uint8Array(33) }));
});

should(`BLAKE2b: key`, () => {
  for (const key of TYPE_TEST.bytes) throws(() => blake2b.fn('data', { key }));
  throws(() => blake2b.fn('data', { key: new Uint8Array(65) }));
});

should(`BLAKE2s: personalization/salt`, () => {
  for (const t of TYPE_TEST.bytes) {
    throws(() => blake2s.fn('data', { personalization: t }));
    throws(() => blake2s.fn('data', { salt: t }));
  }
  for (let i = 0; i < 64; i++) {
    if (i == 8) continue;
    throws(() => blake2s.fn('data', { personalization: Uint8Array(i) }));
    throws(() => blake2s.fn('data', { salt: Uint8Array(i) }));
  }
});

should(`BLAKE2b: personalization/salt`, () => {
  for (const t of TYPE_TEST.bytes) {
    throws(() => blake2b.fn('data', { personalization: t }));
    throws(() => blake2b.fn('data', { salt: t }));
  }
  for (let i = 0; i < 64; i++) {
    if (i == 16) continue;
    throws(() => blake2b.fn('data', { personalization: Uint8Array(i) }));
    throws(() => blake2b.fn('data', { salt: Uint8Array(i) }));
  }
});

describe('BLAKE3', () => {
  should('BLAKE3: dkLen', () => {
    for (const dkLen of TYPE_TEST.int) throws(() => blake3('test', { dkLen }));
  });

  should('vectors', () => {
    for (let i = 0; i < blake3_vectors.cases.length; i++) {
      const v = blake3_vectors.cases[i];
      const res_hash = blake3(pattern(0xfa, v.input_len), { dkLen: v.hash.length / 2 });
      deepStrictEqual(bytesToHex(res_hash), v.hash, `Blake3 ${i} (hash)`);
      const res_keyed = blake3(pattern(0xfa, v.input_len), {
        key: blake3_vectors.key,
        dkLen: v.hash.length / 2,
      });
      deepStrictEqual(bytesToHex(res_keyed), v.keyed_hash, `Blake3 ${i} (keyed)`);
      const res_derive = blake3(pattern(0xfa, v.input_len), {
        context: blake3_vectors.context_string,
        dkLen: v.hash.length / 2,
      });
      deepStrictEqual(bytesToHex(res_derive), v.derive_key, `Blake3 ${i} (derive)`);
    }
  });

  should('Blake3 XOF', () => {
    // XOF ok on xof instances
    blake3.create().xof(10);
    throws(() => {
      const h = blake3.create();
      h.xof(10);
      h.digest();
    }, 'digest after XOF');
    throws(() => {
      const h = blake3.create();
      h.digest();
      h.xof(10);
    }, 'XOF after digest');
    const bigOut = blake3('', { dkLen: 130816 });
    const hashxof = blake3.create();
    const out = [];
    for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
    deepStrictEqual(concatBytes(...out), bigOut, 'xof check against fixed size');
  });
});

should('BLAKE2b inputs are immuatable', () => {
  const msg = new Uint8Array([1, 2, 3, 4]);
  const key = new Uint8Array([1, 2, 3, 4]);
  const pers = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
  blake2b(msg, { key, salt, personalization: pers });
  deepStrictEqual(msg, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(key, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(pers, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
  deepStrictEqual(salt, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
});

should('BLAKE2s inputs are immuatable', () => {
  const msg = new Uint8Array([1, 2, 3, 4]);
  const key = new Uint8Array([1, 2, 3, 4]);
  const pers = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  blake2s(msg, { key, salt, personalization: pers });
  deepStrictEqual(msg, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(key, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(pers, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
  deepStrictEqual(salt, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
});

should('BLAKE3 inputs are immuatable', () => {
  const msg = new Uint8Array([1, 2, 3, 4]);
  const ctx = new Uint8Array([1, 2, 3, 4]);
  const key = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
  ]);
  blake3(msg, { key });
  blake3(msg, { context: ctx });
  deepStrictEqual(msg, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(ctx, new Uint8Array([1, 2, 3, 4]));
  deepStrictEqual(
    key,
    new Uint8Array([
      1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7,
      8,
    ])
  );
});

if (require.main === module) should.run();
