const assert = require('assert');
const { should } = require('micro-should');
const { blake2b } = require('../blake2b');
const { blake2s } = require('../blake2s');
const { TYPE_TEST, pattern, concatBytes } = require('./utils');
const blake2_vectors = require('./vectors/blake2-kat.json');
const blake2_python = require('./vectors/blake2-python.json');
const blake3_vectors = require('./vectors/blake3.json');
const { blake3 } = require('../blake3');

should('Blake2 vectors', () => {
  for (const v of blake2_vectors) {
    const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
    if (!hash) continue;
    const [input, exp] = [v.in, v.out].map((i) => Uint8Array.from(Buffer.from(i, 'hex')));
    const key = v.key ? Uint8Array.from(Buffer.from(v.key, 'hex')) : undefined;
    assert.deepStrictEqual(hash(input, { key }), exp);
  }
});
// NodeJS blake2 doesn't support personalization and salt, so we generated vectors using python: see vectors/blake2-gen.py
should('Blake2 python', () => {
  for (const v of blake2_python) {
    const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
    const opt = { dkLen: v.dkLen };
    if (v.person) opt.personalization = Uint8Array.from(Buffer.from(v.person, 'hex'));
    if (v.salt) opt.salt = Uint8Array.from(Buffer.from(v.salt, 'hex'));
    if (v.key) opt.key = Uint8Array.from(Buffer.from(v.key, 'hex'));
    assert.deepStrictEqual(Buffer.from(hash('data', opt)).toString('hex'), v.digest);
  }
});

should('BLAKE2s: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) assert.throws(() => blake2s('test', { dkLen }));
  assert.throws(() => blake2s('test', { dkLen: 33 }));
});

should('BLAKE2b: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) assert.throws(() => blake2b('test', { dkLen }));
  assert.throws(() => blake2b('test', { dkLen: 65 }));
});

should(`BLAKE2s: key`, () => {
  for (const key of TYPE_TEST.bytes) assert.throws(() => blake2s.fn('data', { key }));
  assert.throws(() => blake2s.fn('data', { key: new Uint8Array(33) }));
});

should(`BLAKE2b: key`, () => {
  for (const key of TYPE_TEST.bytes) assert.throws(() => blake2b.fn('data', { key }));
  assert.throws(() => blake2b.fn('data', { key: new Uint8Array(65) }));
});

should(`BLAKE2s: personalization/salt`, () => {
  for (const t of TYPE_TEST.bytes) {
    assert.throws(() => blake2s.fn('data', { personalization: t }));
    assert.throws(() => blake2s.fn('data', { salt: t }));
  }
  for (let i = 0; i < 64; i++) {
    if (i == 8) continue;
    assert.throws(() => blake2s.fn('data', { personalization: Uint8Array(i) }));
    assert.throws(() => blake2s.fn('data', { salt: Uint8Array(i) }));
  }
});

should(`BLAKE2b: personalization/salt`, () => {
  for (const t of TYPE_TEST.bytes) {
    assert.throws(() => blake2b.fn('data', { personalization: t }));
    assert.throws(() => blake2b.fn('data', { salt: t }));
  }
  for (let i = 0; i < 64; i++) {
    if (i == 16) continue;
    assert.throws(() => blake2b.fn('data', { personalization: Uint8Array(i) }));
    assert.throws(() => blake2b.fn('data', { salt: Uint8Array(i) }));
  }
});

should('BLAKE3: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) assert.throws(() => blake3('test', { dkLen }));
});

for (let i = 0; i < blake3_vectors.cases.length; i++) {
  const v = blake3_vectors.cases[i];
  should(`Blake3 ${i} (hash)`, () => {
    const res = blake3(pattern(0xfa, v.input_len), { dkLen: v.hash.length / 2 });
    assert.deepStrictEqual(Buffer.from(res).toString('hex'), v.hash);
  });
  should(`Blake3 ${i} (keyed)`, () => {
    const res = blake3(pattern(0xfa, v.input_len), {
      key: blake3_vectors.key,
      dkLen: v.hash.length / 2,
    });
    assert.deepStrictEqual(Buffer.from(res).toString('hex'), v.keyed_hash);
  });
  should(`Blake3 ${i} (derive)`, () => {
    const res = blake3(pattern(0xfa, v.input_len), {
      context: blake3_vectors.context_string,
      dkLen: v.hash.length / 2,
    });
    assert.deepStrictEqual(Buffer.from(res).toString('hex'), v.derive_key);
  });
}

should('Blake3 XOF', () => {
  // XOF ok on xof instances
  blake3.create().xof(10);
  assert.throws(() => {
    const h = blake3.create();
    h.xof(10);
    h.digest();
  }, 'digest after XOF');
  assert.throws(() => {
    const h = blake3.create();
    h.digest();
    h.xof(10);
  }, 'XOF after digest');
  const bigOut = blake3('', { dkLen: 130816 });
  const hashxof = blake3.create();
  const out = [];
  for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
  assert.deepStrictEqual(concatBytes(...out), bigOut, 'xof check against fixed size');
});

if (require.main === module) should.run();
