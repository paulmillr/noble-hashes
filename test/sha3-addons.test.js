const assert = require('assert');
const { should } = require('micro-should');
const { blake3 } = require('../lib/blake3');
const { k12, cshake128, cshake256, kmac128, kmac256 } = require('../lib/sha3-addons');
const vectors = require('./vectors/sha3-addons.json').v;

const fromHex = (hex) => (hex ? Uint8Array.from(Buffer.from(hex, 'hex')) : new Uint8Array([]));

for (let i = 0; i < vectors.length; i++) {
  should(`genTest (${i})`, () => {
    const v = vectors[i];
    const fn = {
      cshake128: () =>
        cshake128(fromHex(v.data), {
          personalization: fromHex(v.personalization),
          NISTfn: fromHex(v.NISTfn),
          dkLen: v.exp.length / 2,
        }),
      cshake256: () =>
        cshake256(fromHex(v.data), {
          personalization: fromHex(v.personalization),
          NISTfn: fromHex(v.NISTfn),
          dkLen: v.exp.length / 2,
        }),
      kmac128: () =>
        kmac128(fromHex(v.key), fromHex(v.data), {
          personalization: fromHex(v.personalization),
          dkLen: v.exp.length / 2,
        }),
      kmac256: () =>
        kmac256(fromHex(v.key), fromHex(v.data), {
          personalization: fromHex(v.personalization),
          dkLen: v.exp.length / 2,
        }),
      k12: () =>
        k12(fromHex(v.data), {
          personalization: fromHex(v.personalization),
          dkLen: v.exp.length / 2,
        }),
      blake3: () => blake3(fromHex(v.data), { dkLen: v.exp.length / 2 }),
    };
    assert.deepStrictEqual(Buffer.from(fn[v.fn_name]()).toString('hex'), v.exp);
  });
}

if (require.main === module) should.run();
