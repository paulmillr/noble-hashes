const assert = require('assert');
const { should } = require('micro-should');
const { blake3 } = require('../lib/blake3');
const {
  k12,
  cshake128,
  cshake256,
  kmac128,
  kmac256,
  parallelhash128,
  parallelhash256,
  tuplehash128,
  tuplehash256,
} = require('../lib/sha3-addons');
const { jsonGZ } = require('./utils.js');
const vectors = jsonGZ('vectors/sha3-addons.json.gz').v;

const fromHex = (hex) => (hex ? Uint8Array.from(Buffer.from(hex, 'hex')) : new Uint8Array([]));

const tupleData = (hex) => {
  const data = fromHex(hex);
  const tuples = [];
  for (let i = 0; i < data.length; i++) tuples.push(data.slice(0, i));
  return tuples;
};

should(`pass generated test vectors`, () => {
  for (let i = 0; i < vectors.length; i++) {
    const v = vectors[i];
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
      blake3: () => blake3(fromHex(v.data), opt),
      parallel128: () => parallelhash128(fromHex(v.data), opt),
      parallel256: () => parallelhash256(fromHex(v.data), opt),
      tuple128: () => tuplehash128(tupleData(v.data), opt),
      tuple256: () => tuplehash256(tupleData(v.data), opt),
    };
    let err = `(${i}): ${v.fn_name}`;
    assert.deepStrictEqual(Buffer.from(fn[v.fn_name]()).toString('hex'), v.exp, err);
  }
});

if (require.main === module) should.run();
