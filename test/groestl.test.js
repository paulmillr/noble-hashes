const assert = require('assert');
const { should } = require('micro-should');
const { groestl512 } = require('../groestl512');
const groestl512_vectors = require('./vectors/groestl512.json');
const { groestl256 } = require('../groestl256');

should('groestl vectors', () => {
  for (const v of groestl512_vectors) {
    const hash = { groestl512: groestl512, groestl256: groestl256 }[v.hash];
    if (!hash) continue;
    const [input] = [v.in].map((i) => Uint8Array.from(Buffer.from(i)));
    const [exp] = [v.out].map((i) => Uint8Array.from(Buffer.from(i, 'hex')));
    assert.deepStrictEqual(hash(input), exp);
  }
});

should('groest_2 test', () => {
  const msg =
    'Groestl is an Austrian dish, usually made of leftover potatoes and pork, cut into slice.';
  const actualHash = groestl256(groestl512(msg));
  const expectedHash = Uint8Array.from(
    Buffer.from('55415989225c5c902f5003679a98fac117555890a7c3119ab1d570c89e77b072', 'hex')
  );
  assert.deepStrictEqual(actualHash, expectedHash);
});

should('GROESTL512 inputs are immutable', () => {
  const msg = new Uint8Array([1, 2, 3, 4]);
  groestl512(msg);
  assert.deepStrictEqual(msg, new Uint8Array([1, 2, 3, 4]));
});

if (require.main === module) should.run();
