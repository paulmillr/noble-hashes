const assert = require('assert');
const { should } = require('micro-should');
const { sha256 } = require('../sha256');
const { sha512 } = require('../sha512');
const { hmac } = require('../hmac');
const { sha3_256, shake256 } = require('../sha3');
const { k12, kmac256, prg } = require('../sha3-addons');
const { blake2b } = require('../blake2b');
const { blake2s } = require('../blake2s');
const { blake3, blake3derive } = require('../blake3');
const { ripemd160 } = require('../ripemd160');

// small -- minimal personalization options, big -- all personalization options
// test that clone works correctly if "to" is same class instance but with completely different personalization
const HASHES = {
  sha256: { small: () => sha256.init() },
  sha512: { small: () => sha512.init() },
  ripemd160: { small: () => ripemd160.init() },
  sha3: { small: () => sha3_256.init() },
  shake256: {
    small: () => shake256.init(),
    big: () => shake256.init({ dkLen: 256 }),
  },
  shake256: {
    small: () => shake256.init(),
    big: () => shake256.init({ dkLen: 256 }),
  },
  hmac: {
    small: () => hmac.init(sha256, new Uint8Array([5, 4, 3, 2, 1])),
    big: () => hmac.init(sha256, new Uint8Array([1, 2, 3, 4, 5])),
  },
  kmac: {
    small: () => kmac256.init(new Uint8Array([])),
    big: () =>
      kmac256.init(new Uint8Array([11, 22, 33]), { personalization: new Uint8Array([44, 55, 66]) }),
  },
  k12: {
    small: () => k12.init(new Uint8Array([])),
    big: () =>
      k12.init(new Uint8Array([11, 22, 33]), {
        personalization: new Uint8Array([44, 55, 66]),
        dkLen: 256,
      }),
  },
  blake2s: {
    small: () => blake2s.init(),
    big: () =>
      blake2s.init({
        key: new Uint8Array([11, 22, 33]),
        salt: new Uint8Array([14, 15, 16, 17, 18, 19, 155, 144]),
        personalization: new Uint8Array([24, 25, 26, 27, 28, 29, 255, 244]),
        dkLen: 12,
      }),
  },
  blake2b: {
    small: () => blake2b.init(),
    big: () =>
      blake2b.init({
        key: new Uint8Array([11, 22, 33]),
        salt: new Uint8Array([14, 15, 16, 17, 18, 19, 155, 144, 144, 155, 19, 18, 17, 16, 15, 14]),
        personalization: new Uint8Array([
          24, 25, 26, 27, 28, 29, 255, 244, 244, 255, 29, 28, 27, 26, 25, 24,
        ]),
        dkLen: 12,
      }),
  },
  blake3: {
    small: () => blake3.init(),
    // derive has different IV
    big: () => blake3.init({ context: 'someContext', dkLen: 256 }),
  },
};

for (let k in HASHES) {
  const small = HASHES[k].small;
  const big = HASHES[k].big || HASHES[k].small;
  const smallExp = small()
    .update(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    .digest();
  const bigExp = big()
    .update(new Uint8Array([10, 9, 8, 7, 6, 5, 4, 3, 2, 1]))
    .digest();

  should(`Clone ${k}: just clone small`, () => {
    const s1 = small().update(new Uint8Array([1, 2, 3, 4, 5]));
    const s2 = s1
      ._cloneInto()
      .update(new Uint8Array([6, 7, 8, 9, 10]))
      .digest();
    assert.deepStrictEqual(s2, smallExp, 's2 correct');
    // Original is not modified
    assert.deepStrictEqual(
      s1.digest(),
      small()
        .update(new Uint8Array([1, 2, 3, 4, 5]))
        .digest(),
      's1 same'
    );
  });
  should(`Clone ${k}: just clone big`, () => {
    const b1 = big().update(new Uint8Array([10, 9, 8, 7, 6]));
    const b2 = b1
      ._cloneInto()
      .update(new Uint8Array([5, 4, 3, 2, 1]))
      .digest();
    assert.deepStrictEqual(b2, bigExp, 'b2 correct');
    // Original is not modified
    assert.deepStrictEqual(
      b1.digest(),
      big()
        .update(new Uint8Array([10, 9, 8, 7, 6]))
        .digest(),
      'b1 same'
    );
  });
  should(`Clone ${k}: small<->big`, () => {
    const s1 = small().update(new Uint8Array([1, 2, 3, 4, 5]));
    const s2 = small().update(new Uint8Array([1, 2, 3, 4, 5]));
    const b1 = big().update(new Uint8Array([10, 9, 8, 7, 6]));
    const b2 = big().update(new Uint8Array([10, 9, 8, 7, 6]));
    b1._cloneInto(s2);
    assert.deepStrictEqual(b1, s2, 'b1===s2');
    s1._cloneInto(b2);
    assert.deepStrictEqual(s1, b2, 'b1===b2');
    assert.deepStrictEqual(s2.update(new Uint8Array([5, 4, 3, 2, 1])).digest(), bigExp, 's2===big');
    assert.deepStrictEqual(
      b2.update(new Uint8Array([6, 7, 8, 9, 10])).digest(),
      smallExp,
      'b2===small'
    );
    // Original is not modified
    assert.deepStrictEqual(
      b1.digest(),
      big()
        .update(new Uint8Array([10, 9, 8, 7, 6]))
        .digest(),
      'b1 same'
    );
    assert.deepStrictEqual(
      s1.digest(),
      small()
        .update(new Uint8Array([1, 2, 3, 4, 5]))
        .digest(),
      's1 same'
    );
  });
}

if (require.main === module) should.run();
