const assert = require('assert');
const { should } = require('micro-should');
const { eskdf } = require('../eskdf');
const vectors = require('./vectors/eskdf.json');

function toHex(arr) {
  let hex = '';
  for (let i = 0; i < arr.length; i++) {
    hex += arr[i].toString(16).padStart(2, '0');
  }
  return hex;
}

(async () => {
  for (let v of vectors.derive_main_seed.valid) {
    const { output, fingerprint, username, password } = v;
    should(`deriveMainSeed ${fingerprint}`, async () => {
      const keyc = await eskdf(username, password);
      // assert.equal(toHex(seed), output);
      assert.equal(keyc.fingerprint, fingerprint);
    });
  }
  for (let v of vectors.derive_main_seed.invalid) {
    const { username, password } = v;
    should(`deriveMainSeed errors on ${username} ${password}`, async () => {
      await assert.rejects(() => eskdf(username, password));
    });
  }
  const { username, password } = vectors.derive_child_key.seed;
  const e = await eskdf(username, password);
  for (let v of vectors.derive_child_key.valid) {
    const { output, protocol, account_id, key_length, modulus } = v;
    const opt =
      key_length != null
        ? { keyLength: key_length }
        : modulus != null
          ? { modulus: BigInt('0x' + modulus) }
          : undefined;
    should(`deriveChildKey ${protocol} ${output}`, () => {
      const key = e.deriveChildKey(protocol, account_id, opt);
      assert.equal(toHex(key), output);
    });
  }
  for (let v of vectors.derive_child_key.invalid) {
    const { protocol, account_id } = v;
    should(`deriveChildKey errors on ${protocol} ${account_id}`, () => {
      assert.throws(() => e.deriveChildKey(protocol, account_id));
    });
    should(`deriveChildKey errors on double-options`, () => {
      assert.throws(() => e.deriveChildKey('aes', 0, { keyLength: 64, modulus: BigInt(65537) }));
    });
  }
  // should.run();
  if (require.main === module) should.run();
})();

// if (require.main === module) should.run();
