const assert = require('assert');
const { should } = require('micro-should');
const eskdf = require('../eskdf');
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
      const seed = await eskdf.deriveMainSeed(username, password);
      const keyc = await eskdf.eskdf(username, password);
      assert.equal(toHex(seed), output);
      assert.equal(keyc.fingerprint, fingerprint);
    });
  }
  for (let v of vectors.derive_main_seed.invalid) {
    const { username, password } = v;
    should(`deriveMainSeed errors on ${username} ${password}`, () => {
      assert.throws(() => eskdf.deriveMainSeed(username, password));
    });
  }
  const s = vectors.derive_child_key.seed;
  const seed = await eskdf.deriveMainSeed(s.username, s.password);
  for (let v of vectors.derive_child_key.valid) {
    const { output, protocol, account_id } = v;
    should(`deriveChildKey ${output}`, () => {
      const key = eskdf.deriveChildKey(seed, protocol, account_id);
      assert.equal(toHex(key), output);
    });
  }
  for (let v of vectors.derive_child_key.invalid) {
    const { protocol, account_id } = v;
    should(`deriveChildKey errors on ${protocol} ${account_id}`, () => {
      assert.throws(() => eskdf.deriveChildKey(seed, protocol, account_id));
    });
  }
  // should.run();
})();

if (require.main === module) should.run();
