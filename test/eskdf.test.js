const { equal, rejects, throws } = require('assert');
const { should } = require('micro-should');
const { eskdf } = require('../eskdf');
const { bytesToHex: toHex } = require('../utils');
const vectors = require('./vectors/eskdf.json');

(async () => {
  for (let v of vectors.derive_main_seed.valid) {
    const { output, fingerprint, username, password } = v;
    should(`deriveMainSeed ${fingerprint}`, async () => {
      const keyc = await eskdf(username, password);
      // equal(toHex(seed), output);
      equal(keyc.fingerprint, fingerprint);
    });
  }
  for (let v of vectors.derive_main_seed.invalid) {
    const { username, password } = v;
    should(`deriveMainSeed errors on ${username} ${password}`, async () => {
      await rejects(() => eskdf(username, password));
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
      equal(toHex(key), output);
    });
  }
  for (let v of vectors.derive_child_key.invalid) {
    const { protocol, account_id } = v;
    should(`deriveChildKey errors on ${protocol} ${account_id}`, () => {
      throws(() => e.deriveChildKey(protocol, account_id));
    });
    should(`deriveChildKey errors on double-options`, () => {
      throws(() => e.deriveChildKey('aes', 0, { keyLength: 64, modulus: BigInt(65537) }));
    });
  }
  // should.run();
  if (require.main === module) should.run();
})();

// if (require.main === module) should.run();
