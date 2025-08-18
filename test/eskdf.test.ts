import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, equal, rejects, throws } from 'node:assert';
import { eskdf } from '../src/eskdf.ts';
import { bytesToHex as toHex } from '../src/utils.ts';
import { json } from './utils.ts';
const vectors = json('./vectors/eskdf.json');

describe('eskdf', () => {
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
  let e;
  for (let v of vectors.derive_child_key.valid) {
    const { output, protocol, account_id, key_length, modulus } = v;
    const opt =
      key_length != null
        ? { keyLength: key_length }
        : modulus != null
          ? { modulus: BigInt('0x' + modulus) }
          : undefined;
    should(`deriveChildKey ${protocol} ${output}`, async () => {
      if (!e) e = await eskdf(username, password);
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
  should('types', async () => {
    const keyc = await eskdf('test@test.com', 'test2test');
    eql(
      toHex(keyc.deriveChildKey('ssh', 'test')),
      '3bc39ad06a15d4867aaa53f4025077ecca7cd33b3f5b9da131b50586601726fa'
    );
    eql(
      toHex(keyc.deriveChildKey('ssh', 0)),
      'd7b14774e815d429e75b5f366b0df4eff32343e94f1b30a5e12eaab682974667'
    );

    throws(() => keyc.deriveChildKey('ssh', 'test', { keyLength: 1, modulus: 1 }));
    throws(() => keyc.deriveChildKey('ssh', 'test', {}));
    eql(
      toHex(keyc.deriveChildKey('ssh', 0, { keyLength: 16 })),
      'd7b14774e815d429e75b5f366b0df4ef'
    );
    throws(() => keyc.deriveChildKey('ssh', 'test', { modulus: -1n }));
    throws(() => keyc.deriveChildKey('ssh', 'test', { modulus: 1n }));
    eql(
      toHex(keyc.deriveChildKey('ssh', 0, { modulus: 2n ** 128n - 1n })),
      'e75b5f366b0df4f1a285d2d31f46d8f8'
    );
    throws(() => keyc.deriveChildKey('ssh', ''));
    throws(() => keyc.deriveChildKey('ssh', '1'.repeat(256)));
    throws(() => keyc.deriveChildKey('tmp', 'test'));
    throws(() => keyc.deriveChildKey('ssh', true));
    throws(() => keyc.deriveChildKey('ssh', 100n));
    throws(() => keyc.deriveChildKey('ssh', new Uint8Array(10)));
    // Expire
    keyc.expire();
    throws(() => keyc.deriveChildKey('ssh', 'test'));
    throws(() => keyc.deriveChildKey('ssh', 0));
  });
});

should.runWhen(import.meta.url);
