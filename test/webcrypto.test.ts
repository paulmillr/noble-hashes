import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { PLATFORMS } from './platform.ts';

const BT = { describe, should };
export function test(variant: string, platform: any, { describe, should } = BT) {
const { hkdf, hmac, pbkdf2, sha256, sha384, sha512, web: webcrypto } = platform;
const HASHES = {
  // sha1: { noble: sha1, web: webcrypto.sha1 },
  sha256: { noble: sha256, web: webcrypto.sha256 },
  sha384: { noble: sha384, web: webcrypto.sha384 },
  sha512: { noble: sha512, web: webcrypto.sha512 },
};

const BUF1 = new Uint8Array([1, 2, 3]);
const BUF2 = new Uint8Array([4, 5, 6, 7]);
const BUF3 = new Uint8Array([8, 9, 10]);
describe(`webcrypto (${variant})`, () => {
  for (const [name, { noble, web }] of Object.entries(HASHES)) {
    describe(name, () => {
      should('Basic', async () => {
        eql(await web(BUF1), noble(BUF1));
        eql(web.blockLen, noble.blockLen);
        eql(web.outputLen, noble.outputLen);
      });
      should('descriptor is immutable', async () => {
        const desc = Object.getOwnPropertyDescriptor(web, 'webCryptoName');
        throws(() => {
          web.webCryptoName = 'SHA-512';
        });
        eql(Object.getOwnPropertyDescriptor(web, 'webCryptoName'), desc);
        eql(await webcrypto.hmac(web, BUF1, BUF2), hmac(noble, BUF1, BUF2));
      });
      should('Stream', async () => {
        throws(() => web.create());
        throws(() => hmac.create(web, BUF1));
      });
      should('HMAC', async () => {
        eql(await webcrypto.hmac(web, BUF1, BUF2), hmac(noble, BUF1, BUF2));
      });
      should('hkdf', async () => {
        eql(await webcrypto.hkdf(web, BUF1, BUF2, BUF3, 10), hkdf(noble, BUF1, BUF2, BUF3, 10));
        // No info
        eql(
          await webcrypto.hkdf(web, BUF1, BUF2, undefined, 10),
          hkdf(noble, BUF1, BUF2, undefined, 10)
        );
        // No salt
        eql(
          await webcrypto.hkdf(web, BUF1, undefined, undefined, 10),
          hkdf(noble, BUF1, undefined, undefined, 10)
        );
        // 1k bytes
        eql(
          await webcrypto.hkdf(web, BUF1, undefined, undefined, 1000),
          hkdf(noble, BUF1, undefined, undefined, 1000)
        );
      });
      should('pbkdf2', async () => {
        eql(await webcrypto.pbkdf2(web, BUF1, BUF2, { c: 1 }), pbkdf2(noble, BUF1, BUF2, { c: 1 }));
        eql(
          await webcrypto.pbkdf2(web, 'pwd', 'salt', { c: 11 }),
          pbkdf2(noble, 'pwd', 'salt', { c: 11 })
        );
        eql(
          await webcrypto.pbkdf2(web, 'pwd', 'salt', { c: 11, dkLen: 1000 }),
          pbkdf2(noble, 'pwd', 'salt', { c: 11, dkLen: 1000 })
        );
        await rejects(() => webcrypto.pbkdf2(web, 'pwd', 'salt', { c: 1, dkLen: 0 }));
      });
    });
  }
});
}

if (import.meta.url === pathToFileURL(process.argv[1]).href)
  for (const k in PLATFORMS) test(k, PLATFORMS[k]);

should.runWhen(import.meta.url);
