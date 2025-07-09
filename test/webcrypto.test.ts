import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import { pbkdf2 } from '../src/pbkdf2.ts';
import { sha256, sha384, sha512 } from '../src/sha2.ts';
import * as webcrypto from '../src/webcrypto.ts';

const HASHES = {
  // sha1: { noble: sha1, web: webcrypto.sha1 },
  sha256: { noble: sha256, web: webcrypto.sha256 },
  sha384: { noble: sha384, web: webcrypto.sha384 },
  sha512: { noble: sha512, web: webcrypto.sha512 },
};

const BUF1 = new Uint8Array([1, 2, 3]);
const BUF2 = new Uint8Array([4, 5, 6, 7]);
const BUF3 = new Uint8Array([8, 9, 10]);

describe('webcrypto', () => {
  for (const [name, { noble, web }] of Object.entries(HASHES)) {
    describe(name, () => {
      should('Basic', async () => {
        eql(await web(BUF1), noble(BUF1));
        eql(web.blockLen, noble.blockLen);
        eql(web.outputLen, noble.outputLen);
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
      });
    });
  }
});

should.runWhen(import.meta.url);
