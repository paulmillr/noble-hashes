import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { hmac } from '../src/hmac.ts';
import { sha256, sha384, sha512 } from '../src/sha2.ts';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { EMPTY, fmt, SPACE, truncate, TYPE_TEST } from './utils.ts';

// HMAC test vectors from RFC 4231
const HMAC_VECTORS = [
  {
    key: hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    data: [utf8ToBytes('Hi There')],
    sha256: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    sha512:
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
      'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    key: utf8ToBytes('Jefe'),
    data: [utf8ToBytes('what do ya want '), utf8ToBytes('for nothing?')],
    sha256: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    sha512:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
      '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    key: hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
    data: [
      hexToBytes(
        'dddddddddddddddddddddddddddddddddddddddddddddddddd' +
          'dddddddddddddddddddddddddddddddddddddddddddddddddd'
      ),
    ],
    sha256: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    sha512:
      'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39' +
      'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    key: hexToBytes('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: [
      hexToBytes(
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
      ),
    ],
    sha256: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    sha512:
      'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db' +
      'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    key: hexToBytes('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c'),
    data: [utf8ToBytes('Test With Trunca'), utf8ToBytes('tion')],
    sha256: 'a3b6167473100ee06e0c796c2955552b',
    sha512: '415fad6271580a531d4179bc891d87a6',
    truncate: 16,
  },
  {
    key: hexToBytes(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa'
    ),
    data: [
      utf8ToBytes('Test Using Large'),
      utf8ToBytes('r Than Block-Siz'),
      utf8ToBytes('e Key - Hash Key'),
      utf8ToBytes(' First'),
    ],
    sha256: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    sha512:
      '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352' +
      '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  {
    key: hexToBytes(
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaa'
    ),
    data: [
      utf8ToBytes('This is a test u'),
      utf8ToBytes('sing a larger th'),
      utf8ToBytes('an block-size ke'),
      utf8ToBytes('y and a larger t'),
      utf8ToBytes('han block-size d'),
      utf8ToBytes('ata. The key nee'),
      utf8ToBytes('ds to be hashed '),
      utf8ToBytes('before being use'),
      utf8ToBytes('d by the HMAC al'),
      utf8ToBytes('gorithm.'),
    ],
    sha256: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    sha512:
      'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944' +
      'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
];

describe('hmac', () => {
  for (let i = 0; i < HMAC_VECTORS.length; i++) {
    const t = HMAC_VECTORS[i];
    describe('vector ' + i, () => {
      should('sha256 full', () => {
        const h256 = hmac.create(sha256, t.key).update(concatBytes(...t.data));
        eql(truncate(h256.digest(), t.truncate), hexToBytes(t.sha256));
      });
      should('sha256 partial', () => {
        const h256 = hmac.create(sha256, t.key);
        for (let d of t.data) h256.update(d);
        eql(truncate(h256.digest(), t.truncate), hexToBytes(t.sha256));
      });
      should('sha512 full', () => {
        const h512 = hmac.create(sha512, t.key).update(concatBytes(...t.data));
        eql(truncate(h512.digest(), t.truncate), hexToBytes(t.sha512));
      });
      should('sha512 partial', () => {
        const h512 = hmac.create(sha512, t.key);
        for (let d of t.data) h512.update(d);
        eql(truncate(h512.digest(), t.truncate), hexToBytes(t.sha512));
      });
    });
  }

  should('HMAC types', () => {
    const key = utf8ToBytes('key');
    const msg = utf8ToBytes('msg');
    hmac(sha256, key, msg);
    hmac.create(sha256, key);
    for (const t of TYPE_TEST.bytes) {
      throws(() => hmac(sha256, t, msg), fmt`hmac(key=${t})`);
      throws(() => hmac(sha256, key, t), fmt`hmac(msg=${t})`);
      throws(() => hmac.create(sha256, t), fmt`hmac.create(key=${t})`);
    }
    throws(() => hmac(sha256, undefined, msg), `hmac(key=undefined)`);
    throws(() => hmac(sha256, key), `hmac(msg=undefined)`);
    throws(() => hmac.create(sha256, undefined), `hmac.create(key=undefined)`);
    // for (const t of TYPE_TEST.opts) {
    //   throws(() => hmac(sha256, 'key', 'salt', t), fmt`hmac(opt=${t})`);
    //   throws(() => hmac.create(sha256, 'key', t), fmt`hmac.create(opt=${t})`);
    // }
    for (const t of TYPE_TEST.hash) throws(() => hmac(t, key, msg), fmt`hmac(hash=${t})`);
    eql(
      hmac(sha512, SPACE.bytes, SPACE.bytes),
      hmac.create(sha512, SPACE.bytes).update(SPACE.bytes).digest(),
      'hmac.SPACE (full form bytes)'
    );
    eql(
      hmac(sha512, SPACE.bytes, SPACE.bytes),
      hmac.create(sha512, SPACE.bytes).update(SPACE.bytes).digest(),
      'hmac.SPACE (full form stingr)'
    );
  });

  should('Sha512/384 issue', () => {
    const h = hmac.create(
      sha384,
      hexToBytes(
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      )
    );
    h.update(
      hexToBytes(
        '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101'
      )
    );
    h.update(hexToBytes('00'));
    h.update(
      hexToBytes(
        '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf59a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe'
      )
    );
    eql(
      bytesToHex(h.digest()),
      'a1ae63339c4fac449464e302c61e8ceb5b28c04d108e022179ce6dabb2d3e310cb3bf41cd6013b3006f33c037e6b7fa8'
    );
  });

  should('not be created with invalid hash fn', () => {
    function fakeHash() {}
    fakeHash.create = () => {
      return {};
    };
    fakeHash.update = () => {};
    // no fakeHash.update()
    fakeHash.blockLen = 32;
    fakeHash.outputLen = 32;
    throws(() => hmac(fakeHash, EMPTY.str, EMPTY.str));
  });
});

should.runWhen(import.meta.url);
