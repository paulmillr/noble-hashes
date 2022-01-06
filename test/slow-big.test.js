const assert = require('assert');
const crypto = require('crypto');
const { should } = require('micro-should');
const { HASHES } = require('./hashes.test');
const { bytes, integer, gen, RANDOM, serializeCase, executeKDFTests } = require('./generator');
const { sha256 } = require('../lib/sha256');
const { sha512 } = require('../lib/sha512');
const { hmac } = require('../lib/hmac');
const { hkdf } = require('../lib/hkdf');
const { pbkdf2, pbkdf2Async } = require('../lib/pbkdf2');
const { scrypt, scryptAsync } = require('../lib/scrypt');

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

// 4gb, nodejs/v8 limit. Safari: 2*32-1. Firefox: 2**31-2
const ZERO_4GB = new Uint8Array(4 * GB);
const ZERO_1MB = new Uint8Array(1 * MB);
// Scrypt stuff
const PASSWORD = new Uint8Array([1, 2, 3]);
const SALT = new Uint8Array([4, 5, 6]);

// KDF tests. Takes 5-10 mins
executeKDFTests(false);

// Very slow hash test, hashes 16 gb of data. Tests overflows in u32/i32
// Takes 4h
for (let h in HASHES) {
  const hash = HASHES[h];
  if (!hash.node_obj) continue;
  should(`Node: ${h} 4GB single update`, () => {
    const nodeH = hash.node_obj();
    for (let i = 0; i < 4 * 1024; i++) nodeH.update(ZERO_1MB);
    assert.deepStrictEqual(hash.fn(ZERO_4GB), Uint8Array.from(nodeH.digest()));
  });
  should(`Node: ${h} 16GB partial update`, () => {
    const nodeH = hash.node_obj();
    const nobleH = hash.obj();
    // RANDOM is 1MB
    for (let i = 0; i < 16 * 1024; i++) {
      nodeH.update(RANDOM);
      nobleH.update(RANDOM);
    }
    assert.deepStrictEqual(nobleH.digest(), Uint8Array.from(nodeH.digest()));
  });
}

// Takes 8min
const opts_2gb = [
  { N: 2 ** 14, r: 2 ** 10, p: 1 },
  { N: 2 ** 23, r: 2, p: 1 },
  { N: 2, r: 2 ** 23, p: 1 },
];
for (const opts of opts_2gb) {
  should(`Scrypt (2GB): ${opts}`, async () => {
    const exp = Uint8Array.from(
      crypto.scryptSync(PASSWORD, SALT, 32, {
        ...opts,
        maxmem: 16 * 1024 ** 3,
      })
    );
    const nobleOpts = { ...opts, maxmem: 16 * 1024 ** 3 }; // We don't have XY buffer
    assert.deepStrictEqual(scrypt(PASSWORD, SALT, nobleOpts), exp);
    assert.deepStrictEqual(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
  });
}

// Scrypt with 4gb internal buffer, catches bugs for i32 overflows
should('Scrypt (4GB)', async () => {
  const opts = { N: 2 ** 15, r: 1024, p: 1 };
  const exp = Uint8Array.from(
    crypto.scryptSync(PASSWORD, SALT, 32, {
      ...opts,
      maxmem: 4 * 1024 ** 3 + 128 * 1024 + 128 * 1024 * 2, // 8 GB (V) + 128kb (B) + 256kb (XY)
    })
  );
  const nobleOpts = { ...opts, maxmem: 4 * 1024 ** 3 + 128 * 1024 }; // We don't have XY buffer
  assert.deepStrictEqual(scrypt(PASSWORD, SALT, nobleOpts), exp);
  assert.deepStrictEqual(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
});

// Takes 10h
const SCRYPT_CASES = gen({
  N: integer(1, 10),
  r: integer(1, 1024),
  p: integer(1, 1024),
  dkLen: integer(0, 1024),
  pwd: bytes(0, 1024),
  salt: bytes(0, 1024),
});

for (let i = 0; i < SCRYPT_CASES.length; i++) {
  const c = SCRYPT_CASES[i];
  should(`Scrypt generator (${i}): ${serializeCase(c)}`, async () => {
    const opt = { ...c, N: 2 ** c.N };
    const exp = Uint8Array.from(
      crypto.scryptSync(c.pwd, c.salt, c.dkLen, { maxmem: 1024 ** 4, ...opt })
    );
    assert.deepStrictEqual(scrypt(c.pwd, c.salt, opt), exp, `scrypt(${opt})`);
    assert.deepStrictEqual(await scryptAsync(c.pwd, c.salt, opt), exp, `scryptAsync(${opt})`);
  });
}

// takes 5 min
should('HKDF 4GB', () => {
  const exp = Uint8Array.from(
    Buffer.from('411cd96b5326af15c28c6f63e73c1f87b49e6cd0e21a0f7989a993d6d796e0dd', 'hex')
  );
  assert.deepStrictEqual(hkdf(sha512, ZERO_4GB, ZERO_4GB, ZERO_4GB, 32), exp);
});

// takes 3min
should('PBKDF2 pwd/salt 4GB', async () => {
  const opt = { dkLen: 64, c: 10 };
  const exp = Uint8Array.from(
    Buffer.from(
      '58bf5b189082c9820b63d4eeb31c0d77efbc091b36856fff38032522e7e2f353d6781b0ba2bc0cbc50aa3896863803c61f907bcc3909b25b39e8f2f78174d4aa',
      'hex'
    )
  );
  assert.deepStrictEqual(pbkdf2(sha512, ZERO_4GB, ZERO_4GB, opt), exp, `pbkdf2(${opt})`);
  assert.deepStrictEqual(
    await pbkdf2Async(sha512, ZERO_4GB, ZERO_4GB, opt),
    exp,
    `pbkdf2Async(${opt})`
  );
});

should('Scrypt pwd/salt 4GB', async () => {
  const opt = { N: 4, r: 4, p: 4, dkLen: 32 };
  const exp = Uint8Array.from(
    Buffer.from('00609885de3a56181c60f315c4ee65366368b01dd55efcd7923188597dc40912', 'hex')
  );
  assert.deepStrictEqual(scrypt(ZERO_4GB, ZERO_4GB, opt), exp, `scrypt(${opt})`);
  assert.deepStrictEqual(await scryptAsync(ZERO_4GB, ZERO_4GB, opt), exp, `scryptAsync(${opt})`);
});

should('Hmac 4GB', async () => {
  const exp = Uint8Array.from(
    Buffer.from('c5c39ec0ad91ddc3010d683b7e077aeedaba92fb7da17e367dbcf08e11aa25d1', 'hex')
  );
  assert.deepStrictEqual(hmac(sha256, ZERO_4GB, ZERO_4GB), exp);
});

// non parallel: 14h, parallel: ~1h
if (require.main === module) should.runParallel();
