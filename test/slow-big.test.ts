import { should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { scryptSync as nodeScryptSync } from 'node:crypto';
import { hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import { pbkdf2, pbkdf2Async } from '../src/pbkdf2.ts';
import { scrypt, scryptAsync } from '../src/scrypt.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { cshake128 } from '../src/sha3-addons.ts';
import { bytesToHex, hexToBytes } from '../src/utils.ts';
import { RANDOM, executeKDFTests } from './generator.ts';
import { HASHES } from './hashes.test.ts';
import { fmt } from './utils.ts';

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

// 4gb, nodejs/v8 limit. Safari: 2*32-1. Firefox: 2**31-2
const ZERO_4GB = new Uint8Array(4 * GB);
function supportsXgb(x) {
  try {
    let ZERO_xGB = new Uint8Array(x * GB); // catches u32 overflow in ints
    ZERO_xGB = null; // clean up ram immediately
    return true;
  } catch (error) {
    return false;
  }
}
let supports5GB = supportsXgb(5);
const ZERO_1MB = new Uint8Array(1 * MB);
// Scrypt stuff
const PASSWORD = new Uint8Array([1, 2, 3]);
const SALT = new Uint8Array([4, 5, 6]);

// KDF tests. Takes 5-10 mins
executeKDFTests(false);
// Manually generated with pycryptodome, on input ZERO_4GB / ZERO_5GB
const BIG_VECTORS = {
  SHA1: '13edccc7871c2016fbe8a2a0d808e19a90fbfc63',
  SHA256: '7f06c62352aebd8125b2a1841e2b9e1ffcbed602f381c3dcb3200200e383d1d5',
  SHA224: '0353fd2fc8d5c0dcfa5c49b61a5cb7ac70304302df956ac072985ef5',
  SHA384:
    'ae794355874dee2d4204a9cee0d35a0a2ece18788e5bcd6573684885e7f2ddcd4bc857235f1092d39bd75b4fb99bdcee',
  SHA512:
    'e4f21997407b9cb0df347f6eba2feaeb14c19f15cf784da06b78e1d5ff776a419535c894dea10a859fa72bcb234e94ada0fc86de0ff127bf9280eede8d473edb',
  SHA512_224: '6d740cdd5599e786044f4b5b6de7f583d65a3500f0ff0254ef86b064',
  SHA512_256: 'ddcc0b2490c989ba1e37a36171bdb730e0de15acbe98a75814ca31d16c09e701',
  SHA3_224: '7f56498b4b2ab8c8a8eb4746dc07894e45fc8da4fc534f36ee96730b',
  SHA3_256: '7cdb8fee94e4e69934640535baaca477b947751256ff86cac965d2b6c9708ef4',
  SHA3_384:
    '90156d9045da212c5b560f4436133c3b6390cb45c9c9e7ae02436acc88aed954a073994e4692a78cbceb2cca12daffc2',
  SHA3_512:
    'add927edce7633822abed320dff605b8a5758ef6864419413604da799d5621e8571cedb01ddec4c041c798d7f1506b3fb10c12d64dfa9b91e348d8912d3dc4ca',
  BLAKE2s: '97e0fa0129a302da9544440c32aadee50186dd675f0e0cc9e05bad80b9810d7e',
  BLAKE2b:
    '12bca8ed46df6516bd78da33efa1137479a5a9027755458dc1d186f77306849fdeaf2af8ef129040b659376c7bd134b39c1c7d2c45abd0b7068a80de7f5dbf69',
  SHAKE128: 'f0e99201f2d750f8cc46c752ab69f2dd',
  SHAKE256: 'bc379980c8c9d43ab08cf0e68bebaa3056fe52ed0b938ead35ef657858ba297d',
  TupleHash128:
    'a6ee17e16c2cff92e040239743b687ca170f082b84e68915d76886f74f3c61baa4a09b0ab42d67f3244fc7a4e402d4cbc6fcae95fdfc2d1fc5224ce9af4e6c74',
  TupleHash256:
    'c96923b28270617a392f7a6fe0e781b53089f39f85d3e6862736564b237d918aea4a94835813efd7c316a19942521c5705189df8c66934fe697114d2f876588b',
  KECCAK256: 'cad538e62c6ec50f9833dd49908bb2f56c7d3bdf5807cbe01898e95f70985ab8',
  RIPEMD160: '4a56c4e95e5224fed08572b9043dac45f7b2c78f',
  KT128: 'b4a0ac4477cf1ef00801a4ad3a3e458497d11d4c56fe4946e40be1a4136d207d',
  TURBOSHAKE128: '5e0b79cdec245f486c9749a1bbee1c886c5c8f9965619bccf5beb1d0dda0d4ce',
  TURBOSHAKE256:
    'fd9560144f511dd565c0a37147bbaa1ba7aa3c53da056337341fda4c9e6cc8403dc596bf4d01e9130bc1abe733b1284ddfc666dc929c03d9305a80a736f52bb8',
};

// Very slow hash test, hashes 16 gb of data. Tests overflows in u32/i32
// Takes 4h
for (let h in HASHES) {
  const hash = HASHES[h];
  if (hash.node_obj) {
    should(`Node: ${h} 4GB single update`, () => {
      const nodeH = hash.node_obj();
      for (let i = 0; i < 4 * 1024; i++) nodeH.update(ZERO_1MB);
      eql(hash.fn(ZERO_4GB), Uint8Array.from(nodeH.digest()));
    });
    should(`Node: ${h} 16GB partial update`, () => {
      const nodeH = hash.node_obj();
      const nobleH = hash.obj();
      // RANDOM is 1MB
      for (let i = 0; i < 16 * 1024; i++) {
        nodeH.update(RANDOM);
        nobleH.update(RANDOM);
      }
      eql(nobleH.digest(), Uint8Array.from(nodeH.digest()));
    });
  }
  // Node doesn't support 5gb arrays in crypto :(
  if (supports5GB && BIG_VECTORS[h]) {
    should(`Node: ${h} (5GB)`, () => {
      let ZERO_5GB = new Uint8Array(5 * GB); // catches u32 overflow in ints
      eql(bytesToHex(hash.fn(ZERO_5GB)), BIG_VECTORS[h]);
    });
  }
}

// Takes 8min
const opts_2gb = [
  { N: 2 ** 14, r: 2 ** 10, p: 1 },
  { N: 2 ** 23, r: 2, p: 1 },
  { N: 2, r: 2 ** 23, p: 1 },
];
for (const opts of opts_2gb) {
  should(fmt`Scrypt (2GB): ${opts}`, async () => {
    const exp = Uint8Array.from(
      nodeScryptSync(PASSWORD, SALT, 32, {
        ...opts,
        maxmem: 16 * 1024 ** 3,
      })
    );
    const nobleOpts = { ...opts, maxmem: 16 * 1024 ** 3 }; // We don't have XY buffer
    eql(scrypt(PASSWORD, SALT, nobleOpts), exp);
    eql(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
  });
}

// Scrypt with 4gb internal buffer, catches bugs for i32 overflows
should('Scrypt (4GB)', async () => {
  const opts = { N: 2 ** 15, r: 1024, p: 1 };
  const exp = Uint8Array.from(
    nodeScryptSync(PASSWORD, SALT, 32, {
      ...opts,
      maxmem: 4 * 1024 ** 3 + 128 * 1024 + 128 * 1024 * 2, // 8 GB (V) + 128kb (B) + 256kb (XY)
    })
  );
  const nobleOpts = { ...opts, maxmem: 4 * 1024 ** 3 + 128 * 1024 }; // We don't have XY buffer
  eql(scrypt(PASSWORD, SALT, nobleOpts), exp);
  eql(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
});

// takes 5 min
should('HKDF 4GB', () => {
  const exp = hexToBytes('411cd96b5326af15c28c6f63e73c1f87b49e6cd0e21a0f7989a993d6d796e0dd');
  eql(hkdf(sha512, ZERO_4GB, ZERO_4GB, ZERO_4GB, 32), exp);
});

// takes 3min
should('PBKDF2 pwd/salt 4GB', async () => {
  const opt = { dkLen: 64, c: 10 };
  const exp = hexToBytes(
    '58bf5b189082c9820b63d4eeb31c0d77efbc091b36856fff38032522e7e2f353d6781b0ba2bc0cbc50aa3896863803c61f907bcc3909b25b39e8f2f78174d4aa'
  );
  eql(pbkdf2(sha512, ZERO_4GB, ZERO_4GB, opt), exp, fmt`pbkdf2(${opt})`);
  eql(await pbkdf2Async(sha512, ZERO_4GB, ZERO_4GB, opt), exp, fmt`pbkdf2Async(${opt})`);
});

should('Scrypt pwd/salt 4GB', async () => {
  const opt = { N: 4, r: 4, p: 4, dkLen: 32 };
  const exp = hexToBytes('00609885de3a56181c60f315c4ee65366368b01dd55efcd7923188597dc40912');
  eql(scrypt(ZERO_4GB, ZERO_4GB, opt), exp, fmt`scrypt(${opt})`);
  eql(await scryptAsync(ZERO_4GB, ZERO_4GB, opt), exp, fmt`scryptAsync(${opt})`);
});

should('Hmac 4GB', async () => {
  const exp = hexToBytes('c5c39ec0ad91ddc3010d683b7e077aeedaba92fb7da17e367dbcf08e11aa25d1');
  eql(hmac(sha256, ZERO_4GB, ZERO_4GB), exp);
});

should('cshake >4gb (GH-101)', () => {
  const rng = cshake128(new Uint8Array(), { dkLen: 536_871_912 + 1000 });
  const S = rng.subarray(0, 536_871_912);
  const data = rng.subarray(536_871_912);
  const res = cshake128(data, { personalization: S, dkLen: 32 });
  eql(bytesToHex(res), '2cb9f237767e98f2614b8779cf096a52da9b3a849280bbddec820771ae529cf0');
});

if (supports5GB) {
  should('5GB in hmac, hkdf, pbkdf, scrypt', async () => {
    let ZERO_5GB = new Uint8Array(5 * GB); // catches u32 overflow in ints
    // hmac
    const expHm = hexToBytes('669fbe7961b70cb36f9d5559e939c4303090991a270586c23f2e6c2b82d2a4af');
    eql(hmac(sha256, ZERO_5GB, ZERO_5GB), expHm);

    // hkdf
    const expH = hexToBytes('b5f75ccb25f5e3e2f4b524e9cf99449aac9b03bd4d0ad4957d0e3d42583a77d4');
    eql(hkdf(sha512, ZERO_5GB, ZERO_5GB, ZERO_5GB, 32), expH, 'HKDF 5GB');

    // pbkdf2
    const optP = { dkLen: 64, c: 10 };
    const expP = hexToBytes(
      '1445d2aa24bf84d7f69269a7e088f7130b00901860de454415c947f0cb87ea892d84ccb1757e973a649d09f32f965f4aa223dba690c0cea0ef0359c325cd9501'
    );
    eql(pbkdf2(sha512, ZERO_5GB, ZERO_5GB, optP), expP, fmt`5GB pbkdf2(${optP})`);
    eql(await pbkdf2Async(sha512, ZERO_5GB, ZERO_5GB, optP), expP, fmt`5GB pbkdf2Async(${optP})`);

    // scrypt
    // This doesn't work in node, python: ~1.5h, noble: ~5min
    const optS = { N: 4, r: 4, p: 4, dkLen: 32 };
    const expS = hexToBytes('0e49e31878f256302b581977f4f5b921cd9c53f3072b0b2948f5c6f53416cac7');
    eql(scrypt(ZERO_5GB, ZERO_5GB, optS), expS, fmt`5GB scrypt(${optS})`);
    eql(await scryptAsync(ZERO_5GB, ZERO_5GB, optS), expS, fmt`5GB scryptAsync(${optS})`);
  });

  // 22: 0b4de6108452441913a780b56461c011c3480e29c82dc47aa0af59321e039b9c
  // 23: 5380409ca2367f95520267c162a46a9b24e65797f8675a9dad7bdfa2b4f4ea17
  // 24: 6ce62287b7938f0a1dc838d158d4b6753ddb0bc2c66a88e32d506913dace9865
  // 25: 6b7aa6f838478c4c9ed696fce7ff530aee543d8399e57b8095b6b036b185a5f1
  // 26: 1740d229ad1f230b75483687b1f167ef804203c261c4f2c3de7eed12226b857a
  // 27: 8ed4c994fab397a1c87c0f15ec810f0ca3ec8e9100bb3f49604a910527ad14df
  should('Scrypt (2**25)', async () => {
    if (!supportsXgb(9)) return;
    const opts = { N: 2 ** 25, r: 2, p: 2 };
    const exp = hexToBytes('6b7aa6f838478c4c9ed696fce7ff530aee543d8399e57b8095b6b036b185a5f1');
    const nobleOpts = { ...opts, maxmem: 9 * GB };
    eql(scrypt(PASSWORD, SALT, nobleOpts), exp);
    eql(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
  });

  should('Scrypt (16GB)', async () => {
    if (!supportsXgb(17)) return;
    const opts = { N: 2 ** 24, r: 8, p: 1 };
    const exp = Uint8Array.from(
      nodeScryptSync(PASSWORD, SALT, 32, {
        ...opts,
        maxmem: 17 * GB,
      })
    );
    const nobleOpts = { ...opts, maxmem: 17 * GB };
    eql(scrypt(PASSWORD, SALT, nobleOpts), exp);
    eql(await scryptAsync(PASSWORD, SALT, nobleOpts), exp);
  });
}

// non parallel: 14h, parallel: ~1h
should.runWhen(import.meta.url);
