const assert = require('assert');
const crypto = require('crypto');
const { should } = require('micro-should');
const { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } = require('../lib/sha3');
const { k12, m14, cshake128, cshake256, kmac128, kmac256 } = require('../lib/sha3-addons');
const { pattern, times, EMPTY, TYPE_TEST } = require('./utils.js');
const fs = require('fs');

function getVectors(name) {
  const vectors = fs.readFileSync(`${__dirname}/vectors/${name}.txt`, 'utf8').split('\n\n');
  const res = [];
  for (const v of vectors) {
    if (v.startsWith('#')) continue;
    const item = {};
    const args = v.split('\n').map((i) => i.split('=', 2).map((j) => j.trim()));
    for (const [arg, val] of args) if (arg) item[arg] = val;
    res.push(item);
  }
  return res;
}

const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

for (let v of getVectors('ShortMsgKAT_SHA3-224')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`SHA3-224 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(sha3_224(msg), fromHex(v.MD));
  });
}

for (let v of getVectors('ShortMsgKAT_SHA3-256')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`SHA3-256 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(sha3_256(msg), fromHex(v.MD));
  });
}

for (let v of getVectors('ShortMsgKAT_SHA3-384')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`SHA3-384 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(sha3_384(msg), fromHex(v.MD));
  });
}

for (let v of getVectors('ShortMsgKAT_SHA3-512')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`SHA3-512 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(sha3_512(msg), fromHex(v.MD));
  });
}

for (let v of getVectors('ShortMsgKAT_SHAKE128')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`Shake128 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(shake128(msg, { dkLen: 512 }), fromHex(v.Squeezed));
  });
}

for (let v of getVectors('ShortMsgKAT_SHAKE256')) {
  if (+v.Len % 8) continue; // partial bytes is not supported
  should(`Shake256 len=${v.Len} hex=${v.Msg}`, () => {
    const msg = +v.Len ? fromHex(v.Msg) : new Uint8Array([]);
    assert.deepStrictEqual(shake256(msg, { dkLen: 512 }), fromHex(v.Squeezed));
  });
}

const K12_VECTORS = [
  // KangarooTwelve(M=empty, C=empty, 32 bytes):
  // 1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5
  {
    msg: EMPTY.bytes,
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5',
  },
  // KangarooTwelve(M=empty, C=empty, 64 bytes):
  // 1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5 42 69 c0 56 b8 c8 2e 48 27 60 38 b6 d2 92 96 6c c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71
  {
    msg: EMPTY.bytes,
    personalization: EMPTY.bytes,
    dkLen: 64,
    exp: '1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca 1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5 42 69 c0 56 b8 c8 2e 48 27 60 38 b6 d2 92 96 6c c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71',
  },
  // KangarooTwelve(M=empty, C=empty, 10032 bytes), last 32 bytes:
  // e8 dc 56 36 42 f7 22 8c 84 68 4c 89 84 05 d3 a8 34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d
  {
    msg: EMPTY.bytes,
    personalization: EMPTY.bytes,
    dkLen: 10032,
    last: 32,
    exp: 'e8 dc 56 36 42 f7 22 8c 84 68 4c 89 84 05 d3 a8 34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^0 bytes, C=empty, 32 bytes):
  // 2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58 ef ca 7c f7 d8 21 8e 02 d3 45 df aa 65 24 4a 1f
  {
    msg: pattern(0xfa, 17 ** 0),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58 ef ca 7c f7 d8 21 8e 02 d3 45 df aa 65 24 4a 1f',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^1 bytes, C=empty, 32 bytes):
  // 6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b 0f 37 12 05 f6 a9 a9 3a 27 3f 51 df 37 12 28 88
  {
    msg: pattern(0xfa, 17 ** 1),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b 0f 37 12 05 f6 a9 a9 3a 27 3f 51 df 37 12 28 88',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^2 bytes, C=empty, 32 bytes):
  // 0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1 e7 46 75 d7 f5 32 7a 50 67 f3 67 b1 08 ec b6 7c
  {
    msg: pattern(0xfa, 17 ** 2),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1 e7 46 75 d7 f5 32 7a 50 67 f3 67 b1 08 ec b6 7c',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^3 bytes, C=empty, 32 bytes):
  // cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77 2c 12 e3 22 e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0
  {
    msg: pattern(0xfa, 17 ** 3),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: 'cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77 2c 12 e3 22 e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^4 bytes, C=empty, 32 bytes):
  // 87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c 3a f1 a7 71 c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe
  {
    msg: pattern(0xfa, 17 ** 4),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c 3a f1 a7 71 c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^5 bytes, C=empty, 32 bytes):
  // 84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c c7 cb d6 7c ee df 88 3e b6 78 a0 a8 e0 37 16 82
  {
    msg: pattern(0xfa, 17 ** 5),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c c7 cb d6 7c ee df 88 3e b6 78 a0 a8 e0 37 16 82',
  },
  // KangarooTwelve(M=pattern 0x00 to 0xFA for 17^6 bytes, C=empty, 32 bytes):
  // 3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32 55 c8 d9 58 78 48 1d 3c d8 ce 85 f5 8e 88 0a f8
  {
    msg: pattern(0xfa, 17 ** 6),
    personalization: EMPTY.bytes,
    dkLen: 32,
    exp: '3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32 55 c8 d9 58 78 48 1d 3c d8 ce 85 f5 8e 88 0a f8',
  },
  // KangarooTwelve(M=0 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^0 bytes, 32 bytes):
  // fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30 45 f4 6e e9 84 c5 6e 3c 33 28 ca af 1a a1 a5 83
  {
    msg: times(0xff, 0),
    personalization: pattern(0xfa, 41 ** 0),
    dkLen: 32,
    exp: 'fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30 45 f4 6e e9 84 c5 6e 3c 33 28 ca af 1a a1 a5 83',
  },
  // KangarooTwelve(M=1 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^1 bytes, 32 bytes):
  // d8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c 20 b8 08 ac c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4
  {
    msg: times(0xff, 1),
    personalization: pattern(0xfa, 41 ** 1),
    dkLen: 32,
    exp: 'd8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c 20 b8 08 ac c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4',
  },
  // KangarooTwelve(M=3 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^2 bytes, 32 bytes):
  // c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0 13 58 cf 4c 1b af 89 44 7a 72 42 34 dc 7c ed 74
  {
    msg: times(0xff, 3),
    personalization: pattern(0xfa, 41 ** 2),
    dkLen: 32,
    exp: 'c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0 13 58 cf 4c 1b af 89 44 7a 72 42 34 dc 7c ed 74',
  },
  // KangarooTwelve(M=7 times byte 0xFF, C=pattern 0x00 to 0xFA for 41^3 bytes, 32 bytes):
  // 75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9 db cf 07 0c 7b 0d ca 06 45 0a b2 91 d7 44 3b cf
  {
    msg: times(0xff, 7),
    personalization: pattern(0xfa, 41 ** 3),
    dkLen: 32,
    exp: '75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9 db cf 07 0c 7b 0d ca 06 45 0a b2 91 d7 44 3b cf',
  },
];

for (let i = 0; i < K12_VECTORS.length; i++) {
  should(`K12 ${i}`, () => {
    const v = K12_VECTORS[i];
    const exp = fromHex(v.exp.replace(/ /g, ''));
    let res = k12(v.msg, { personalization: v.personalization, dkLen: v.dkLen });
    if (v.last) res = res.slice(-v.last);
    assert.deepStrictEqual(res, exp);
  });
}
should('K12: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) assert.throws(() => k12('test', { dkLen }));
});
// Same as K12, generated by K12-test.py with replaced K12 with K14
const M14_VECTORS = [
  '6f 66 ef 14 74 eb 53 80 7a a3 29 25 7c 76 8b b8 88 93 d9 f0 86 e5 1d a2 f5 c8 0d 17 ca 0f c5 7d',
  '6f 66 ef 14 74 eb 53 80 7a a3 29 25 7c 76 8b b8 88 93 d9 f0 86 e5 1d a2 f5 c8 0d 17 ca 0f c5 7d 5a 24 fa c8 79 01 4f 8b 30 a3 fd f5 ac 56 eb af a2 19 eb 89 1d 4b bb ab 7e 1d f3 b2 72 05 b4 59',
  'c0 93 22 de 15 13 d0 cd 60 47 28 f3 6d 11 ad ff 58 b9 3f 77 63 81 09 5a 07 19 21 ea fb 30 e1 e3',
  'cc 05 eb c9 28 15 6c 7a 03 54 00 85 35 5c 47 c6 ae a1 d0 7d c8 11 cd de d0 e4 c3 67 f8 d9 93 68',
  'aa 76 4f d8 b3 8f 19 97 6a 30 5c b0 07 f1 93 84 b2 10 a5 c7 b0 fc 44 99 d6 f8 3c 62 27 bf f8 50',
  'f1 8a 6e 25 0b 1c c8 3d ea 89 ff bb 4d e5 6a 8e 70 04 1c 71 fc 5b 17 a2 aa ab 05 c6 06 aa 6b f2',
  '0a c8 9b 11 a0 6f 46 b2 f6 fe ef f0 46 c9 7e 90 dc 02 91 0a e5 09 b8 73 9c fe a5 df 1d f9 0b 82',
  '35 af 0a 5f c6 c4 d1 11 fb c6 8f 87 9d 05 50 6a af d3 00 b5 ab 13 69 86 d7 ae d8 a9 f1 be 33 1e',
  '0c 98 2c 5d 53 34 e2 7c c6 59 1c da 30 8d fa 6b 4f dd 73 6a ad be 64 53 6b de f8 3c 1d 49 6b a0',
  '98 81 fd 57 a1 2f f0 50 a4 67 5a de f9 48 11 18 90 ca 4c 18 39 10 d5 f1 2d 53 9d 03 0a 5d fb 5c',
  'e6 c2 3c ee ab 20 89 d1 4d c3 b0 88 fd fe 6d 44 18 bf 8a 6f 33 0f b3 ed cc 30 0c d8 1e 1b ef 2f',
  '2b ab 75 b3 1b 8c 30 49 ab eb 76 74 77 47 71 b6 4f 59 22 5b e2 0e 93 0e bd bf 8e 37 c2 4f ad 69',
  '73 2a 60 c3 08 be bf 5f 7b 3d 3e 8f 0d 26 e3 24 c0 4b ab 41 97 ca 0a 60 8b 0b ef aa 25 ea 59 76',
  '61 58 3c df aa 64 ab 60 e7 7b 8c 8b dd 0a d0 88 f9 d7 60 b2 94 4f 7d 64 c5 dd 81 ce 7e 92 d9 6b',
];

for (let i = 0; i < K12_VECTORS.length; i++) {
  should(`M14 ${i}`, () => {
    const v = K12_VECTORS[i];
    const exp = fromHex(M14_VECTORS[i].replace(/ /g, ''));
    let res = m14(v.msg, { personalization: v.personalization, dkLen: v.dkLen });
    if (v.last) res = res.slice(-v.last);
    assert.deepStrictEqual(res, exp);
  });
}

// https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/cshake_samples.pdf
const CSHAKE_VESTORS = [
  {
    fn: cshake128,
    data: fromHex('00010203'),
    dkLen: 32,
    NISTfn: '',
    personalization: 'Email Signature',
    output: fromHex('c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'),
  },
  {
    fn: cshake128,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 32,
    NISTfn: '',
    personalization: 'Email Signature',
    output: fromHex('c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b'),
  },
  {
    fn: cshake128,
    data: new Uint8Array([]),
    dkLen: 32,
    NISTfn: '',
    personalization: '',
    output: fromHex('7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'),
  },

  {
    fn: cshake256,
    data: fromHex('00010203'),
    dkLen: 64,
    NISTfn: '',
    personalization: 'Email Signature',
    output: fromHex(
      'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'
    ),
  },
  {
    fn: cshake256,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 64,
    NISTfn: '',
    personalization: 'Email Signature',
    output: fromHex(
      '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb'
    ),
  },
  {
    fn: cshake256,
    data: new Uint8Array([]),
    dkLen: 64,
    NISTfn: '',
    personalization: '',
    output: fromHex(
      '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'
    ),
  },
];

for (let i = 0; i < CSHAKE_VESTORS.length; i++) {
  should(`CSHAKE ${i}`, () => {
    const v = CSHAKE_VESTORS[i];
    assert.deepStrictEqual(
      v.fn(v.data, { personalization: v.personalization, NISTfn: v.NISTfn, dkLen: v.dkLen }),
      v.output
    );
  });
}

// http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/KMAC_samples.pdf
const KMAC_VECTORS = [
  {
    fn: kmac128,
    data: fromHex('00010203'),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: '',
    output: fromHex('e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'),
  },
  {
    fn: kmac128,
    data: fromHex('00010203'),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex('3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'),
  },
  {
    fn: kmac128,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex('1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'),
  },

  {
    fn: kmac256,
    data: fromHex('00010203'),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex(
      '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'
    ),
  },
  {
    fn: kmac256,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: '',
    output: fromHex(
      '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'
    ),
  },
  {
    fn: kmac256,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex(
      'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965'
    ),
  },
];

for (let i = 0; i < KMAC_VECTORS.length; i++) {
  should(`KMAC ${i}`, () => {
    const v = KMAC_VECTORS[i];
    assert.deepStrictEqual(
      v.fn(v.key, v.data, { personalization: v.personalization, dkLen: v.dkLen }),
      v.output
    );
  });
}

should('Shake128: dkLen', () => {
  for (const dkLen of TYPE_TEST.int) assert.throws(() => shake128('test', { dkLen }));
});

should('Shake128', () => {
  for (let i = 0; i < 4096; i++) {
    const node = Uint8Array.from(crypto.createHash('shake128', { outputLength: i }).digest());
    assert.deepStrictEqual(shake128('', { dkLen: i }), node);
  }
});

should('Shake128', () => {
  for (let i = 0; i < 4096; i++) {
    const node = Uint8Array.from(crypto.createHash('shake256', { outputLength: i }).digest());
    assert.deepStrictEqual(shake256('', { dkLen: i }), node);
  }
});

if (require.main === module) should.run();
