import { hexToBytes } from '../../esm/utils.js';
import {
  cshake128,
  cshake256,
  k12,
  kmac128,
  kmac128xof,
  kmac256,
  kmac256xof,
  parallelhash128,
  parallelhash128xof,
  parallelhash256,
  parallelhash256xof,
  tuplehash128,
  tuplehash128xof,
  tuplehash256,
  tuplehash256xof,
  turboshake128,
  turboshake256,
} from '../../sha3-addons.js';
import { EMPTY, pattern, times } from '../utils.js';
const fromHex = (hex) => hexToBytes(hex.replace(/ |\n/gm, ''));

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
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf
  {
    fn: kmac128xof,
    data: fromHex('00010203'),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: '',
    output: fromHex('cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35'),
  },
  {
    fn: kmac128xof,
    data: fromHex('00010203'),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex('31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c'),
  },
  {
    fn: kmac128xof,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 32,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex('47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f'),
  },
  {
    fn: kmac256xof,
    data: fromHex('00010203'),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex(
      '1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b'
    ),
  },
  {
    fn: kmac256xof,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: '',
    output: fromHex(
      'ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02ca633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b'
    ),
  },
  {
    fn: kmac256xof,
    data: fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7'
    ),
    dkLen: 64,
    key: fromHex('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    personalization: 'My Tagged Application',
    output: fromHex(
      'd5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d'
    ),
  },
];

const T1 = fromHex('000102');
const T2 = fromHex('101112131415');
const T3 = fromHex('202122232425262728');
const TUPLE_VECTORS = [
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHash_samples.pdf
  {
    fn: tuplehash128,
    data: [T1, T2],
    personalization: '',
    dkLen: 32,
    output: fromHex('c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1'),
  },
  {
    fn: tuplehash128,
    data: [T1, T2],
    personalization: 'My Tuple App',
    dkLen: 32,
    output: fromHex('75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb'),
  },
  {
    fn: tuplehash128,
    data: [T1, T2, T3],
    personalization: 'My Tuple App',
    dkLen: 32,
    output: fromHex('e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84'),
  },
  {
    fn: tuplehash256,
    data: [T1, T2],
    personalization: '',
    dkLen: 64,
    output: fromHex(
      'cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194'
    ),
  },
  {
    fn: tuplehash256,
    data: [T1, T2],
    personalization: 'My Tuple App',
    dkLen: 64,
    output: fromHex(
      '147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e'
    ),
  },
  {
    fn: tuplehash256,
    data: [T1, T2, T3],
    personalization: 'My Tuple App',
    dkLen: 64,
    output: fromHex(
      '45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce'
    ),
  },
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHashXOF_samples.pdf
  {
    fn: tuplehash128xof,
    data: [T1, T2],
    personalization: '',
    dkLen: 32,
    output: fromHex('2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488'),
  },
  {
    fn: tuplehash128xof,
    data: [T1, T2],
    personalization: 'My Tuple App',
    dkLen: 32,
    output: fromHex('3fc8ad69453128292859a18b6c67d7ad85f01b32815e22ce839c49ec374e9b9a'),
  },
  {
    fn: tuplehash128xof,
    data: [T1, T2, T3],
    personalization: 'My Tuple App',
    dkLen: 32,
    output: fromHex('900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8'),
  },
  {
    fn: tuplehash256xof,
    data: [T1, T2],
    personalization: '',
    dkLen: 64,
    output: fromHex(
      '03ded4610ed6450a1e3f8bc44951d14fbc384ab0efe57b000df6b6df5aae7cd568e77377daf13f37ec75cf5fc598b6841d51dd207c991cd45d210ba60ac52eb9'
    ),
  },
  {
    fn: tuplehash256xof,
    data: [T1, T2],
    personalization: 'My Tuple App',
    dkLen: 64,
    output: fromHex(
      '6483cb3c9952eb20e830af4785851fc597ee3bf93bb7602c0ef6a65d741aeca7e63c3b128981aa05c6d27438c79d2754bb1b7191f125d6620fca12ce658b2442'
    ),
  },
  {
    fn: tuplehash256xof,
    data: [T1, T2, T3],
    personalization: 'My Tuple App',
    dkLen: 64,
    output: fromHex(
      '0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a2446284dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897'
    ),
  },
];

const PARALLEL_VECTORS = [
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHash_samples.pdf
  {
    fn: parallelhash128,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: '',
    dkLen: 32,
    output: fromHex('ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5'),
  },
  {
    fn: parallelhash128,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: 'Parallel Data',
    dkLen: 32,
    output: fromHex('fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206'),
  },
  {
    fn: parallelhash128,
    data: fromHex(
      '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b'
    ),
    blockLen: 12,
    personalization: 'Parallel Data',
    dkLen: 32,
    output: fromHex('f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc'),
  },
  {
    fn: parallelhash256,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: '',
    dkLen: 64,
    output: fromHex(
      'bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429'
    ),
  },
  {
    fn: parallelhash256,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: 'Parallel Data',
    dkLen: 64,
    output: fromHex(
      'cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110'
    ),
  },
  {
    fn: parallelhash256,
    data: fromHex(
      '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b'
    ),
    blockLen: 12,
    personalization: 'Parallel Data',
    dkLen: 64,
    output: fromHex(
      '69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9'
    ),
  },
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHashXOF_samples.pdf
  {
    fn: parallelhash128xof,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: '',
    dkLen: 32,
    output: fromHex('fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3'),
  },
  {
    fn: parallelhash128xof,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: 'Parallel Data',
    dkLen: 32,
    output: fromHex('ea2a793140820f7a128b8eb70a9439f93257c6e6e79b4a540d291d6dae7098d7'),
  },
  {
    fn: parallelhash128xof,
    data: fromHex(
      '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b'
    ),
    blockLen: 12,
    personalization: 'Parallel Data',
    dkLen: 32,
    output: fromHex('0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0'),
  },
  {
    fn: parallelhash256xof,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: '',
    dkLen: 64,
    output: fromHex(
      'c10a052722614684144d28474850b410757e3cba87651ba167a5cbddff7f466675fbf84bcae7378ac444be681d729499afca667fb879348bfdda427863c82f1c'
    ),
  },
  {
    fn: parallelhash256xof,
    data: fromHex('000102030405060710111213141516172021222324252627'),
    blockLen: 8,
    personalization: 'Parallel Data',
    dkLen: 64,
    output: fromHex(
      '538e105f1a22f44ed2f5cc1674fbd40be803d9c99bf5f8d90a2c8193f3fe6ea768e5c1a20987e2c9c65febed03887a51d35624ed12377594b5585541dc377efc'
    ),
  },
  {
    fn: parallelhash256xof,
    data: fromHex(
      '000102030405060708090a0b101112131415161718191a1b202122232425262728292a2b303132333435363738393a3b404142434445464748494a4b505152535455565758595a5b'
    ),
    blockLen: 12,
    personalization: 'Parallel Data',
    dkLen: 64,
    output: fromHex(
      '6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bcefb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249'
    ),
  },
];

const VECTORS_TURBO = [
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F
       54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `5A 22 3A D3 0B 3B 8C 66 A2 43 04 8C FC ED 43 0F
        54 E7 52 92 87 D1 51 50 B9 73 13 3A DF AC 6A 2F
        FE 27 08 E7 30 61 E0 9A 40 00 16 8B A9 C8 CA 18
        13 19 8F 7B BE D4 98 4B 41 85 F2 C2 58 0E E6 23`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 10032,
    D: 0x07,
    last: 32,
    exp: fromHex(
      `75 93 A2 80 20 A3 C4 AE 0D 60 5F D6 1F 5E B5 6E
      CC D2 7C C3 D1 2F F0 9F 78 36 97 72 A4 60 C5 5D`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 1),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `AC BD 4A A5 75 07 04 3B CE E5 5A D3 F4 85 04 D8
      15 E7 07 FE 82 EE 3D AD 6D 58 52 C8 92 0B 90 5E`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 2),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `7A 4D E8 B1 D9 27 A6 82 B9 29 61 01 03 F0 E9 64
      55 9B D7 45 42 CF AD 74 0E E3 D9 B0 36 46 9E 0A`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 3),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `74 52 ED 0E D8 60 AA 8F E8 E7 96 99 EC E3 24 F8
      D9 32 71 46 36 10 DA 76 80 1E BC EE 4F CA FE 42`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 4),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `CA 5F 1F 3E EA C9 92 CD C2 AB EB CA 0E 21 67 65
      DB F7 79 C3 C1 09 46 05 5A 94 AB 32 72 57 35 22`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 5),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `E9 88 19 3F B9 11 9F 11 CD 34 46 79 14 E2 A2 6D
      A9 BD F9 6C 8B EF 07 6A EE AD 1A 89 7B 86 63 83`
    ),
  },
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 6),
    dkLen: 32,
    D: 0x07,
    exp: fromHex(
      `9C 0F FB 98 7E EE ED AD FA 55 94 89 87 75 6D 09
      0B 67 CC B6 12 36 E3 06 AC 8A 24 DE 1D 0A F7 74`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x0b,
    exp: fromHex(
      `8B 03 5A B8 F8 EA 7B 41 02 17 16 74 58 33 2E 46
      F5 4B E4 FF 83 54 BA F3 68 71 04 A6 D2 4B 0E AB`
    ),
  },
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `C7 90 29 30 6B FA 2F 17 83 6A 3D 65 16 D5 56 63
      40 FE A6 EB 1A 11 39 AD 90 0B 41 24 3C 49 4B 37`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68
      7A 25 CB 05 C7 4C CA 1E 42 50 1A BD 83 87 4A 67`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `3D 03 98 8B B5 9E 68 18 51 A1 92 F4 29 AE 03 98
      8E 8F 44 4B C0 60 36 A3 F1 A7 D2 CC D7 58 D1 74`
    ),
  },
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `05 D9 AE 67 3D 5F 0E 48 BB 2B 57 E8 80 21 A1 A8
      3D 70 BA 85 92 3A A0 4C 12 E8 F6 5B A1 F9 45 95`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `4A 55 5B 06 EC F8 F1 53 8C CF 5C 95 15 D0 D0 49
      70 18 15 63 A6 23 81 C7 F0 C8 07 A6 D1 BD 9E 81
      97 80 4B FD E2 42 8B F7 29 61 EB 52 B4 18 9C 39
      1C EF 6F EE 66 3A 3C 1C E7 8B 88 25 5B C1 AC C3`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    D: 0x07,
    exp: fromHex(
      `40 22 1A D7 34 F3 ED C1 B1 06 BA D5 0A 72 94 93
      15 B3 52 BA 39 AD 98 B5 B3 C2 30 11 63 AD AA D0`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `66 D3 78 DF E4 E9 02 AC 4E B7 8F 7C 2E 5A 14 F0
      2B C1 C8 49 E6 21 BA E6 65 79 6F B3 34 6E 6C 79
      75 70 5B B9 3C 00 F3 CA 8F 83 BC A4 79 F0 69 77
      AB 3A 60 F3 97 96 B1 36 53 8A AA E8 BC AC 85 44`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 2),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `C5 21 74 AB F2 82 95 E1 5D FB 37 B9 46 AC 36 BD
      3A 6B CC 98 C0 74 FC 25 19 9E 05 30 42 5C C5 ED
      D4 DF D4 3D C3 E7 E6 49 1A 13 17 98 30 C3 C7 50
      C9 23 7E 83 FD 9A 3F EC 46 03 FF 57 E4 22 2E F2`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 3),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `62 A5 A0 BF F0 64 26 D7 1A 7A 3E 9E 3F 2F D6 E2
      52 FF 3F C1 88 A6 A5 36 EC A4 5A 49 A3 43 7C B3
      BC 3A 0F 81 49 C8 50 E6 E7 F4 74 7A 70 62 7F D2
      30 30 41 C6 C3 36 30 F9 43 AD 92 F8 E1 FF 43 90`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 4),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `52 3C 06 47 18 2D 89 41 F0 DD 5C 5C 0A B6 2D 4F
      C2 95 61 61 53 96 BB 5B 9A 9D EB 02 2B 80 C5 BF
      2D 83 A3 BB 36 FF C0 4F AC 58 CF 11 49 C6 6D EC
      4A 59 52 6E 51 F2 95 96 D8 24 42 1A 4B 84 B4 4D`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 5),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `D1 14 A1 C1 A2 08 FF 05 FD 49 D0 9E E0 35 46 5D
      86 54 7E BA D8 E9 AF 4F 8E 87 53 70 57 3D 6B 7B
      B2 0A B9 60 63 5A B5 74 E2 21 95 EF 9D 17 1C 9A
      28 01 04 4B 6E 2E DF 27 2E 23 02 55 4B 3A 77 C9`
    ),
  },
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 6),
    dkLen: 64,
    D: 0x07,
    exp: fromHex(
      `1E 51 34 95 D6 16 98 75 B5 94 53 A5 94 E0 8A E2
      71 CA 20 E0 56 43 C8 8A 98 7B 5B 6A B4 23 ED E7
      24 0F 34 F2 B3 35 FA 94 BC 4B 0D 70 E3 1F B6 33
      B0 79 84 43 31 FE A4 2A 9C 4D 79 BB 8C 5F 9E 73`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x0b,
    exp: fromHex(
      `C7 49 F7 FB 23 64 4A 02 1D 35 65 3D 1B FD F7 47
      CE CE 5F 97 39 F9 A3 44 AD 16 9F 10 90 6C 68 17
      C8 EE 12 78 4E 42 FF 57 81 4E FC 1C 89 87 89 D5
      E4 15 DB 49 05 2E A4 3A 09 90 1D 7A 82 A2 14 5C`
    ),
  },
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `FF 23 DC CD 62 16 8F 5A 44 46 52 49 A8 6D C1 0E
      8A AB 4B D2 6A 22 DE BF 23 48 02 0A 83 1C DB E1
      2C DD 36 A7 DD D3 1E 71 C0 1F 7C 97 A0 D4 C3 A0
      CC 1B 21 21 E6 B7 CE AB 38 87 A4 C9 A5 AF 8B 03`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57 E3
      DD 7D 07 05 6A 26 A3 03 C4 33 FA 35 33 45 52 80
      F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0 7B
      E3 2A 0A 97 2E 22 E6 3A DC 1B 09 0D AE FE 00 4B`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `E5 53 8C DD 28 30 2A 2E 81 E4 1F 65 FD 2A 40 52
      01 4D 0C D4 63 DF 67 1D 1E 51 0A 9D 95 C3 7D 71
      35 EF 27 28 43 0A 9E 31 70 04 F8 36 C9 A2 38 EF
      35 37 02 80 D0 3D CE 7F 06 12 F0 31 5B 3C BF 63`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    dkLen: 64,
    D: 0x06,
    exp: fromHex(
      `B3 8B 8C 15 F4 A6 E8 0C D3 EC 64 5F 99 9F 64 98
      AA D7 A5 9A 48 9C 1D EE 29 70 8B 4F 8A 59 E1 24
      99 A9 6F 89 37 22 56 FE 52 2B 1B 97 47 2A DD 73
      69 15 BD 4D F9 3B 21 FF E5 97 21 7E B3 C2 C6 D9`
    ),
  },
  // Additional vectors for default dkLen
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    // dkLen: 32,
    D: 0x06,
    exp: fromHex(
      `05 D9 AE 67 3D 5F 0E 48 BB 2B 57 E8 80 21 A1 A8
      3D 70 BA 85 92 3A A0 4C 12 E8 F6 5B A1 F9 45 95`
    ),
  },
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    D: 0x06,
    // dkLen: 64,
    exp: fromHex(
      `B3 8B 8C 15 F4 A6 E8 0C D3 EC 64 5F 99 9F 64 98
      AA D7 A5 9A 48 9C 1D EE 29 70 8B 4F 8A 59 E1 24
      99 A9 6F 89 37 22 56 FE 52 2B 1B 97 47 2A DD 73
      69 15 BD 4D F9 3B 21 FF E5 97 21 7E B3 C2 C6 D9`
    ),
  },
];

const VECTORS_K12 = [
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
      3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5
      42 69 C0 56 B8 C8 2E 48 27 60 38 B6 D2 92 96 6C
      C0 7A 3D 46 45 27 2E 31 FF 38 50 81 39 EB 0A 71`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    exp: fromHex(
      `E8 DC 56 36 42 F7 22 8C 84 68 4C 89 84 05 D3 A8
      34 79 91 58 C0 79 B1 28 80 27 7A 1D 28 E2 FF 6D`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 1),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `2B DA 92 45 0E 8B 14 7F 8A 7C B6 29 E7 84 A0 58
      EF CA 7C F7 D8 21 8E 02 D3 45 DF AA 65 24 4A 1F`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `6B F7 5F A2 23 91 98 DB 47 72 E3 64 78 F8 E1 9B
      0F 37 12 05 F6 A9 A9 3A 27 3F 51 DF 37 12 28 88`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `0C 31 5E BC DE DB F6 14 26 DE 7D CF 8F B7 25 D1
      E7 46 75 D7 F5 32 7A 50 67 F3 67 B1 08 EC B6 7C`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77
      2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `87 01 04 5E 22 20 53 45 FF 4D DA 05 55 5C BB 5C
      3A F1 A7 71 C2 B8 9B AE F3 7D B4 3D 99 98 B9 FE`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `84 4D 61 09 33 B1 B9 96 3C BD EB 5A E3 B6 B0 5C
      C7 CB D6 7C EE DF 88 3E B6 78 A0 A8 E0 37 16 82`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `3C 39 07 82 A8 A4 E8 9F A6 36 7F 72 FE AA F1 32
      55 C8 D9 58 78 48 1D 3C D8 CE 85 F5 8E 88 0A F8`
    ),
  },
  {
    hash: k12,
    msg: new Uint8Array(0),
    C: pattern(0xfa, 1),
    dkLen: 32,
    exp: fromHex(
      `FA B6 58 DB 63 E9 4A 24 61 88 BF 7A F6 9A 13 30
      45 F4 6E E9 84 C5 6E 3C 33 28 CA AF 1A A1 A5 83`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF'),
    C: pattern(0xfa, 41),
    dkLen: 32,
    exp: fromHex(
      `D8 48 C5 06 8C ED 73 6F 44 62 15 9B 98 67 FD 4C
      20 B8 08 AC C3 D5 BC 48 E0 B0 6B A0 A3 76 2E C4`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF FF FF'),
    C: pattern(0xfa, 41 ** 2),
    dkLen: 32,
    exp: fromHex(
      `C3 89 E5 00 9A E5 71 20 85 4C 2E 8C 64 67 0A C0
      13 58 CF 4C 1B AF 89 44 7A 72 42 34 DC 7C ED 74`
    ),
  },
  {
    hash: k12,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: pattern(0xfa, 41 ** 3),
    dkLen: 32,
    exp: fromHex(
      `75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9
      DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8191),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1B 57 76 36 F7 23 64 3E 99 0C C7 D6 A6 59 83 74
      36 FD 6A 10 36 26 60 0E B8 30 1C D1 DB E5 53 D6`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `48 F2 56 F6 77 2F 9E DF B6 A8 B6 61 EC 92 DC 93
      B9 5E BD 05 A0 8A 17 B3 9A E3 49 08 70 C9 26 C3`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8189),
    dkLen: 32,
    exp: fromHex(
      `3E D1 2F 70 FB 05 DD B5 86 89 51 0A B3 E4 D2 3C
      6C 60 33 84 9A A0 1E 1D 8C 22 0A 29 7F ED CD 0B`
    ),
  },
  {
    hash: k12,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8190),
    dkLen: 32,
    exp: fromHex(
      `6A 7C 1B 6A 5C D0 D8 C9 CA 94 3A 4A 21 6C C6 46
      04 55 9A 2E A4 5F 78 57 0A 15 25 3D 67 BA 00 AE`
    ),
  },
];

export {
  CSHAKE_VESTORS,
  K12_VECTORS,
  KMAC_VECTORS,
  M14_VECTORS,
  PARALLEL_VECTORS,
  TUPLE_VECTORS,
  VECTORS_K12,
  VECTORS_TURBO,
};
