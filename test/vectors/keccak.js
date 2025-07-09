import {
  cshake128,
  cshake256,
  kmac128,
  kmac128xof,
  kmac256,
  kmac256xof,
  kt128,
  kt256,
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
} from '../../src/sha3-addons.ts';
import { hexToBytes } from '../../src/utils.ts';
import { pattern } from '../utils.ts';
const fromHex = (hex) => hexToBytes(hex.replace(/ |\n/gm, ''));

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

const TURBO_VECTORS = [
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

// https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/ (v17)
const K12_VECTORS = [
  // TurboSHAKE128(M=`00`^0, D=`1F`, 32):
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1E 41 5F 1C 59 83 AF F2 16 92 17 27 7D 17 BB 53
        8C D9 45 A3 97 DD EC 54 1F 1C E4 1A F2 C1 B7 4C`
    ),
  },
  // TurboSHAKE128(M=`00`^0, D=`1F`, 64):
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `1E 41 5F 1C 59 83 AF F2 16 92 17 27 7D 17 BB 53
        8C D9 45 A3 97 DD EC 54 1F 1C E4 1A F2 C1 B7 4C
        3E 8C CA E2 A4 DA E5 6C 84 A0 4C 23 85 C0 3C 15
        E8 19 3B DF 58 73 73 63 32 16 91 C0 54 62 C8 DF`
    ),
  },
  // TurboSHAKE128(M=`00`^0, D=`1F`, 10032), last 32 bytes:
  {
    hash: turboshake128,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    exp: fromHex(
      `A3 B9 B0 38 59 00 CE 76 1F 22 AE D5 48 E7 54 DA
        10 A5 24 2D 62 E8 C6 58 E3 F3 A9 23 A7 55 56 07`
    ),
  },
  // TurboSHAKE128(M=ptn(17**0 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `55 CE DD 6F 60 AF 7B B2 9A 40 42 AE 83 2E F3 F5
        8D B7 29 9F 89 3E BB 92 47 24 7D 85 69 58 DA A9`
    ),
  },
  // TurboSHAKE128(M=ptn(17**1 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 1),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `9C 97 D0 36 A3 BA C8 19 DB 70 ED E0 CA 55 4E C6
        E4 C2 A1 A4 FF BF D9 EC 26 9C A6 A1 11 16 12 33`
    ),
  },
  // TurboSHAKE128(M=ptn(17**2 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `96 C7 7C 27 9E 01 26 F7 FC 07 C9 B0 7F 5C DA E1
        E0 BE 60 BD BE 10 62 00 40 E7 5D 72 23 A6 24 D2`
    ),
  },
  // TurboSHAKE128(M=ptn(17**3 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `D4 97 6E B5 6B CF 11 85 20 58 2B 70 9F 73 E1 D6
        85 3E 00 1F DA F8 0E 1B 13 E0 D0 59 9D 5F B3 72`
    ),
  },
  // TurboSHAKE128(M=ptn(17**4 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `DA 67 C7 03 9E 98 BF 53 0C F7 A3 78 30 C6 66 4E
        14 CB AB 7F 54 0F 58 40 3B 1B 82 95 13 18 EE 5C`
    ),
  },
  // TurboSHAKE128(M=ptn(17**5 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `B9 7A 90 6F BF 83 EF 7C 81 25 17 AB F3 B2 D0 AE
        A0 C4 F6 03 18 CE 11 CF 10 39 25 12 7F 59 EE CD`
    ),
  },
  // TurboSHAKE128(M=ptn(17**6 bytes), D=`1F`, 32):
  {
    hash: turboshake128,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `35 CD 49 4A DE DE D2 F2 52 39 AF 09 A7 B8 EF 0C
        4D 1C A4 FE 2D 1A C3 70 FA 63 21 6F E7 B4 C2 B1`
    ),
  },
  // TurboSHAKE128(M=`FF FF FF`, D=`01`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x01,
    dkLen: 32,
    exp: fromHex(
      `BF 32 3F 94 04 94 E8 8E E1 C5 40 FE 66 0B E8 A0
        C9 3F 43 D1 5E C0 06 99 84 62 FA 99 4E ED 5D AB`
    ),
  },
  // TurboSHAKE128(M=`FF`, D=`06`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF'),
    C: new Uint8Array(0),
    D: 0x06,
    dkLen: 32,
    exp: fromHex(
      `8E C9 C6 64 65 ED 0D 4A 6C 35 D1 35 06 71 8D 68
        7A 25 CB 05 C7 4C CA 1E 42 50 1A BD 83 87 4A 67`
    ),
  },
  // TurboSHAKE128(M=`FF FF FF`, D=`07`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x07,
    dkLen: 32,
    exp: fromHex(
      `B6 58 57 60 01 CA D9 B1 E5 F3 99 A9 F7 77 23 BB
        A0 54 58 04 2D 68 20 6F 72 52 68 2D BA 36 63 ED`
    ),
  },
  // TurboSHAKE128(M=`FF FF FF FF FF FF FF`, D=`0B`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: new Uint8Array(0),
    D: 0x0b,
    dkLen: 32,
    exp: fromHex(
      `8D EE AA 1A EC 47 CC EE 56 9F 65 9C 21 DF A8 E1
        12 DB 3C EE 37 B1 81 78 B2 AC D8 05 B7 99 CC 37`
    ),
  },
  // TurboSHAKE128(M=`FF`, D=`30`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF'),
    C: new Uint8Array(0),
    D: 0x30,
    dkLen: 32,
    exp: fromHex(
      `55 31 22 E2 13 5E 36 3C 32 92 BE D2 C6 42 1F A2
        32 BA B0 3D AA 07 C7 D6 63 66 03 28 65 06 32 5B`
    ),
  },
  // TurboSHAKE128(M=`FF FF FF`, D=`7F`, 32):
  {
    hash: turboshake128,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x7f,
    dkLen: 32,
    exp: fromHex(
      `16 27 4C C6 56 D4 4C EF D4 22 39 5D 0F 90 53 BD
        A6 D2 8E 12 2A BA 15 C7 65 E5 AD 0E 6E AF 26 F9`
    ),
  },
  // TurboSHAKE256(M=`00`^0, D=`1F`, 64):
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `36 7A 32 9D AF EA 87 1C 78 02 EC 67 F9 05 AE 13
        C5 76 95 DC 2C 66 63 C6 10 35 F5 9A 18 F8 E7 DB
        11 ED C0 E1 2E 91 EA 60 EB 6B 32 DF 06 DD 7F 00
        2F BA FA BB 6E 13 EC 1C C2 0D 99 55 47 60 0D B0`
    ),
  },
  // TurboSHAKE256(M=`00`^0, D=`1F`, 10032), last 32 bytes:
  {
    hash: turboshake256,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    exp: fromHex(
      `AB EF A1 16 30 C6 61 26 92 49 74 26 85 EC 08 2F
        20 72 65 DC CF 2F 43 53 4E 9C 61 BA 0C 9D 1D 75`
    ),
  },
  // TurboSHAKE256(M=ptn(17**0 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `3E 17 12 F9 28 F8 EA F1 05 46 32 B2 AA 0A 24 6E
        D8 B0 C3 78 72 8F 60 BC 97 04 10 15 5C 28 82 0E
        90 CC 90 D8 A3 00 6A A2 37 2C 5C 5E A1 76 B0 68
        2B F2 2B AE 74 67 AC 94 F7 4D 43 D3 9B 04 82 E2`
    ),
  },
  // TurboSHAKE256(M=ptn(17**1 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 1),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `B3 BA B0 30 0E 6A 19 1F BE 61 37 93 98 35 92 35
        78 79 4E A5 48 43 F5 01 10 90 FA 2F 37 80 A9 E5
        CB 22 C5 9D 78 B4 0A 0F BF F9 E6 72 C0 FB E0 97
        0B D2 C8 45 09 1C 60 44 D6 87 05 4D A5 D8 E9 C7`
    ),
  },
  // TurboSHAKE256(M=ptn(17**2 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `66 B8 10 DB 8E 90 78 04 24 C0 84 73 72 FD C9 57
        10 88 2F DE 31 C6 DF 75 BE B9 D4 CD 93 05 CF CA
        E3 5E 7B 83 E8 B7 E6 EB 4B 78 60 58 80 11 63 16
        FE 2C 07 8A 09 B9 4A D7 B8 21 3C 0A 73 8B 65 C0`
    ),
  },
  // TurboSHAKE256(M=ptn(17**3 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `C7 4E BC 91 9A 5B 3B 0D D1 22 81 85 BA 02 D2 9E
        F4 42 D6 9D 3D 42 76 A9 3E FE 0B F9 A1 6A 7D C0
        CD 4E AB AD AB 8C D7 A5 ED D9 66 95 F5 D3 60 AB
        E0 9E 2C 65 11 A3 EC 39 7D A3 B7 6B 9E 16 74 FB`
    ),
  },
  // TurboSHAKE256(M=ptn(17**4 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `02 CC 3A 88 97 E6 F4 F6 CC B6 FD 46 63 1B 1F 52
        07 B6 6C 6D E9 C7 B5 5B 2D 1A 23 13 4A 17 0A FD
        AC 23 4E AB A9 A7 7C FF 88 C1 F0 20 B7 37 24 61
        8C 56 87 B3 62 C4 30 B2 48 CD 38 64 7F 84 8A 1D`
    ),
  },
  // TurboSHAKE256(M=ptn(17**5 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `AD D5 3B 06 54 3E 58 4B 58 23 F6 26 99 6A EE 50
        FE 45 ED 15 F2 02 43 A7 16 54 85 AC B4 AA 76 B4
        FF DA 75 CE DF 6D 8C DC 95 C3 32 BD 56 F4 B9 86
        B5 8B B1 7D 17 78 BF C1 B1 A9 75 45 CD F4 EC 9F`
    ),
  },
  // TurboSHAKE256(M=ptn(17**6 bytes), D=`1F`, 64):
  {
    hash: turboshake256,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `9E 11 BC 59 C2 4E 73 99 3C 14 84 EC 66 35 8E F7
        1D B7 4A EF D8 4E 12 3F 78 00 BA 9C 48 53 E0 2C
        FE 70 1D 9E 6B B7 65 A3 04 F0 DC 34 A4 EE 3B A8
        2C 41 0F 0D A7 0E 86 BF BD 90 EA 87 7C 2D 61 04`
    ),
  },
  // TurboSHAKE256(M=`FF FF FF`, D=`01`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x01,
    dkLen: 64,
    exp: fromHex(
      `D2 1C 6F BB F5 87 FA 22 82 F2 9A EA 62 01 75 FB
        02 57 41 3A F7 8A 0B 1B 2A 87 41 9C E0 31 D9 33
        AE 7A 4D 38 33 27 A8 A1 76 41 A3 4F 8A 1D 10 03
        AD 7D A6 B7 2D BA 84 BB 62 FE F2 8F 62 F1 24 24`
    ),
  },
  // TurboSHAKE256(M=`FF`, D=`06`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF'),
    C: new Uint8Array(0),
    D: 0x06,
    dkLen: 64,
    exp: fromHex(
      `73 8D 7B 4E 37 D1 8B 7F 22 AD 1B 53 13 E3 57 E3
        DD 7D 07 05 6A 26 A3 03 C4 33 FA 35 33 45 52 80
        F4 F5 A7 D4 F7 00 EF B4 37 FE 6D 28 14 05 E0 7B
        E3 2A 0A 97 2E 22 E6 3A DC 1B 09 0D AE FE 00 4B`
    ),
  },
  // TurboSHAKE256(M=`FF FF FF`, D=`07`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x07,
    dkLen: 64,
    exp: fromHex(
      `18 B3 B5 B7 06 1C 2E 67 C1 75 3A 00 E6 AD 7E D7
        BA 1C 90 6C F9 3E FB 70 92 EA F2 7F BE EB B7 55
        AE 6E 29 24 93 C1 10 E4 8D 26 00 28 49 2B 8E 09
        B5 50 06 12 B8 F2 57 89 85 DE D5 35 7D 00 EC 67`
    ),
  },
  //  TurboSHAKE256(M=`FF FF FF FF FF FF FF`, D=`0B`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: new Uint8Array(0),
    D: 0x0b,
    dkLen: 64,
    exp: fromHex(
      `BB 36 76 49 51 EC 97 E9 D8 5F 7E E9 A6 7A 77 18
        FC 00 5C F4 25 56 BE 79 CE 12 C0 BD E5 0E 57 36
        D6 63 2B 0D 0D FB 20 2D 1B BB 8F FE 3D D7 4C B0
        08 34 FA 75 6C B0 34 71 BA B1 3A 1E 2C 16 B3 C0`
    ),
  },
  //  TurboSHAKE256(M=`FF`, D=`30`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF'),
    C: new Uint8Array(0),
    D: 0x30,
    dkLen: 64,
    exp: fromHex(
      `F3 FE 12 87 3D 34 BC BB 2E 60 87 79 D6 B7 0E 7F
        86 BE C7 E9 0B F1 13 CB D4 FD D0 C4 E2 F4 62 5E
        14 8D D7 EE 1A 52 77 6C F7 7F 24 05 14 D9 CC FC
        3B 5D DA B8 EE 25 5E 39 EE 38 90 72 96 2C 11 1A`
    ),
  },
  // TurboSHAKE256(M=`FF FF FF`, D=`7F`, 64):
  {
    hash: turboshake256,
    msg: fromHex('FF FF FF'),
    C: new Uint8Array(0),
    D: 0x7f,
    dkLen: 64,
    exp: fromHex(
      `AB E5 69 C1 F7 7E C3 40 F0 27 05 E7 D3 7C 9A B7
        E1 55 51 6E 4A 6A 15 00 21 D7 0B 6F AC 0B B4 0C
        06 9F 9A 98 28 A0 D5 75 CD 99 F9 BA E4 35 AB 1A
        CF 7E D9 11 0B A9 7C E0 38 8D 07 4B AC 76 87 76`
    ),
  },
  // KT128(M=`00`^0, C=`00`^0, 32):
  {
    hash: kt128,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1A C2 D4 50 FC 3B 42 05 D1 9D A7 BF CA 1B 37 51
        3C 08 03 57 7A C7 16 7F 06 FE 2C E1 F0 EF 39 E5`
    ),
  },
  //   KT128(M=`00`^0, C=`00`^0, 64):
  {
    hash: kt128,
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
  // KT128(M=`00`^0, C=`00`^0, 10032), last 32 bytes:
  {
    hash: kt128,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10032,
    last: 32,
    exp: fromHex(
      `E8 DC 56 36 42 F7 22 8C 84 68 4C 89 84 05 D3 A8
        34 79 91 58 C0 79 B1 28 80 27 7A 1D 28 E2 FF 6D`
    ),
  },
  // KT128(M=ptn(1 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 0),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `2B DA 92 45 0E 8B 14 7F 8A 7C B6 29 E7 84 A0 58
        EF CA 7C F7 D8 21 8E 02 D3 45 DF AA 65 24 4A 1F`
    ),
  },
  // KT128(M=ptn(17 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 1),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `6B F7 5F A2 23 91 98 DB 47 72 E3 64 78 F8 E1 9B
        0F 37 12 05 F6 A9 A9 3A 27 3F 51 DF 37 12 28 88`
    ),
  },
  // KT128(M=ptn(17**2 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `0C 31 5E BC DE DB F6 14 26 DE 7D CF 8F B7 25 D1
        E7 46 75 D7 F5 32 7A 50 67 F3 67 B1 08 EC B6 7C`
    ),
  },
  // KT128(M=ptn(17**3 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `CB 55 2E 2E C7 7D 99 10 70 1D 57 8B 45 7D DF 77
        2C 12 E3 22 E4 EE 7F E4 17 F9 2C 75 8F 0D 59 D0`
    ),
  },
  // KT128(M=ptn(17**4 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `87 01 04 5E 22 20 53 45 FF 4D DA 05 55 5C BB 5C
        3A F1 A7 71 C2 B8 9B AE F3 7D B4 3D 99 98 B9 FE`
    ),
  },
  // KT128(M=ptn(17**5 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `84 4D 61 09 33 B1 B9 96 3C BD EB 5A E3 B6 B0 5C
        C7 CB D6 7C EE DF 88 3E B6 78 A0 A8 E0 37 16 82`
    ),
  },
  // KT128(M=ptn(17**6 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `3C 39 07 82 A8 A4 E8 9F A6 36 7F 72 FE AA F1 32
        55 C8 D9 58 78 48 1D 3C D8 CE 85 F5 8E 88 0A F8`
    ),
  },
  // KT128(`00`^0, C=ptn(1 bytes), 32):
  {
    hash: kt128,
    msg: new Uint8Array(0),
    C: pattern(0xfa, 1),
    dkLen: 32,
    exp: fromHex(
      `FA B6 58 DB 63 E9 4A 24 61 88 BF 7A F6 9A 13 30
      45 F4 6E E9 84 C5 6E 3C 33 28 CA AF 1A A1 A5 83`
    ),
  },
  // KT128(`FF`, C=ptn(41 bytes), 32):
  {
    hash: kt128,
    msg: fromHex('FF'),
    C: pattern(0xfa, 41 ** 1),
    dkLen: 32,
    exp: fromHex(
      `D8 48 C5 06 8C ED 73 6F 44 62 15 9B 98 67 FD 4C
        20 B8 08 AC C3 D5 BC 48 E0 B0 6B A0 A3 76 2E C4`
    ),
  },
  // KT128(`FF FF FF`, C=ptn(41**2 bytes), 32):
  {
    hash: kt128,
    msg: fromHex('FF FF FF'),
    C: pattern(0xfa, 41 ** 2),
    dkLen: 32,
    exp: fromHex(
      `C3 89 E5 00 9A E5 71 20 85 4C 2E 8C 64 67 0A C0
        13 58 CF 4C 1B AF 89 44 7A 72 42 34 DC 7C ED 74`
    ),
  },
  // KT128(`FF FF FF FF FF FF FF`, C=ptn(41**3 bytes), 32):
  {
    hash: kt128,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: pattern(0xfa, 41 ** 3),
    dkLen: 32,
    exp: fromHex(
      `75 D2 F8 6A 2E 64 45 66 72 6B 4F BC FC 56 57 B9
        DB CF 07 0C 7B 0D CA 06 45 0A B2 91 D7 44 3B CF`
    ),
  },
  // KT128(M=ptn(8191 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 8191),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `1B 57 76 36 F7 23 64 3E 99 0C C7 D6 A6 59 83 74
        36 FD 6A 10 36 26 60 0E B8 30 1C D1 DB E5 53 D6`
    ),
  },
  // KT128(M=ptn(8192 bytes), C=`00`^0, 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 8192),
    C: new Uint8Array(0),
    dkLen: 32,
    exp: fromHex(
      `48 F2 56 F6 77 2F 9E DF B6 A8 B6 61 EC 92 DC 93
        B9 5E BD 05 A0 8A 17 B3 9A E3 49 08 70 C9 26 C3`
    ),
  },
  // KT128(M=ptn(8192 bytes), C=ptn(8189 bytes), 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8189),
    dkLen: 32,
    exp: fromHex(
      `3E D1 2F 70 FB 05 DD B5 86 89 51 0A B3 E4 D2 3C
        6C 60 33 84 9A A0 1E 1D 8C 22 0A 29 7F ED CD 0B`
    ),
  },
  // KT128(M=ptn(8192 bytes), C=ptn(8190 bytes), 32):
  {
    hash: kt128,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8190),
    dkLen: 32,
    exp: fromHex(
      `6A 7C 1B 6A 5C D0 D8 C9 CA 94 3A 4A 21 6C C6 46
        04 55 9A 2E A4 5F 78 57 0A 15 25 3D 67 BA 00 AE`
    ),
  },
  // KT256(M=`00`^0, C=`00`^0, 64):
  {
    hash: kt256,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `B2 3D 2E 9C EA 9F 49 04 E0 2B EC 06 81 7F C1 0C
        E3 8C E8 E9 3E F4 C8 9E 65 37 07 6A F8 64 64 04
        E3 E8 B6 81 07 B8 83 3A 5D 30 49 0A A3 34 82 35
        3F D4 AD C7 14 8E CB 78 28 55 00 3A AE BD E4 A9`
    ),
  },
  // KT256(M=`00`^0, C=`00`^0, 128):
  {
    hash: kt256,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 128,
    exp: fromHex(
      `B2 3D 2E 9C EA 9F 49 04 E0 2B EC 06 81 7F C1 0C
        E3 8C E8 E9 3E F4 C8 9E 65 37 07 6A F8 64 64 04
        E3 E8 B6 81 07 B8 83 3A 5D 30 49 0A A3 34 82 35
        3F D4 AD C7 14 8E CB 78 28 55 00 3A AE BD E4 A9
        B0 92 53 19 D8 EA 1E 12 1A 60 98 21 EC 19 EF EA
        89 E6 D0 8D AE E1 66 2B 69 C8 40 28 9F 18 8B A8
        60 F5 57 60 B6 1F 82 11 4C 03 0C 97 E5 17 84 49
        60 8C CD 2C D2 D9 19 FC 78 29 FF 69 93 1A C4 D0`
    ),
  },
  // KT256(M=`00`^0, C=`00`^0, 10064), last 64 bytes:
  {
    hash: kt256,
    msg: new Uint8Array(0),
    C: new Uint8Array(0),
    dkLen: 10064,
    last: 64,
    exp: fromHex(
      `AD 4A 1D 71 8C F9 50 50 67 09 A4 C3 33 96 13 9B
        44 49 04 1F C7 9A 05 D6 8D A3 5F 1E 45 35 22 E0
        56 C6 4F E9 49 58 E7 08 5F 29 64 88 82 59 B9 93
        27 52 F3 CC D8 55 28 8E FE E5 FC BB 8B 56 30 69`
    ),
  },
  // KT256(M=ptn(1 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 0),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `0D 00 5A 19 40 85 36 02 17 12 8C F1 7F 91 E1 F7
        13 14 EF A5 56 45 39 D4 44 91 2E 34 37 EF A1 7F
        82 DB 6F 6F FE 76 E7 81 EA A0 68 BC E0 1F 2B BF
        81 EA CB 98 3D 72 30 F2 FB 02 83 4A 21 B1 DD D0`
    ),
  },
  // KT256(M=ptn(17 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 1),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `1B A3 C0 2B 1F C5 14 47 4F 06 C8 97 99 78 A9 05
        6C 84 83 F4 A1 B6 3D 0D CC EF E3 A2 8A 2F 32 3E
        1C DC CA 40 EB F0 06 AC 76 EF 03 97 15 23 46 83
        7B 12 77 D3 E7 FA A9 C9 65 3B 19 07 50 98 52 7B`
    ),
  },
  // KT256(M=ptn(17**2 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 2),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `DE 8C CB C6 3E 0F 13 3E BB 44 16 81 4D 4C 66 F6
        91 BB F8 B6 A6 1E C0 A7 70 0F 83 6B 08 6C B0 29
        D5 4F 12 AC 71 59 47 2C 72 DB 11 8C 35 B4 E6 AA
        21 3C 65 62 CA AA 9D CC 51 89 59 E6 9B 10 F3 BA`
    ),
  },
  // KT256(M=ptn(17**3 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 3),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `64 7E FB 49 FE 9D 71 75 00 17 1B 41 E7 F1 1B D4
        91 54 44 43 20 99 97 CE 1C 25 30 D1 5E B1 FF BB
        59 89 35 EF 95 45 28 FF C1 52 B1 E4 D7 31 EE 26
        83 68 06 74 36 5C D1 91 D5 62 BA E7 53 B8 4A A5`
    ),
  },
  // KT256(M=ptn(17**4 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 4),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `B0 62 75 D2 84 CD 1C F2 05 BC BE 57 DC CD 3E C1
        FF 66 86 E3 ED 15 77 63 83 E1 F2 FA 3C 6A C8 F0
        8B F8 A1 62 82 9D B1 A4 4B 2A 43 FF 83 DD 89 C3
        CF 1C EB 61 ED E6 59 76 6D 5C CF 81 7A 62 BA 8D`
    ),
  },
  // KT256(M=ptn(17**5 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 5),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `94 73 83 1D 76 A4 C7 BF 77 AC E4 5B 59 F1 45 8B
        16 73 D6 4B CD 87 7A 7C 66 B2 66 4A A6 DD 14 9E
        60 EA B7 1B 5C 2B AB 85 8C 07 4D ED 81 DD CE 2B
        40 22 B5 21 59 35 C0 D4 D1 9B F5 11 AE EB 07 72`
    ),
  },
  // KT256(M=ptn(17**6 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 17 ** 6),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `06 52 B7 40 D7 8C 5E 1F 7C 8D CC 17 77 09 73 82
        76 8B 7F F3 8F 9A 7A 20 F2 9F 41 3B B1 B3 04 5B
        31 A5 57 8F 56 8F 91 1E 09 CF 44 74 6D A8 42 24
        A5 26 6E 96 A4 A5 35 E8 71 32 4E 4F 9C 70 04 DA`
    ),
  },
  // KT256(`00`^0, C=ptn(1 bytes), 64):
  {
    hash: kt256,
    msg: new Uint8Array(0),
    C: pattern(0xfa, 1),
    dkLen: 64,
    exp: fromHex(
      `92 80 F5 CC 39 B5 4A 5A 59 4E C6 3D E0 BB 99 37
        1E 46 09 D4 4B F8 45 C2 F5 B8 C3 16 D7 2B 15 98
        11 F7 48 F2 3E 3F AB BE 5C 32 26 EC 96 C6 21 86
        DF 2D 33 E9 DF 74 C5 06 9C EE CB B4 DD 10 EF F6`
    ),
  },
  // KT256(`FF`, C=ptn(41 bytes), 64):
  {
    hash: kt256,
    msg: fromHex('FF'),
    C: pattern(0xfa, 41),
    dkLen: 64,
    exp: fromHex(
      `47 EF 96 DD 61 6F 20 09 37 AA 78 47 E3 4E C2 FE
        AE 80 87 E3 76 1D C0 F8 C1 A1 54 F5 1D C9 CC F8
        45 D7 AD BC E5 7F F6 4B 63 97 22 C6 A1 67 2E 3B
        F5 37 2D 87 E0 0A FF 89 BE 97 24 07 56 99 88 53`
    ),
  },
  // KT256(`FF FF FF`, C=ptn(41**2 bytes), 64):
  {
    hash: kt256,
    msg: fromHex('FF FF FF'),
    C: pattern(0xfa, 41 ** 2),
    dkLen: 64,
    exp: fromHex(
      `3B 48 66 7A 50 51 C5 96 6C 53 C5 D4 2B 95 DE 45
        1E 05 58 4E 78 06 E2 FB 76 5E DA 95 90 74 17 2C
        B4 38 A9 E9 1D DE 33 7C 98 E9 C4 1B ED 94 C4 E0
        AE F4 31 D0 B6 4E F2 32 4F 79 32 CA A6 F5 49 69`
    ),
  },
  //  KT256(`FF FF FF FF FF FF FF`, C=ptn(41**3 bytes), 64):
  {
    hash: kt256,
    msg: fromHex('FF FF FF FF FF FF FF'),
    C: pattern(0xfa, 41 ** 3),
    dkLen: 64,
    exp: fromHex(
      `E0 91 1C C0 00 25 E1 54 08 31 E2 66 D9 4A DD 9B
        98 71 21 42 B8 0D 26 29 E6 43 AA C4 EF AF 5A 3A
        30 A8 8C BF 4A C2 A9 1A 24 32 74 30 54 FB CC 98
        97 67 0E 86 BA 8C EC 2F C2 AC E9 C9 66 36 97 24`
    ),
  },
  // KT256(M=ptn(8191 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 8191),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `30 81 43 4D 93 A4 10 8D 8D 8A 33 05 B8 96 82 CE
        BE DC 7C A4 EA 8A 3C E8 69 FB B7 3C BE 4A 58 EE
        F6 F2 4D E3 8F FC 17 05 14 C7 0E 7A B2 D0 1F 03
        81 26 16 E8 63 D7 69 AF B3 75 31 93 BA 04 5B 20`
    ),
  },
  // KT256(M=ptn(8192 bytes), C=`00`^0, 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 8192),
    C: new Uint8Array(0),
    dkLen: 64,
    exp: fromHex(
      `C6 EE 8E 2A D3 20 0C 01 8A C8 7A AA 03 1C DA C2
        21 21 B4 12 D0 7D C6 E0 DC CB B5 34 23 74 7E 9A
        1C 18 83 4D 99 DF 59 6C F0 CF 4B 8D FA FB 7B F0
        2D 13 9D 0C 90 35 72 5A DC 1A 01 B7 23 0A 41 FA`
    ),
  },
  // KT256(M=ptn(8192 bytes), C=ptn(8189 bytes), 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8189),
    dkLen: 64,
    exp: fromHex(
      `74 E4 78 79 F1 0A 9C 5D 11 BD 2D A7 E1 94 FE 57
        E8 63 78 BF 3C 3F 74 48 EF F3 C5 76 A0 F1 8C 5C
        AA E0 99 99 79 51 20 90 A7 F3 48 AF 42 60 D4 DE
        3C 37 F1 EC AF 8D 2C 2C 96 C1 D1 6C 64 B1 24 96`
    ),
  },
  // KT256(M=ptn(8192 bytes), C=ptn(8190 bytes), 64):
  {
    hash: kt256,
    msg: pattern(0xfa, 8192),
    C: pattern(0xfa, 8190),
    dkLen: 64,
    exp: fromHex(
      `F4 B5 90 8B 92 9F FE 01 E0 F7 9E C2 F2 12 43 D4
        1A 39 6B 2E 73 03 A6 AF 1D 63 99 CD 6C 7A 0A 2D
        D7 C4 F6 07 E8 27 7F 9C 9B 1C B4 AB 9D DC 59 D4
        B9 2D 1F C7 55 84 41 F1 83 2C 32 79 A4 24 1B 8B`
    ),
  },
];

export {
  CSHAKE_VESTORS,
  K12_VECTORS,
  KMAC_VECTORS,
  PARALLEL_VECTORS,
  TUPLE_VECTORS,
  TURBO_VECTORS,
};
