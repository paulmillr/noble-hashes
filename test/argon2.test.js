const { deepStrictEqual } = require('assert');
const { describe, should } = require('micro-should');
const { argon2i, argon2d, argon2id } = require('../argon2');
const { argon2iAsync, argon2dAsync, argon2idAsync } = require('../argon2');
const { hexToBytes, bytesToHex } = require('./utils');

const asyncMap = new Map([
  [argon2i, argon2iAsync],
  [argon2d, argon2dAsync],
  [argon2id, argon2idAsync],
]);

const VECTORS = [
  {
    fn: argon2i,
    password: 'password',
    salt: 'saltysaltsaltysalt',
    m: 16,
    p: 2,
    t: 2,
    exp: 'a78e02964b20e856927be1a1ba5a6bffd700dc84e9e82f5e926600c8896ee2ce',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2d
  {
    fn: argon2d,
    version: 19,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2d_v16
  {
    fn: argon2d,
    version: 16,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: '96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2i
  {
    fn: argon2i,
    version: 19,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2i_v16
  {
    fn: argon2i,
    version: 16,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: '87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2id
  {
    fn: argon2id,
    version: 19,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/kats/argon2id_v16
  {
    fn: argon2id,
    version: 16,
    password: hexToBytes('0101010101010101010101010101010101010101010101010101010101010101'),
    salt: hexToBytes('02020202020202020202020202020202'),
    secret: hexToBytes('0303030303030303'),
    data: hexToBytes('040404040404040404040404'),
    m: 32,
    t: 3,
    p: 4,
    exp: 'b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0',
  },
  // https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 1048576,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9',
  }, // SLOW
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 262144,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 256,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 256,
    p: 2,
    password: 'password',
    salt: 'somesalt',
    exp: 'b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 1,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 4,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 65536,
    p: 1,
    password: 'differentpassword',
    salt: 'somesalt',
    exp: 'e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3',
  },
  {
    fn: argon2i,
    version: 0x10,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'diffsalt',
    exp: '79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497',
  },
  {
    fn: argon2i,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0',
  },
  {
    fn: argon2i,
    t: 2,
    m: 1048576,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'd1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41',
  },
  {
    fn: argon2i,
    t: 2,
    m: 262144,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb',
  },
  {
    fn: argon2i,
    t: 2,
    m: 256,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f',
  },
  {
    fn: argon2i,
    t: 2,
    m: 256,
    p: 2,
    password: 'password',
    salt: 'somesalt',
    exp: '4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61',
  },
  {
    fn: argon2i,
    t: 1,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'd168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf',
  }, // SLOW
  {
    fn: argon2i,
    t: 4,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b',
  },
  {
    fn: argon2i,
    t: 2,
    m: 65536,
    p: 1,
    password: 'differentpassword',
    salt: 'somesalt',
    exp: '14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee',
  },
  {
    fn: argon2i,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'diffsalt',
    exp: 'b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271',
  },
  {
    fn: argon2id,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
  },
  {
    fn: argon2id,
    t: 2,
    m: 262144,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c',
  },
  {
    fn: argon2id,
    t: 2,
    m: 256,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe',
  },
  {
    fn: argon2id,
    t: 2,
    m: 256,
    p: 2,
    password: 'password',
    salt: 'somesalt',
    exp: '6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037',
  },
  {
    fn: argon2id,
    t: 1,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: 'f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98',
  },
  {
    fn: argon2id,
    t: 4,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'somesalt',
    exp: '9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c',
  },
  {
    fn: argon2id,
    t: 2,
    m: 65536,
    p: 1,
    password: 'differentpassword',
    salt: 'somesalt',
    exp: '0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde',
  },
  {
    fn: argon2id,
    t: 2,
    m: 65536,
    p: 1,
    password: 'password',
    salt: 'diffsalt',
    exp: 'bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c',
  },
].filter((i) => !!i);

describe('Argon2', () => {
  for (let i = 0; i < VECTORS.length; i++) {
    const v = VECTORS[i];
    const ver = v.version || 0x13;
    should(`${v.fn.name}/v${ver} (${i})`, () => {
      const res = bytesToHex(
        v.fn(v.password, v.salt, {
          m: v.m,
          p: v.p,
          t: v.t,
          key: v.secret,
          personalization: v.data,
          version: v.version,
        })
      );
      deepStrictEqual(res, v.exp);
    });
    should(`${v.fn.name}/v${ver} (${i}): async`, async () => {
      const asyncFn = asyncMap.get(v.fn);
      const res = bytesToHex(
        await asyncFn(v.password, v.salt, {
          m: v.m,
          p: v.p,
          t: v.t,
          key: v.secret,
          personalization: v.data,
          version: v.version,
        })
      );
      deepStrictEqual(res, v.exp);
    });
  }
});

if (require.main === module) should.run();
