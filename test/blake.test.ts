import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { blake224, blake256, blake384, blake512 } from '../src/blake1.ts';
import { blake2b, blake2s } from '../src/blake2.ts';
import { blake3 } from '../src/blake3.ts';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { TYPE_TEST, json, pattern } from './utils.ts';

const blake1_vectors = [
  {
    input: new Uint8Array(0),
    blake224: '7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed',
    blake256: '716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a',
    blake384:
      'c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706',
    blake512:
      'a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8',
  },
  {
    input: bytesToHex(utf8ToBytes('The quick brown fox jumps over the lazy dog')),
    blake256: '7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7',
  },
  {
    input: bytesToHex(utf8ToBytes('BLAKE')),
    blake256: '07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6',
  },
  {
    input: bytesToHex(utf8ToBytes('')),
    blake256: '716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a',
  },
  {
    input: bytesToHex(utf8ToBytes("'BLAKE wins SHA-3! Hooray!!!' (I have time machine)")),
    blake256: '18a393b4e62b1887a2edf79a5c5a5464daf5bbb976f4007bea16a73e4c1e198e',
  },
  {
    input: bytesToHex(utf8ToBytes('Go')),
    blake256: 'fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2',
  },
  {
    input: bytesToHex(utf8ToBytes("HELP! I'm trapped in hash!")),
    blake256: '1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711',
  },
  {
    input: bytesToHex(utf8ToBytes('1111111111111111111111111111111111111111111111111111111')),
    blake256: '8390ba773e45e42aa3913ff0109b81e6ef57e11554880b23b1dd27980a9b046f',
  },
  {
    input: bytesToHex(utf8ToBytes('11111111111111111111111111111111111111111111111111111111')),
    blake256: '731cb9580ccb3c1de397547f6e825ddf7a67d75b56d65612a0138d9ae582af41',
  },

  {
    input: bytesToHex(
      utf8ToBytes(
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu'
      )
    ),
    blake256: 'af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a',
  },
  {
    input: bytesToHex(
      utf8ToBytes(
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est.'
      )
    ),
    blake256: '4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08',
  },
  {
    input: '00',
    blake224: '4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5',
    blake256: '0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87',
    blake384:
      '10281f67e135e90ae8e882251a355510a719367ad70227b137343e1bc122015c29391e8545b5272d13a7c2879da3d807',
    blake512:
      '97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3',
  },
  {
    input:
      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    blake224: 'f5aa00dd1cb847e3140372af7b5c46b4888d82c8c0a917913cfb5d04',
    blake256: 'd419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41',
  },
  {
    input:
      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    blake384:
      '0b9845dd429566cdab772ba195d271effe2d0211f16991d766ba749447c5cde569780b2daa66c4b224a2ec2e5d09174c',
    blake512:
      '313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde',
  },
];

describe('blake', () => {
  should('Blake1 vectors', () => {
    for (const v of blake1_vectors) {
      const msg = typeof v.input === 'string' ? hexToBytes(v.input, 'hex') : v.input;
      if (v.blake224) eql(bytesToHex(blake224(msg)), v.blake224);
      if (v.blake256) eql(bytesToHex(blake256(msg)), v.blake256);
      if (v.blake384) eql(bytesToHex(blake384(msg)), v.blake384);
      if (v.blake512) eql(bytesToHex(blake512(msg)), v.blake512);
    }
  });
  // https://github.com/dchest/blake256/blob/master/blake256_test.go
  should('blake1-256 salt', () => {
    const VECTORS = [
      {
        input: '',
        salt: '1234567890123456',
        exp: '561d6d0cfa3d31d5eedaf2d575f3942539b03522befc2a1196ba0e51af8992a8',
      },
      {
        input: "It's so salty out there!",
        salt: 'SALTsaltSaltSALT',
        exp: '88cc11889bbbee42095337fe2153c591971f94fbf8fe540d3c7e9f1700ab2d0c',
      },
    ];
    for (const { input: inp, salt: salts, exp } of VECTORS) {
      const input = utf8ToBytes(inp);
      const salt = utf8ToBytes(salts);
      eql(bytesToHex(blake256.create({ salt }).update(input).digest()), exp);
    }
    throws(() => blake256.create({ salt: new Uint8Array(100) }));
    throws(() => blake256.create({ salt: new Uint8Array(0) }));
  });
  should('Blake2 vectors', () => {
    const blake2_kat_vectors = json('./vectors/blake2-kat.json');
    for (const v of blake2_kat_vectors) {
      const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
      if (!hash) continue;
      const [input, exp] = [v.in, v.out].map(hexToBytes);
      const key = v.key ? hexToBytes(v.key) : undefined;
      eql(hash(input, { key }), exp);
    }
  });
  // NodeJS blake2 doesn't support personalization and salt, so we generated vectors using python: see vectors/blake2-gen.py

  const data = utf8ToBytes('data');

  should('Blake2 python', () => {
    const blake2_python = json('./vectors/blake2-python.json');
    for (const v of blake2_python) {
      const hash = { blake2s: blake2s, blake2b: blake2b }[v.hash];
      const opt = { dkLen: v.dkLen };
      if (v.person) opt.personalization = hexToBytes(v.person);
      if (v.salt) opt.salt = hexToBytes(v.salt);
      if (v.key) opt.key = hexToBytes(v.key);
      eql(bytesToHex(hash(data, opt)), v.digest);
    }
  });

  should('BLAKE2s: dkLen', () => {
    for (const dkLen of TYPE_TEST.int) throws(() => blake2s(data, { dkLen }));
    throws(() => blake2s(data, { dkLen: 33 }));
  });

  should('BLAKE2b: dkLen', () => {
    for (const dkLen of TYPE_TEST.int) throws(() => blake2b(data, { dkLen }));
    throws(() => blake2b(data, { dkLen: 65 }));
  });

  should('BLAKE2s: key', () => {
    for (const key of TYPE_TEST.bytes) {
      throws(() => blake2s(data, { key }));
    }
    throws(() => blake2s(data, { key: new Uint8Array(33) }));
    throws(() => blake2s(data, { key: new Uint8Array(0) }));
  });

  should('BLAKE2b: key', () => {
    for (const key of TYPE_TEST.bytes) {
      throws(() => blake2b(data, { key }));
    }
    throws(() => blake2b(data, { key: new Uint8Array(65) }));
    throws(() => blake2b(data, { key: new Uint8Array(0) }));
  });

  should('BLAKE2s: personalization/salt', () => {
    for (const t of TYPE_TEST.bytes) {
      throws(() => blake2s(data, { personalization: t }));
      throws(() => blake2s(data, { salt: t }));
    }
    for (let i = 0; i < 64; i++) {
      if (i == 8) continue;
      throws(() => blake2s(data, { personalization: new Uint8Array(i) }));
      throws(() => blake2s(data, { salt: new Uint8Array(i) }));
    }
  });

  should('BLAKE2b: personalization/salt', () => {
    for (const t of TYPE_TEST.bytes) {
      throws(() => blake2b(data, { personalization: t }));
      throws(() => blake2b(data, { salt: t }));
    }
    for (let i = 0; i < 64; i++) {
      if (i == 16) continue;
      throws(() => blake2b(data, { personalization: new Uint8Array(i) }));
      throws(() => blake2b(data, { salt: new Uint8Array(i) }));
    }
  });

  describe('input immutability', () => {
    should('BLAKE2b', () => {
      const msg = new Uint8Array([1, 2, 3, 4]);
      const key = new Uint8Array([1, 2, 3, 4]);
      const pers = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
      const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
      blake2b(msg, { key, salt, personalization: pers });
      eql(msg, new Uint8Array([1, 2, 3, 4]));
      eql(key, new Uint8Array([1, 2, 3, 4]));
      eql(pers, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
      eql(salt, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
    });

    should('BLAKE2s', () => {
      const msg = new Uint8Array([1, 2, 3, 4]);
      const key = new Uint8Array([1, 2, 3, 4]);
      const pers = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      blake2s(msg, { key, salt, personalization: pers });
      eql(msg, new Uint8Array([1, 2, 3, 4]));
      eql(key, new Uint8Array([1, 2, 3, 4]));
      eql(pers, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      eql(salt, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    });

    should('BLAKE3', () => {
      const msg = new Uint8Array([1, 2, 3, 4]);
      const ctx = new Uint8Array([1, 2, 3, 4]);
      const key = new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7,
        8,
      ]);
      blake3(msg, { key });
      blake3(msg, { context: ctx });
      eql(msg, new Uint8Array([1, 2, 3, 4]));
      eql(ctx, new Uint8Array([1, 2, 3, 4]));
      eql(
        key,
        new Uint8Array([
          1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
          7, 8,
        ])
      );
    });
  });

  describe('blake3', () => {
    should('dkLen', () => {
      for (const dkLen of TYPE_TEST.int) throws(() => blake3(data, { dkLen }));
    });

    should('not allow using both key + context', () => {
      // not allow specifying both key / context
      throws(() => {
        blake3(data, { context: new Uint8Array(32), key: new Uint8Array(32) });
      });
    });

    should('vectors', () => {
      const blake3_vectors = json('./vectors/blake3.json');
      for (let i = 0; i < blake3_vectors.cases.length; i++) {
        const v = blake3_vectors.cases[i];
        const res_hash = blake3(pattern(0xfa, v.input_len), { dkLen: v.hash.length / 2 });
        eql(bytesToHex(res_hash), v.hash, `Blake3 ${i} (hash)`);
        const res_keyed = blake3(pattern(0xfa, v.input_len), {
          key: utf8ToBytes(blake3_vectors.key),
          dkLen: v.hash.length / 2,
        });
        eql(bytesToHex(res_keyed), v.keyed_hash, `Blake3 ${i} (keyed)`);
        const res_derive = blake3(pattern(0xfa, v.input_len), {
          context: utf8ToBytes(blake3_vectors.context_string),
          dkLen: v.hash.length / 2,
        });
        eql(bytesToHex(res_derive), v.derive_key, `Blake3 ${i} (derive)`);
      }
    });

    should('XOF', () => {
      // XOF ok on xof instances
      blake3.create().xof(10);
      throws(() => {
        const h = blake3.create();
        h.xof(10);
        h.digest();
      }, 'digest after XOF');
      throws(() => {
        const h = blake3.create();
        h.digest();
        h.xof(10);
      }, 'XOF after digest');
      const bigOut = blake3(new Uint8Array(), { dkLen: 130816 });
      const hashxof = blake3.create();
      const out = [];
      for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
      eql(concatBytes(...out), bigOut, 'xof check against fixed size');
    });
  });
});

should.runWhen(import.meta.url);
