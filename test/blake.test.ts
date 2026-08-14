import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { PLATFORMS } from './platform.ts';
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

const BT = { describe, it };
export function test(variant: string, platform: any, { describe, it } = BT) {
  const { blake224, blake256, blake384, blake512, blake2b, blake2s, blake3 } = platform;
  describe(`blake (${variant})`, () => {
    it('Blake1 vectors', () => {
      for (const v of blake1_vectors) {
        const msg = typeof v.input === 'string' ? hexToBytes(v.input, 'hex') : v.input;
        if (v.blake224) eql(bytesToHex(blake224(msg)), v.blake224);
        if (v.blake256) eql(bytesToHex(blake256(msg)), v.blake256);
        if (v.blake384) eql(bytesToHex(blake384(msg)), v.blake384);
        if (v.blake512) eql(bytesToHex(blake512(msg)), v.blake512);
      }
    });
    // https://github.com/dchest/blake256/blob/master/blake256_test.go
    it('blake1-256 salt', () => {
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
    it('Blake1 salted family and padding-boundary vectors', () => {
      // Generated independently with @awasm/noble's pure-JS target. These cover every BLAKE1
      // variant and both sides of the one-block padding threshold (55 / 111 bytes).
      const vectors = [
        [blake224, 16, 0, '3d57ffe9a741df39288918367b3939c48f2e3524b88931fea3ee8391'],
        [blake224, 16, 55, '303b273ef1f866952a7786a6249df2b231dd004efe3757767af95b1d'],
        [blake224, 16, 56, '93881558011d27bb9ce8db677fe36e567271ea391cc27cda19642a25'],
        [blake256, 16, 0, '5a763c4847d1a3ed39b15c21bb09d3d54c48cb71d4c4dc22f6f562215a45f05f'],
        [blake256, 16, 55, '7d42f0a7714c1aa4d62b4661ee556a6b1781d240c1950e131222cca3df05935b'],
        [blake256, 16, 56, 'db77158b0a9fc360f95d81f5e17265b3dd4942422e218ea75daef23a1c5974d0'],
        [
          blake384,
          32,
          0,
          'b010259f92c5deeb6f28f25d82309b8ae37ca443b7c74ec0a7284c70aaf159df33800fa3da5cf206c9af5a18ba0f02f8',
        ],
        [
          blake384,
          32,
          111,
          'fb390bb8952641eaf1c3ef7522e9e4d9fadf6fe0abedaeadc4e95060f3368910b3c7ed2b440822fe0c882350d609093e',
        ],
        [
          blake384,
          32,
          112,
          'aa765e9f3476a7675f705fe59922209f881fb813f01b1483b8ed40711a4e514ea194900b1d965bc18f553d1d938da832',
        ],
        [
          blake512,
          32,
          0,
          '67c891f74248b6c194930b473afdae9b7eae8e74c7d26918674568fbace88f2053047aa03abde87eb01ac5a88ff729a6bbfb013a790a450db58c22b24cd7fe5b',
        ],
        [
          blake512,
          32,
          111,
          '862dba34ccc407d0ff8e66c53afc521ce3dd8109937ab4d0b6583077d852d89f81b4ae8c5f6da38c6f78fd6ff7305603a71b5d8476e1a312254d06e7d9ee54d9',
        ],
        [
          blake512,
          32,
          112,
          'eea9b09cf54c5fc7f5e9dad79ac4d7a6def1fc8e8728493c5dad9244cf995752dce009e0b0b545fc64623fb6f001f78898ee326e8f0fdac49c0f9f5a21cd7255',
        ],
      ] as const;
      for (const [hash, saltLen, len, expected] of vectors) {
        const msg = Uint8Array.from({ length: len }, (_, i) => (len + 29 * i + i * i) & 255);
        const salt = Uint8Array.from({ length: saltLen }, (_, i) => i + 1);
        eql(bytesToHex(hash(msg, { salt })), expected);
      }
    });
    it('Blake2 vectors', () => {
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

    it('Blake2 python', () => {
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
    it('BLAKE2 digestInto accepts odd lengths', () => {
      const outB = new Uint8Array(17);
      blake2b.create({ dkLen: 17 }).update(data).digestInto(outB);
      eql(bytesToHex(outB), 'c1f8306b76569775355538d7eda848b540');

      const outS = new Uint8Array(15);
      blake2s.create({ dkLen: 15 }).update(data).digestInto(outS);
      eql(bytesToHex(outS), 'ff7ad4af516d3a39b8641c1cc14324');
    });

    it('BLAKE2s: dkLen', () => {
      for (const dkLen of TYPE_TEST.int) throws(() => blake2s(data, { dkLen }));
      throws(() => blake2s(data, { dkLen: 0 }));
      throws(() => blake2s(data, { dkLen: 33 }));
    });

    it('BLAKE2b: dkLen', () => {
      for (const dkLen of TYPE_TEST.int) throws(() => blake2b(data, { dkLen }));
      throws(() => blake2b(data, { dkLen: 0 }));
      throws(() => blake2b(data, { dkLen: 65 }));
    });

    it('BLAKE2s: key', () => {
      for (const key of TYPE_TEST.bytes) {
        throws(() => blake2s(data, { key }));
      }
      throws(() => blake2s(data, { key: new Uint8Array(33) }));
      throws(() => blake2s(data, { key: new Uint8Array(0) }));
    });

    it('BLAKE2b: key', () => {
      for (const key of TYPE_TEST.bytes) {
        throws(() => blake2b(data, { key }));
      }
      throws(() => blake2b(data, { key: new Uint8Array(65) }));
      throws(() => blake2b(data, { key: new Uint8Array(0) }));
    });

    it('BLAKE2s: personalization/salt', () => {
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

    it('BLAKE2b: personalization/salt', () => {
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

    it('BLAKE2: unaligned salt/personalization/input views', () => {
      // salt/personalization as subarrays with byteOffset % 4 != 0 used to
      // throw a cryptic RangeError from the Uint32Array constructor.
      const mk = (len, off) => {
        const buf = new Uint8Array(len + off);
        for (let i = 0; i < len; i++) buf[off + i] = i + 1;
        return buf.subarray(off);
      };
      for (const [fn, sLen] of [
        [blake2b, 16],
        [blake2s, 8],
      ]) {
        const aligned = fn(data, { salt: mk(sLen, 0), personalization: mk(sLen, 0) });
        for (let off = 1; off < 4; off++) {
          eql(
            fn(data, { salt: mk(sLen, off), personalization: mk(sLen, off) }),
            aligned,
            `salt/pers byteOffset=${off}`
          );
        }
        // unaligned message views must match aligned ones (zero-copy path skips them)
        const msg = mk(3 * 128 + 13, 0);
        const exp = fn(msg);
        for (let off = 1; off < 4; off++) eql(fn(mk(3 * 128 + 13, off)), exp, `msg off=${off}`);
      }
    });

    describe('input immutability', () => {
      it('BLAKE2b', () => {
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

      it('BLAKE2s', () => {
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

      it('BLAKE3', () => {
        const msg = new Uint8Array([1, 2, 3, 4]);
        const ctx = new Uint8Array([1, 2, 3, 4]);
        const key = new Uint8Array([
          1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
          7, 8,
        ]);
        blake3(msg, { key });
        blake3(msg, { context: ctx });
        eql(msg, new Uint8Array([1, 2, 3, 4]));
        eql(ctx, new Uint8Array([1, 2, 3, 4]));
        eql(
          key,
          new Uint8Array([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
          ])
        );
      });
      it('BLAKE3 keyed state', () => {
        const key = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
        const msg = Uint8Array.from([1, 2, 3, 4, 5, 6]);
        const state = blake3.create({ key, dkLen: 32 }).update(msg.subarray(0, 3));
        key.fill(0);
        const out = state.update(msg.subarray(3)).digest();
        const exp = blake3(msg, {
          key: Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1)),
          dkLen: 32,
        });
        eql(out, exp);
      });
    });

    describe('blake3', () => {
      it('dkLen', () => {
        for (const dkLen of TYPE_TEST.int) throws(() => blake3(data, { dkLen }));
        eql(blake3(data, { dkLen: 0 }), new Uint8Array(0));
      });

      it('not allow using both key + context', () => {
        // not allow specifying both key / context
        throws(() => {
          blake3(data, { context: new Uint8Array(32), key: new Uint8Array(32) });
        });
      });

      it('vectors', () => {
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

      it('one-shot fast path', () => {
        const lengths = [
          0, 1, 3, 4, 31, 32, 63, 64, 65, 127, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073, 4096,
          4097, 8192, 8193, 16384, 31744, 102400,
        ];
        for (const len of lengths) {
          for (let offset = 0; offset < 4; offset++) {
            const backing = pattern(0xfa, len + offset + 5);
            const msg = backing.subarray(offset, offset + len);
            const before = msg.slice();
            const expected = blake3.create().update(msg).digest();
            eql(blake3(msg), expected, `len=${len}, offset=${offset}`);
            eql(msg, before, `input mutation: len=${len}, offset=${offset}`);
          }
        }

        const first = blake3(Uint8Array.of(1));
        const saved = first.slice();
        const second = blake3(Uint8Array.of(2));
        eql(first, saved, 'returned output aliases reusable scratch');
        eql(second, blake3.create().update(Uint8Array.of(2)).digest());
        eql(blake3.outputLen, 32);
        eql(blake3.blockLen, 64);
        eql(blake3.canXOF, true);
        eql(Object.isFrozen(blake3), true);

        // Typed-array view metadata can run user code before a nonstandard view is admitted to the
        // direct traversal. Nested hashing must leave the outer result correct.
        let nested: Uint8Array | undefined;
        class ReentrantBytes extends Uint8Array {
          get byteOffset() {
            nested = blake3(Uint8Array.of(9));
            return super.byteOffset;
          }
        }
        const reentrant = new ReentrantBytes(32);
        reentrant.set(pattern(0xfa, 32));
        eql(blake3(reentrant), blake3.create().update(reentrant).digest());
        eql(nested, blake3.create().update(Uint8Array.of(9)).digest());

        // Overridden view metadata must not let a subclass make the direct traversal read outside
        // the typed array's intrinsic range. Nonstandard views retain the stateful API behavior.
        for (const forgedLength of [-1, 64]) {
          class ForgedLength extends Uint8Array {
            get length() {
              return forgedLength;
            }
          }
          const forged = new ForgedLength([1, 2, 3]);
          eql(blake3(forged), blake3.create().update(forged).digest());
        }
      });

      it('XOF', () => {
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
        const bigOut = blake3(Uint8Array.of(), { dkLen: 130816 });
        const hashxof = blake3.create();
        const out = [];
        for (let i = 0; i < 512; i++) out.push(hashxof.xof(i));
        eql(concatBytes(...out), bigOut, 'xof check against fixed size');
      });
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href)
  for (const k in PLATFORMS) test(k, PLATFORMS[k]);

it.runWhen(import.meta.url);
