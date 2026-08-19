// noble-hashes only tests (non-shared). This file exists for implementation-specific
// details that should not leak into shared test helpers reused by other projects
// such as awasm-noble.
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { HashMD } from '../src/_md.ts';
import { blake256, blake512 } from '../src/blake1.ts';
import { blake2b } from '../src/blake2.ts';
import { _BLAKE3, blake3 } from '../src/blake3.ts';
import { expand, hkdf } from '../src/hkdf.ts';
import { pbkdf2, pbkdf2Async } from '../src/pbkdf2.ts';
import { _SHA256, sha256 } from '../src/sha2.ts';
import { copyBytes, createHasher, hexToBytes, utf8ToBytes } from '../src/utils.ts';

describe('noble-hashes only', () => {
  it('HashMD requires family-local clone implementations', () => {
    // A shared clone feedback site becomes megamorphic across state layouts and materializes the
    // get() tuple, leaving chaining state in an allocation the library cannot explicitly wipe.
    eql(Object.hasOwn(HashMD.prototype, '_cloneInto'), false);
  });
  it('HKDF supports cloneable tree hashes', () => {
    const input = Uint8Array.of(1, 2, 3);
    eql(
      hkdf(blake3, input, input, input, 32),
      hexToBytes('5dc160b282b3d9ba657831b7af270b6f15eebb2b8042bfd2258670799bfd9de7')
    );
  });
  it('standalone HKDF expand repeatedly supports tree hashes', () => {
    const prk = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const info = Uint8Array.of(1, 2, 3);
    const expected = hexToBytes(
      'ccbc393a25bc4f7f4f0835d4d62858667fed95058e4c0e4ddeab6cae5b4520ac' +
        '603f8046cd5b376edefc189577a8b859a3cef2294fdbd66a98388b7b66c0949f'
    );
    // Every call creates and destroys its own alternating worker, including BLAKE3's tree stack
    // and keyed state, so separate complete outputs must remain identical.
    eql(expand(blake3, prk, info, 64), expected);
    eql(expand(blake3, prk, info, 64), expected);
  });
  it('PBKDF2 supports cloneable tree hashes', async () => {
    const input = Uint8Array.of(1, 2, 3);
    eql(
      pbkdf2(blake3, input, input, { c: 2, dkLen: 32 }),
      hexToBytes('4992a32e0807d4cfbb908ae8ad70afcfe268a993fb954419edea595d24f967b7')
    );
    const expected = hexToBytes(
      '174ac2c563bd99606730bf2a88410f38ab83b72d38f7bb2b0cb0ebfcc37a9b79' +
        '140887ec4caec3618da6026a0c5f5c8ddb26878342f751e35fec1759e9a9e85d'
    );
    // Repeat the multi-block c=1 path to catch state accidentally retained between calls.
    eql(pbkdf2(blake3, input, input, { c: 1, dkLen: 64 }), expected);
    eql(pbkdf2(blake3, input, input, { c: 1, dkLen: 64 }), expected);
    const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const wide = createHasher(() => blake3.create({ key, dkLen: 96 }));
    const wideExpected = hexToBytes(
      'bc66243fdfcf1ab7dca2943e66ef545baf38a378668e81c0e915973f1ae60de3' +
        '3d9da5adb2cc72a493d6bd126591c366b00eff42739e9fafffd51c3f6e57bb0c' +
        '596aa8919da0abd5bcc95ad7267e6d7d1b6af38f5e715530768c3d60da0d0566' +
        '91ec46c39b1476fd3fad92a38996fc501059401d39c342ca0ebf1d73194ea57dc' +
        '8d90e83cceaae9e722bba3bbe1bd0a1064b4052d485b7c7b856fd91dd28af814' +
        '505cbe52e3a2a5c2bdeca16672aad82a1dc0b3c10ee575e4ddf4fbacbce4986'
    );
    // Pad reuse must size digest scratch for configured XOF outputs wider than one hash block.
    eql(
      [
        pbkdf2(wide, input, input, { c: 2, dkLen: 192 }),
        await pbkdf2Async(wide, input, input, { c: 2, dkLen: 192, asyncTick: 0 }),
      ],
      [wideExpected, wideExpected]
    );
  });
  it('PBKDF2-BLAKE3 does not abandon live keyed CV stacks', () => {
    const abandoned: Uint32Array[] = [];
    class TrackedBLAKE3 extends _BLAKE3 {
      _cloneInto(to?: _BLAKE3): _BLAKE3 {
        if (to) abandoned.push(...((to as any).stack as Uint32Array[]));
        return super._cloneInto(to);
      }
    }
    const password = Uint8Array.from({ length: 33 }, (_, i) => (1 + 29 * i + i * i) & 255);
    const salt = Uint8Array.from({ length: 9001 }, (_, i) => (2 + 29 * i + i * i) & 255);
    const opts = { c: 2, dkLen: 65 };
    const tracked = createHasher(() => new TrackedBLAKE3());
    eql(pbkdf2(tracked, password, salt, opts), pbkdf2(blake3, password, salt, opts));
    // Replacing a reusable tree destination must not orphan password-derived CVs that final
    // destroy() can no longer reach. Retained references make every abandoned entry observable.
    eql(
      abandoned.map((item) => Uint32Array.from(item)),
      abandoned.map((item) => new Uint32Array(item.length))
    );
  });
  it('PBKDF2 async c=1 yields between output blocks', async () => {
    let digests = 0;
    class CountingSHA256 extends _SHA256 {
      digestInto(out: Uint8Array): void {
        digests++;
        super.digestInto(out);
      }
    }
    const hash = createHasher(() => new CountingSHA256());
    let afterFirstYield = -1;
    queueMicrotask(() => {
      afterFirstYield = digests;
    });
    const output = await pbkdf2Async(hash, 'password', 'salt', {
      c: 1,
      dkLen: 128,
      asyncTick: 0,
    });
    // Each block needs two raw hash digests. The first queued microtask must run after block one,
    // not after all four blocks, or asyncTick cannot keep a long c=1 expansion responsive.
    eql(
      { afterFirstYield, digests, output },
      {
        afterFirstYield: 2,
        digests: 8,
        output: hexToBytes(
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17' +
            'b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc1' +
            '8c22cd7fe60fa40e91c65849e1f60c0d8b62a7b2dbd0d3dfd75fb8498a5c2' +
            '131ab02b66de5e7dad0c54f172ee4b25fc800dea31e40a5d0e9547b365d911' +
            '8b5fd4b'
        ),
      }
    );
  });
  it('concurrent configured/tree KDF calls do not interfere', async () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
    const configured = createHasher(() => blake3.create({ key }));
    const input = Uint8Array.from({ length: 65 }, (_, i) => (17 * i + 3) & 255);
    const info = Uint8Array.of(4, 5, 6);
    const expected = [
      [
        '28fdc4f4c9b2595f9ec604fa57fdda8212753fa885954064490c6b9a880bf7a7' +
          'c70a21c1d915ac305c397e0a8f45f52f265b4edd94a6c3d69e363216d18b023e',
        '09782c90827231b9f1f8a5d84dabdc2d3bca2275c0a88113ec9e91f8c396ea0d' +
          '1200fd6cbfc8c15ae3919223266c331bf1c323bbb56a51a79bf1394bf287b291',
        '935328addc0612161c15b65f07a5c15fc9fa6fb2277bf5d380e38f6e6c950a47' +
          'f5bb89c26ee354bfc80c01af8a2c73a299c27010e38a8e34c3c4439cd71f0dff',
      ],
      [
        '208ca168a73101f8404eaffabda7fcc3fb21b05ee9f4d51c15f1b16d1d2529c2' +
          'c733889097f3c4ea1171294a88cab218088785849565c00b0ff63f26af2aeddb',
        '3461bf0323fbb804219b3a448fdc5facb276e8fb4a055e7d6a308411963173e1' +
          '51e685ca151043fd09272cebfe7a9e0cf0ca4a8f8925a3370db48f5f78d1d7b0',
        '704049a338296c219f6e99a9a5a4022a9239b2f1fdc1930fd99d9ea00fb10587' +
          'b17025b9fc27317ad17c18b5132ea46cbb355dc2e3835958b746139932d00310',
      ],
    ].map((pair) => pair.map(hexToBytes));
    const actual = [];
    for (const hash of [sha256, configured]) {
      const length = 2 * hash.outputLen;
      const concurrent = await Promise.all([
        pbkdf2Async(hash, input, info, { c: 1, dkLen: length }),
        pbkdf2Async(hash, info, input, { c: 1, dkLen: length }),
      ]);
      actual.push([
        expand(hash, input, info, length),
        pbkdf2(hash, input, info, { c: 1, dkLen: length }),
        await pbkdf2Async(hash, input, info, { c: 1, dkLen: length }),
        ...concurrent,
        expand(hash, input, info, length),
      ]);
    }
    // Exercise sequential and concurrent clone destinations with flat and configured tree hashes;
    // every complete result must be independent of the surrounding call order.
    eql(
      actual,
      expected.map(([expandOut, pbkdfOut, reverseOut]) => [
        expandOut,
        pbkdfOut,
        pbkdfOut,
        pbkdfOut,
        reverseOut,
        expandOut,
      ])
    );
  });
  it('BLAKE1 unsalted clone replacements clear dead buffers and reuse immutable state', () => {
    const suffix = Uint8Array.of(1, 2, 3);
    const hashes = [blake256, blake512];
    const expected = hashes.map((hash) => {
      const block = new Uint8Array(hash.blockLen).fill(hash.outputLen);
      return {
        constantsShared: true,
        saltShared: true,
        partialBuffer: new Uint8Array(hash.blockLen),
        alignedBuffer: new Uint8Array(hash.blockLen),
        digest: hash.create().update(block).update(suffix).digest(),
      };
    });
    const actual = hashes.map((hash) => {
      const block = new Uint8Array(hash.blockLen).fill(hash.outputLen);
      const stale = new Uint8Array(hash.blockLen).fill(0xa5);
      const empty: any = hash.create();
      const partialTarget: any = hash.create().update(stale.subarray(0, -1));
      empty._cloneInto(partialTarget);
      partialTarget.destroy();
      const partialBuffer = copyBytes(partialTarget.buffer);
      empty.destroy();

      const source: any = hash.create().update(block);
      // Split a full block so it passes through the internal buffer before eager compression,
      // leaving known stale bytes in an otherwise block-aligned destination.
      const target: any = hash.create().update(stale.subarray(0, -1)).update(stale.subarray(-1));
      source._cloneInto(target);
      const constantsShared = target.constants === source.constants;
      const saltShared = target.salt === source.salt;
      const alignedBuffer = copyBytes(target.buffer);
      source.destroy();
      const digest = target.update(suffix).digest();
      return { constantsShared, saltShared, partialBuffer, alignedBuffer, digest };
    });
    // Replacing either a partial destination or an eagerly compressed aligned destination must
    // discard its old message bytes. Unsalted constants and the sentinel remain immutable and
    // safe to share across independently destroyable clones.
    eql(actual, expected);
  });
  it('BLAKE1 salted clone destinations remain independent and reusable', () => {
    const prefix = Uint8Array.of(4, 5, 6);
    const suffix = Uint8Array.of(7, 8, 9);
    const hashes = [
      { hash: blake256, saltLen: 16 },
      { hash: blake512, saltLen: 32 },
    ];
    const expected = hashes.map(({ hash, saltLen }) => {
      const salt1 = Uint8Array.from({ length: saltLen }, (_, i) => i + 1);
      const salt2 = Uint8Array.from({ length: saltLen }, (_, i) => 255 - i);
      return {
        arraysReused: [true, true],
        first: hash.create({ salt: salt1 }).update(prefix).update(suffix).digest(),
        second: hash.create({ salt: salt2 }).update(prefix).update(suffix).digest(),
      };
    });
    const actual = hashes.map(({ hash, saltLen }) => {
      const salt1 = Uint8Array.from({ length: saltLen }, (_, i) => i + 1);
      const salt2 = Uint8Array.from({ length: saltLen }, (_, i) => 255 - i);
      const source1: any = hash.create({ salt: salt1 }).update(prefix);
      const target: any = hash.create({ salt: salt2 });
      const constants = target.constants;
      const salt = target.salt;
      source1._cloneInto(target);
      const firstReuse = target.constants === constants && target.salt === salt;
      source1.destroy();
      const first = target.update(suffix).digest();
      const source2: any = hash.create({ salt: salt2 }).update(prefix);
      source2._cloneInto(target);
      const secondReuse = target.constants === constants && target.salt === salt;
      source2.destroy();
      const second = target.update(suffix).digest();
      return { arraysReused: [firstReuse, secondReuse], first, second };
    });
    // Destroying either source must not wipe its clone, and cloning into the already-destroyed
    // destination must restore its private salt-derived arrays without allocating replacements.
    eql(actual, expected);
  });
  it('BLAKE3 clones share only immutable default IV', () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const context = utf8ToBytes('BLAKE3 clone context');
    const prefix = Uint8Array.of(1, 2, 3);
    const suffix = Uint8Array.of(4, 5, 6);
    const plain1: any = blake3.create();
    const plain2: any = blake3.create();
    const sharedIV = plain1.IV;
    const expectedIV = Uint32Array.from(sharedIV);
    const keyedTarget: any = blake3.create({ key });
    const oldKeyedIV = keyedTarget.IV;
    plain1.destroy();
    plain2._cloneInto(keyedTarget);

    const keyedSource: any = blake3.create({ key }).update(prefix);
    const defaultTarget: any = blake3.create();
    keyedSource._cloneInto(defaultTarget);
    const keyedPrivate = defaultTarget.IV !== sharedIV && defaultTarget.IV !== keyedSource.IV;
    keyedSource.destroy();

    const contextSource: any = blake3.create({ context }).update(prefix);
    const contextTarget: any = blake3.create({ key });
    const contextTargetIV = contextTarget.IV;
    contextSource._cloneInto(contextTarget);
    contextSource.destroy();

    // Default IV is immutable and survives destruction of any sharing instance. Configured IVs
    // remain private, reusable, and independently destroyable across both clone directions.
    eql(
      {
        defaultShared: plain2.IV === sharedIV,
        defaultAfterDestroy: Uint32Array.from(plain2.IV),
        defaultIntoKeyed: keyedTarget.IV === sharedIV,
        oldKeyedIV: Uint32Array.from(oldKeyedIV),
        keyedPrivate,
        keyedDigest: defaultTarget.update(suffix).digest(),
        contextReused: contextTarget.IV === contextTargetIV,
        contextDigest: contextTarget.update(suffix).digest(),
      },
      {
        defaultShared: true,
        defaultAfterDestroy: expectedIV,
        defaultIntoKeyed: true,
        oldKeyedIV: new Uint32Array(8),
        keyedPrivate: true,
        keyedDigest: blake3.create({ key }).update(prefix).update(suffix).digest(),
        contextReused: true,
        contextDigest: blake3.create({ context }).update(prefix).update(suffix).digest(),
      }
    );
  });
  it('BLAKE3 merges CVs with full-width chunk counters', () => {
    const TWO32 = 2 ** 32;
    const boundaries = [
      { chunks: TWO32, stackSize: 32, expectedSize: 1 },
      { chunks: 2 * TWO32, stackSize: 33, expectedSize: 1 },
      { chunks: 3 * TWO32, stackSize: 33, expectedSize: 2 },
    ];
    const actual = boundaries.map(({ chunks, stackSize }) => {
      const hash: any = new _BLAKE3();
      hash.chunksDone = chunks - 1;
      hash.chunkPos = 15;
      hash.stack = Array.from({ length: stackSize }, (_, i) =>
        Uint32Array.from({ length: 8 }, () => i + 1)
      );
      const oldest = Uint32Array.from(hash.stack[0]);
      // Complete the synthetic boundary chunk directly: hashing 3 * 2^32 chunks would require
      // 12 TiB of input, but the tree merge depends only on this counter and valid stack shape.
      hash.compress(new Uint32Array(16));
      const stack = hash.stack as Uint32Array[];
      const result = {
        chunks: hash.chunksDone,
        stackSize: stack.length,
        oldestPreserved:
          stack.length > 1 && stack[0].every((word, wordPos) => word === oldest[wordPos]),
      };
      hash.destroy();
      return result;
    });
    eql(
      actual,
      boundaries.map(({ chunks, expectedSize }) => ({
        chunks,
        stackSize: expectedSize,
        oldestPreserved: expectedSize > 1,
      }))
    );
  });
  it('BLAKE3 unfinished clones skip dead output scratch and wipe stale XOF output', () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
    const prefix = Uint8Array.of(1, 2, 3);
    const suffix = Uint8Array.of(4, 5, 6);
    const source: any = blake3.create().update(prefix);
    // Unfinished BLAKE3 overwrites this output scratch before reading it. Poisoning the dead
    // bytes makes an unnecessary clone copy observable without changing the hash state.
    source.bufferOut32.fill(0xa5a5a5a5);
    const unfinished: any = blake3.create({ key }).update(Uint8Array.of(7));
    const liveXof: any = blake3.create({ key }).update(Uint8Array.of(8));
    liveXof.xof(17);
    const destroyed: any = blake3.create({ key }).update(Uint8Array.of(9));
    destroyed.digest();
    const targets = [unfinished, liveXof, destroyed];
    const outputs = targets.map((target) => target.bufferOut32 as Uint32Array);
    for (const target of targets) source._cloneInto(target);
    const digest = blake3.create().update(prefix).update(suffix).digest();

    const finished = blake3.create({ dkLen: 128 }).update(prefix);
    const expected = blake3.create({ dkLen: 128 }).update(prefix);
    finished.xof(17);
    expected.xof(17);
    const finishedTarget = blake3.create({ dkLen: 128 });
    finished._cloneInto(finishedTarget);
    // A live keyed XOF destination contains key-derived output and must be wiped; unfinished and
    // destroyed destinations are already clean. Finished source output remains live clone state.
    eql(
      {
        outputs: outputs.map((output) => Uint32Array.from(output)),
        digests: targets.map((target) => target.update(suffix).digest()),
        finished: finishedTarget.xof(193),
      },
      {
        outputs: Array.from({ length: 3 }, () => new Uint32Array(16)),
        digests: Array.from({ length: 3 }, () => copyBytes(digest)),
        finished: expected.xof(193),
      }
    );
  });
  it('BLAKE2 digestInto rejects unaligned output views', () => {
    const out = new Uint8Array(33).subarray(1);
    const msg = utf8ToBytes('abc');
    throws(
      () => blake2b.create({ dkLen: 32 }).update(msg).digestInto(out),
      (err) => {
        eql(err instanceof RangeError, true);
        eql(err.message, '"output" expected 4-byte aligned byteOffset, got 1');
        return true;
      }
    );
  });
});

it.runWhen(import.meta.url);
