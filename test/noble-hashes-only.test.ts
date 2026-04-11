// noble-hashes only tests (non-shared). This file exists for implementation-specific
// details that should not leak into shared test helpers reused by other projects
// such as awasm-noble.
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { blake2b } from '../src/blake2.ts';
import { utf8ToBytes } from '../src/utils.ts';

describe('noble-hashes only', () => {
  should('BLAKE2 digestInto rejects unaligned output views', () => {
    const out = new Uint8Array(33).subarray(1);
    const msg = utf8ToBytes('abc');
    throws(
      () => blake2b.create({ dkLen: 32 }).update(msg).digestInto(out),
      (err) => {
        eql(err instanceof RangeError, true);
        eql(err.message, '"digestInto() output" expected 4-byte aligned byteOffset, got 1');
        return true;
      }
    );
  });
});
