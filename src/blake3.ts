import * as u64 from './_u64';
import * as blake2 from './_blake2';
import * as blake2s from './blake2s';
import { Input, u8, u32, toBytes, wrapConstructorWithOpts, assertNumber } from './utils';

// Flag bitset
enum Flags {
  CHUNK_START = 1 << 0,
  CHUNK_END = 1 << 1,
  PARENT = 1 << 2,
  ROOT = 1 << 3,
  KEYED_HASH = 1 << 4,
  DERIVE_KEY_CONTEXT = 1 << 5,
  DERIVE_KEY_MATERIAL = 1 << 6,
}

const SIGMA: Uint8Array = (() => {
  const Id = Array.from({ length: 16 }, (_, i) => i);
  const permute = (arr: number[]) =>
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].map((i) => arr[i]);
  const res: number[] = [];
  for (let i = 0, v = Id; i < 7; i++, v = permute(v)) res.push(...v);
  return Uint8Array.from(res);
})();

// - key: is 256-bit key
// - context: string should be hardcoded, globally unique, and application - specific.
//   A good default format for the context string is "[application] [commit timestamp] [purpose]"
// - Only one of 'key' (keyed mode) or 'context' (derive key mode) can be used at same time
export type Blake3Opts = { dkLen?: number; key?: Input; context?: Input };

// Why is this so slow? It should be 6x faster than blake2b.
// - There is only 30% reduction in number of rounds from blake2s
// - This function uses tree mode to achive parallelisation via SIMD and threading,
//   however in JS we don't have threads and SIMD, so we get only overhead from tree structure
// - It is possible to speed it up via Web Workers, hovewer it will make code singnificantly more
//   complicated, which we are trying to avoid, since this library is intended to be used
//   for cryptographic purposes. Also, parallelization happens only on chunk level (1024 bytes),
//   which won't really benefit small inputs.
class BLAKE3 extends blake2.BLAKE2<BLAKE3> {
  private IV: Uint32Array;
  private flags = 0 | 0;
  private state: Uint32Array;
  private chunkPos = 0; // Position of current block in chunk
  private chunksDone = 0; // How many chunks we already have
  private stack: Uint32Array[] = [];

  constructor(opts: Blake3Opts = {}, flags = 0) {
    super(64, opts.dkLen === undefined ? 32 : opts.dkLen, {}, Number.MAX_SAFE_INTEGER, 0, 0);
    this.outputLen = opts.dkLen === undefined ? 32 : opts.dkLen;
    assertNumber(this.outputLen);
    if (opts.key !== undefined && opts.context !== undefined)
      throw new Error('Blake3: only key or context can be specified at same time');
    else if (opts.key !== undefined) {
      const key = toBytes(opts.key);
      if (key.length !== 32) throw new Error('Blake3: key should be 32 byte');
      this.IV = u32(key);
      this.flags = flags | Flags.KEYED_HASH;
    } else if (opts.context !== undefined) {
      const context_key = new BLAKE3({ dkLen: 32 }, Flags.DERIVE_KEY_CONTEXT)
        .update(opts.context)
        .digest();
      this.IV = u32(context_key);
      this.flags = flags | Flags.DERIVE_KEY_MATERIAL;
    } else {
      this.IV = blake2s.IV.slice();
      this.flags = flags;
    }
    this.state = this.IV.slice();
  }
  // Unused
  protected get() {
    return [];
  }
  protected set() {}
  private b2Compress(counter: number, flags: number, buf: Uint32Array, bufPos: number = 0) {
    const { state, pos } = this;
    const { h, l } = u64.fromBig(BigInt(counter), true);
    // prettier-ignore
    const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } =
      blake2s.compress(
        SIGMA, bufPos, buf, 7,
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        blake2s.IV[0], blake2s.IV[1], blake2s.IV[2], blake2s.IV[3], h, l, pos, flags
      );
    state[0] = v0 ^ v8;
    state[1] = v1 ^ v9;
    state[2] = v2 ^ v10;
    state[3] = v3 ^ v11;
    state[4] = v4 ^ v12;
    state[5] = v5 ^ v13;
    state[6] = v6 ^ v14;
    state[7] = v7 ^ v15;
  }
  private finishChunk(buf: Uint32Array, bufPos: number = 0, isLast = false) {
    const flags = this.flags | (!this.chunkPos ? Flags.CHUNK_START : 0) | Flags.CHUNK_END;
    this.b2Compress(this.chunksDone, flags, buf, bufPos);
    let chunk = this.state;
    this.state = this.IV.slice();
    // If not the last one, compress only when there are trailing zeros in chunk counter
    for (let last, chunks = this.chunksDone + 1; isLast || !(chunks & 1); chunks >>= 1) {
      if (!(last = this.stack.pop())) break;
      this.buffer32.set(last, 0);
      this.buffer32.set(chunk, 8);
      this.pos = this.blockLen;
      this.b2Compress(0, this.flags | Flags.PARENT, this.buffer32, 0);
      chunk = this.state;
      this.state = this.IV.slice();
    }
    this.chunksDone++;
    this.pos = 0;
    this.chunkPos = 0;
    this.stack.push(chunk);
  }
  protected compress(buf: Uint32Array, bufPos: number = 0) {
    this.pos = this.blockLen;
    // If current block is last in chunk (16 blocks), then compress whole chunk instead of block
    if (this.chunkPos === 15) return this.finishChunk(buf, bufPos);
    const flags = this.flags | (!this.chunkPos ? Flags.CHUNK_START : 0);
    this.b2Compress(this.chunksDone, flags, buf, bufPos);
    this.chunkPos += 1;
    this.pos = 0;
  }
  _cloneInto(to?: BLAKE3): BLAKE3 {
    to = blake2.BLAKE2.prototype._cloneInto.call(this, to) as BLAKE3;
    const { IV, flags, state, chunkPos, stack, chunksDone } = this;
    to.state.set(state.slice());
    to.stack = stack.map((i) => Uint32Array.from(i));
    to.IV.set(IV);
    to.flags = flags;
    to.chunkPos = chunkPos;
    to.chunksDone = chunksDone;
    return to;
  }
  _clean() {
    this.state.fill(0);
    this.buffer.fill(0);
    this.IV.fill(0);
    for (let i of this.stack) i.fill(0);
  }
  // Same as b2Compress, but doesn't modify state and returns 16 u32 array (instead of 8)
  private compressOut(counter: number, flags: number, out: Uint32Array) {
    const { state, pos, buffer32 } = this;
    const { h, l } = u64.fromBig(BigInt(counter), true);
    // prettier-ignore
    const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } =
      blake2s.compress(
        SIGMA, 0, buffer32, 7,
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        blake2s.IV[0], blake2s.IV[1], blake2s.IV[2], blake2s.IV[3], h, l, pos, flags
      );
    out[0] = v0 ^ v8;
    out[1] = v1 ^ v9;
    out[2] = v2 ^ v10;
    out[3] = v3 ^ v11;
    out[4] = v4 ^ v12;
    out[5] = v5 ^ v13;
    out[6] = v6 ^ v14;
    out[7] = v7 ^ v15;
    out[8] = state[0] ^ v8;
    out[9] = state[1] ^ v9;
    out[10] = state[2] ^ v10;
    out[11] = state[3] ^ v11;
    out[12] = state[4] ^ v12;
    out[13] = state[5] ^ v13;
    out[14] = state[6] ^ v14;
    out[15] = state[7] ^ v15;
  }
  _writeDigest(buf: Uint8Array) {
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    // Padding
    this.buffer.fill(0, this.pos);
    // Process last chunk
    let flags = this.flags | Flags.ROOT;
    if (this.stack.length) {
      flags |= Flags.PARENT;
      this.finishChunk(this.buffer32, 0, true);
      this.chunksDone = 0;
      this.pos = this.blockLen;
    } else {
      flags |= (!this.chunkPos ? Flags.CHUNK_START : 0) | Flags.CHUNK_END;
    }
    // XOF. We cannot re-use buffer, because current buffer value is used for compress
    const tmp = this.buffer32.slice();
    const tmp8 = u8(tmp);
    for (let i = 0, pos = 0; pos < this.outputLen; i++, pos += this.blockLen) {
      this.compressOut(i, flags, tmp);
      buf.set(tmp8.subarray(0, buf.length - pos), pos);
    }
    this._clean();
  }
  digest() {
    let res = new Uint8Array(this.outputLen);
    this._writeDigest(res);
    return res;
  }
}

export const blake3 = wrapConstructorWithOpts<BLAKE3, Blake3Opts>((opts) => new BLAKE3(opts));
