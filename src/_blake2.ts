import { assertNumber, Hash, Input, PartialOpts, toBytes, u32 } from './utils';
// prettier-ignore
export const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  // For BLAKE2b, the two extra permutations for rounds 10 and 11 are SIGMA[10..11] = SIGMA[0..1].
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
].map(arr => new Uint8Array(arr));

export type BlakeOpts = PartialOpts & {
  dkLen?: number;
  key?: Uint8Array;
  salt?: Uint8Array;
  personalization?: Uint8Array;
};

const isBytes = (arr: any) => arr instanceof Uint8Array;

export abstract class Blake2 extends Hash {
  abstract _compress(msg: Uint32Array, offset: number, isLast: boolean): void;
  abstract _get(): number[];
  abstract clean(): void;
  buffer: Uint8Array;
  buffer32: Uint32Array;
  length: number = 0;
  done = false;
  cleaned = false;

  constructor(
    readonly blockLen: number,
    readonly outputLen: number,
    readonly opts: BlakeOpts,
    keyLen: number,
    saltLen: number,
    persLen: number
  ) {
    super();
    assertNumber(outputLen);
    if (outputLen < 1 || outputLen > keyLen)
      throw new Error('Blake2: outputLen bigger than keyLen');
    if (opts.key) {
      if (!isBytes(opts.key) || opts.key.length < 1 || opts.key.length > keyLen)
        throw new Error(`Key should be up 1..${keyLen} byte long or undefined`);
    }
    if (opts.salt) {
      if (!isBytes(opts.salt) || opts.salt.length !== saltLen)
        throw new Error(`Salt should be ${saltLen} byte long or undefined`);
    }
    if (opts.personalization) {
      if (!isBytes(opts.personalization) || opts.personalization.length !== persLen)
        throw new Error(`Personalization should be ${persLen} byte long or undefined`);
    }
    this.buffer32 = u32((this.buffer = new Uint8Array(blockLen)));
  }
  update(_data: Input) {
    const { done, blockLen, buffer32 } = this;
    if (done) throw new Error('Hash already finalized');
    const data = toBytes(_data);
    if (!data.length) return this; // Empty data buffer, there is nothing to do
    // Main difference with other hashes: there is flag for last block,
    // so we cannot process current block before we know that there
    // is the next one. This significantly complicates logic and reduces ability
    // to do zero-copy processing
    let pos = 0; // Position in data buffer
    let len = data.length;
    let offset = this.length % blockLen; // Offset position in internal buffer
    if (this.length) {
      const left = blockLen - offset;
      // There is full block in buffer written by previous updates
      if (!offset) this._compress(buffer32, 0, false);
      else if (offset && left < len) {
        // We can fill current block and there is data to start next block
        const tmp = data.subarray(0, left);
        this.buffer.set(tmp, offset);
        this.length += pos = tmp.length;
        this._compress(buffer32, 0, false);
        offset = 0;
      }
    }
    // Special case: if current position is aligned to 4 bytes and there is
    // more than 1 block in data we can process without copy
    const dataOffset = data.byteOffset + pos; // Current offset in ArrayBuffer of data
    if (!(dataOffset % 4) && blockLen < len - pos) {
      const data32 = new Uint32Array(data.buffer, dataOffset, Math.floor((data.length - pos) / 4));
      const blockLen32 = blockLen / 4;
      for (let pos32 = 0; blockLen < len - pos; pos32 += blockLen32, pos += blockLen, offset = 0) {
        this.length += blockLen;
        this._compress(data32, pos32, false);
      }
    }
    // Process blocks except last one
    for (; blockLen < len - pos; pos += blockLen, offset = 0) {
      this.buffer.set(data.subarray(pos, pos + blockLen));
      this.length += blockLen;
      this._compress(buffer32, 0, false);
    }
    // If there is still data then copy it to internal buffer.
    // Data at current position is <= blockLen
    // Internal buffer is empty here, because all leftovers was processed in first step
    this.buffer.set(data.subarray(pos), offset);
    this.length += len - pos;
    return this;
  }
  _writeDigest(out: Uint8Array) {
    if (this.cleaned) throw new Error('Hash instance cleaned');
    if (!this.done) {
      this.done = true;
      // Padding
      const i = this.length % this.blockLen; // current buffer offset
      if (i) this.buffer.subarray(i).fill(0);
      this._compress(this.buffer32, 0, true);
    }
    const out32 = u32(out);
    this._get().forEach((v, i) => (out32[i] = v));
  }
  digest() {
    const { buffer, outputLen } = this;
    this._writeDigest(buffer);
    const res = buffer.slice(0, outputLen);
    if (this.opts.cleanup) this.clean();
    return res;
  }
  _clean() {}
  _cloneOpts() {
    return Object.assign({}, this.opts, {
      key: undefined,
      salt: undefined,
      personalization: undefined,
    });
  }
}
