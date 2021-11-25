import { _n, Hash, createView, Input, toBytes } from './utils';

const _32n = _n(32);
const _u32_max = _n(0xffffffff);

// Polyfill for Safari 14
function setBigUint64(view: DataView, byteOffset: number, value: bigint, isLE: boolean): void {
  if (typeof view.setBigUint64 === 'function') return view.setBigUint64(byteOffset, value, isLE);
  const wh = Number((value >> _32n) & _u32_max);
  const wl = Number(value & _u32_max);
  const [h, l] = isLE ? [4, 0] : [0, 4];
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}

// Base SHA2 class (RFC 6234)
export abstract class SHA2<T extends SHA2<T>> extends Hash<T> {
  protected abstract process(buf: DataView, offset: number): void;
  protected abstract get(): number[];
  protected abstract set(...args: number[]): void;
  abstract destroy(): void;
  protected abstract roundClean(): void;
  // For partial updates less than block size
  protected buffer: Uint8Array;
  protected view: DataView;
  protected finished = false;
  protected length = 0;
  protected pos = 0;
  protected destroyed = false;

  constructor(
    readonly blockLen: number,
    public outputLen: number,
    readonly padOffset: number,
    readonly isLE: boolean
  ) {
    super();
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data: Input): this {
    if (this.destroyed) throw new Error('instance is destroyed');
    const { view, buffer, blockLen, finished } = this;
    if (finished) throw new Error('digest() was already called');
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      // Fast path: we have at least one block in input, cast it to view and process
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out: Uint8Array) {
    if (this.destroyed) throw new Error('instance is destroyed');
    if (!(out instanceof Uint8Array) || out.length < this.outputLen)
      throw new Error('_Sha2: Invalid output buffer');
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    // Padding
    // We can avoid allocation of buffer for padding completely if it
    // was previously not allocated here. But it won't change performance.
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    // append the bit '1' to the message
    buffer[pos++] = 0b10000000;
    this.buffer.subarray(pos).fill(0);
    // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    // Pad until full block byte with zeros
    for (let i = pos; i < blockLen; i++) buffer[i] = 0;
    // NOTE: sha512 requires length to be 128bit integer, but length in JS will overflow before that
    // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
    // So we just write lowest 64bit of that value.
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    this.get().forEach((v, i) => oview.setUint32(4 * i, v, isLE));
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to?: T): T {
    to ||= new (this.constructor as any)() as T;
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen) to.buffer.set(buffer);
    return to;
  }
}
