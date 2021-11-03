import { assertHash, Hash, CHash, Input, toBytes } from './utils';
// HMAC (RFC 2104)
class HMAC<T extends Hash<T>> extends Hash<HMAC<T>> {
  oHash: T;
  iHash: T;
  blockLen: number;
  outputLen: number;
  private finished = false;
  private destroyed = false;

  constructor(hash: CHash, _key: Input) {
    super();
    assertHash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create() as T;
    if (!(this.iHash instanceof Hash))
      throw new TypeError('Expected instance of class which extends utils.Hash');
    const blockLen = (this.blockLen = this.iHash.blockLen);
    this.outputLen = this.iHash.outputLen;
    const pad = new Uint8Array(blockLen);
    // blockLen can be bigger than outputLen
    pad.set(key.length > this.iHash.blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36;
    this.iHash.update(pad);
    // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
    this.oHash = hash.create() as T;
    // Undo internal XOR && apply outer XOR
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf: Input) {
    if (this.destroyed) throw new Error('instance is destroyed');
    this.iHash.update(buf);
    return this;
  }
  digestInto(out: Uint8Array) {
    if (this.destroyed) throw new Error('instance is destroyed');
    if (!(out instanceof Uint8Array) || out.length !== this.outputLen)
      throw new Error('HMAC: Invalid output buffer');
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to?: HMAC<T>): HMAC<T> {
    // Create new instance without calling constructor since key already in state and we don't know it.
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to as this;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
}

export const hmac = (hash: CHash, key: Input, message: Input): Uint8Array =>
  new HMAC(hash, key).update(message).digest();
hmac.create = (hash: CHash, key: Input) => new HMAC(hash, key);
hmac.init = hmac.create;
