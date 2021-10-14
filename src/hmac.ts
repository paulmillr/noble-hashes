// prettier-ignore
import {
  assertHash, Cloneable, cloneHashInto, Hash, CHash, Input, toBytes
} from './utils';

// HMAC (RFC 2104)
class HMAC extends Hash {
  oHash: Hash;
  iHash: Hash;
  blockLen: number;
  outputLen: number;
  finished = false;

  constructor(hash: CHash, _key: Input) {
    super();
    assertHash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
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
    this.oHash = hash.create();
    // Undo internal XOR && apply outer XOR
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c;
    this.oHash.update(pad);
    pad.fill(0);
  }
  update(buf: Input) {
    this.iHash.update(buf);
    return this;
  }
  _writeDigest(out: Uint8Array) {
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    this.iHash._writeDigest(out);
    this.oHash.update(out);
    this.oHash._writeDigest(out);
    this._clean();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this._writeDigest(out);
    return out;
  }
  _cloneInto(obj?: this) {
    if (!obj) obj = Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, blockLen, outputLen } = this;
    obj = obj as this;
    obj.finished = finished;
    obj.blockLen = blockLen;
    obj.outputLen = outputLen;
    obj.oHash = cloneHashInto(oHash as Cloneable, obj.oHash as Cloneable);
    obj.iHash = cloneHashInto(iHash as Cloneable, obj.iHash as Cloneable);
    return obj as this;
  }
  _clean() {
    this.oHash._clean();
    this.iHash._clean();
  }
}

export const hmac = (hash: CHash, key: Input, message: Input): Uint8Array =>
  new HMAC(hash, key).update(message).digest();
hmac.create = (hash: CHash, key: Input) => new HMAC(hash, key);
hmac.init = hmac.create;
