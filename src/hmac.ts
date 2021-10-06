// prettier-ignore
import {
  assertHash, checkOpts, Cloneable, cloneHashInto, Hash, CHash, Input, PartialOpts, toBytes
} from './utils';

// HMAC (RFC 2104)
class _Hmac extends Hash {
  oHash: Hash;
  iHash: Hash;
  blockLen: number;
  outputLen: number;
  opts: PartialOpts;
  done = false;

  constructor(hash: CHash, _key: Input, _opts?: PartialOpts) {
    super();
    assertHash(hash);
    const opts = (this.opts = checkOpts({}, _opts));
    const key = toBytes(_key);
    this.iHash = hash.init(opts);
    if (!(this.iHash instanceof Hash))
      throw new TypeError('Expected instance of class which extends utils.Hash');
    const blockLen = (this.blockLen = this.iHash.blockLen);
    this.outputLen = this.iHash.outputLen;
    const pad = new Uint8Array(blockLen);
    // blockLen can be bigger than outputLen
    pad.set(key.length > this.iHash.blockLen ? hash.init(opts).update(key).digest() : key);
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36;
    this.iHash.update(pad);
    // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
    this.oHash = hash.init(opts);
    // Undo internal XOR && apply outer XOR
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c;
    this.oHash.update(pad);
    if (opts.cleanup) pad.fill(0);
  }
  update(buf: Input) {
    this.iHash.update(toBytes(buf));
    return this;
  }
  _writeDigest(out: Uint8Array) {
    if (!this.done) {
      this.done = true;
      this.iHash._writeDigest(out);
      this.oHash.update(out);
    }
    this.oHash._writeDigest(out);
  }
  digest() {
    if (!this.done) {
      this.done = true;
      this.oHash.update(this.iHash.digest());
    }
    return this.oHash.digest();
  }
  _cloneInto(obj?: this) {
    if (!obj) obj = Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, done, blockLen, outputLen, opts } = this;
    obj = obj as this;
    obj.done = done;
    obj.opts = opts;
    obj.blockLen = blockLen;
    obj.outputLen = outputLen;
    obj.oHash = cloneHashInto(oHash as Cloneable, obj.oHash as Cloneable);
    obj.iHash = cloneHashInto(iHash as Cloneable, obj.iHash as Cloneable);
    return obj as this;
  }
  clean() {
    this.oHash.clean();
    this.iHash.clean();
  }
}

export const hmac = (hash: CHash, key: Input, msg: Input, opts?: PartialOpts): Uint8Array =>
  new _Hmac(hash, key, opts).update(toBytes(msg)).digest();
hmac.init = (hash: CHash, key: Input, opts?: PartialOpts) => new _Hmac(hash, key, opts);
