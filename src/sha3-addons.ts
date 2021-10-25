import { Hash, Input, toBytes, wrapConstructorWithOpts, assertNumber, u32 } from './utils';
import { Keccak, ShakeOpts } from './sha3';
// cSHAKE && KMAC
function leftEncode(n: number): Uint8Array {
  const res = [n & 0xff];
  n >>= 8;
  for (; n > 0; n >>= 8) res.unshift(n & 0xff);
  res.unshift(res.length);
  return new Uint8Array(res);
}

function rightEncode(n: number): Uint8Array {
  const res = [n & 0xff];
  n >>= 8;
  for (; n > 0; n >>= 8) res.unshift(n & 0xff);
  res.push(res.length);
  return new Uint8Array(res);
}

const toBytesOptional = (buf?: Input) => (buf !== undefined ? toBytes(buf) : new Uint8Array([]));
// NOTE: second modulo is necessary since we don't need to add padding if current element takes whole block
const getPadding = (len: number, block: number) => new Uint8Array((block - (len % block)) % block);
export type cShakeOpts = ShakeOpts & { personalization?: Input; NISTfn?: Input };

// Personalization
function cshakePers(hash: Keccak, opts: cShakeOpts = {}): Keccak {
  if (!opts || (!opts.personalization && !opts.NISTfn)) return hash;
  // Encode and pad inplace to avoid unneccesary memory copies/slices (so we don't need to zero them later)
  // bytepad(encode_string(N) || encode_string(S), 168)
  const blockLenBytes = leftEncode(hash.blockLen);
  const fn = toBytesOptional(opts.NISTfn);
  const fnLen = leftEncode(8 * fn.length); // length in bits
  const pers = toBytesOptional(opts.personalization);
  const persLen = leftEncode(8 * pers.length); // length in bits
  if (!fn.length && !pers.length) return hash;
  hash.suffix = 0x04;
  hash.update(blockLenBytes).update(fnLen).update(fn).update(persLen).update(pers);
  let totalLen = blockLenBytes.length + fnLen.length + fn.length + persLen.length + pers.length;
  hash.update(getPadding(totalLen, hash.blockLen));
  return hash;
}

const gencShake = (suffix: number, blockLen: number, outputLen: number) =>
  wrapConstructorWithOpts<Keccak, cShakeOpts>((opts: cShakeOpts = {}) =>
    cshakePers(
      new Keccak(blockLen, suffix, opts.dkLen !== undefined ? opts.dkLen : outputLen),
      opts
    )
  );

export const cshake128 = gencShake(0x1f, 168, 128 / 8);
export const cshake256 = gencShake(0x1f, 136, 256 / 8);

class KMAC extends Keccak {
  constructor(
    public blockLen: number,
    public outputLen: number,
    key: Input,
    opts: cShakeOpts = {}
  ) {
    super(blockLen, 0x1f, outputLen);
    cshakePers(this, { NISTfn: 'KMAC', personalization: opts.personalization });
    key = toBytes(key);
    // 1. newX = bytepad(encode_string(K), 168) || X || right_encode(L).
    const blockLenBytes = leftEncode(this.blockLen);
    const keyLen = leftEncode(8 * key.length);
    this.update(blockLenBytes).update(keyLen).update(key);
    const totalLen = blockLenBytes.length + keyLen.length + key.length;
    this.update(getPadding(totalLen, this.blockLen));
  }
  _writeDigest(buf: Uint8Array) {
    this.update(rightEncode(this.outputLen * 8)); // outputLen in bits
    return Keccak.prototype._writeDigest.call(this, buf);
  }
  _cloneInto(to?: KMAC): KMAC {
    // Create new instance without calling constructor since key already in state and we don't know it.
    // Force "to" to be instance of KMAC instead of Sha3.
    if (!to) {
      to = Object.create(Object.getPrototypeOf(this), {}) as KMAC;
      to.state = this.state.slice();
      to.blockLen = this.blockLen;
      to.state32 = u32(to.state);
    }
    return Keccak.prototype._cloneInto.call(this, to) as KMAC;
  }
}

function genKmac(blockLen: number, outputLen: number) {
  const kmac = (key: Input, message: Input, opts?: cShakeOpts): Uint8Array =>
    kmac.create(key, opts).update(message).digest();
  kmac.create = (key: Input, opts: cShakeOpts = {}) =>
    new KMAC(blockLen, opts.dkLen !== undefined ? opts.dkLen : outputLen, key, opts);
  kmac.init = kmac.create;
  return kmac;
}

export const kmac128 = genKmac(168, 128 / 8);
export const kmac256 = genKmac(136, 256 / 8);

// Kangaroo
// Same as NIST rightEncode, but returns [0] for zero string
function rightEncodeK12(n: number): Uint8Array {
  const res = [];
  for (; n > 0; n >>= 8) res.unshift(n & 0xff);
  res.push(res.length);
  return new Uint8Array(res);
}

export type KangarooOpts = { dkLen?: number; personalization?: Input };
const EMPTY = new Uint8Array([]);

class KangarooTwelve extends Hash<KangarooTwelve> {
  outputLen: number;
  blockLen = 8192;
  private finished = false;
  private rootHash: Keccak;
  private leafHash?: Keccak;
  private length = 0;
  private personalization: Uint8Array;
  constructor(
    private rounds = 12,
    private leafBlockLen = 168,
    private leafOutputLen = 32,
    opts: KangarooOpts = {}
  ) {
    super();
    let { dkLen, personalization } = opts;
    if (dkLen !== undefined) assertNumber(dkLen);
    dkLen ||= 32;
    this.outputLen = dkLen;
    this.personalization = toBytesOptional(personalization);
    this.rootHash = new Keccak(leafBlockLen, 0x07, dkLen, rounds);
  }
  newLeaf() {
    return (this.leafHash = new Keccak(this.leafBlockLen, 0x0b, this.leafOutputLen, this.rounds));
  }
  update(data: Input) {
    data = toBytes(data);
    const { blockLen, rootHash } = this;
    let pos = 0; // Position inside data buffer
    let leaf: Keccak | undefined = this.leafHash;
    // First block is not filled yet
    if (!leaf) {
      if (this.length < blockLen) {
        const left = Math.min(blockLen - (this.length % blockLen), data.length);
        rootHash.update(data.subarray(0, left));
        pos += left;
        this.length += left;
      }
      // Fast path, there is no bytes left
      if (pos === data.length) return this;
      // At this point first block is filled and we still has bytes left -> create leaf node
      rootHash.suffix = 0x06; // Its safe to change suffix here since its used only in digest()
      rootHash.update(new Uint8Array([3, 0, 0, 0, 0, 0, 0, 0]));
      leaf = this.newLeaf();
    }
    // At this point we have always have leafHash
    while (data.length - pos) {
      const left = Math.min(blockLen - (this.length % blockLen), data.length - pos);
      leaf.update(data.subarray(pos, pos + left));
      pos += left;
      this.length += left;
      if (this.length % blockLen) continue;
      // Leaf finished
      rootHash.update(leaf.digest());
      leaf = this.newLeaf();
    }
    return this;
  }
  _writeDigest(buf: Uint8Array) {
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    const { personalization, rootHash, blockLen } = this;
    this.update(personalization);
    this.update(rightEncodeK12(personalization.length));
    // Leaf hash
    if (this.leafHash) {
      rootHash.update(this.leafHash.digest());
      const leafBlocks = Math.ceil(this.length / blockLen) - 1; // First block is root
      rootHash.update(rightEncodeK12(leafBlocks)).update(new Uint8Array([0xff, 0xff]));
    }
    rootHash._writeDigest(buf);
  }
  digest() {
    const res = new Uint8Array(this.outputLen);
    this._writeDigest(res);
    this._clean();
    return res;
  }
  _clean() {
    this.rootHash._clean();
    if (this.leafHash) this.leafHash._clean();
    // We cannot zero personalization buffer since it is user provided and we don't want to mutate user input
    this.personalization = EMPTY;
  }
  _cloneInto(to?: KangarooTwelve): KangarooTwelve {
    const { outputLen, personalization, length, finished, rootHash, leafHash } = this;
    to ||= new KangarooTwelve(this.rounds, this.leafBlockLen, this.leafOutputLen, {
      dkLen: outputLen,
      personalization,
    });
    rootHash._cloneInto(to.rootHash);
    if (leafHash) to.leafHash = leafHash._cloneInto(to.leafHash);
    to.length = length;
    to.finished = finished;
    return to;
  }
}
// Default to 32 bytes, so it can be used without opts
export const k12 = wrapConstructorWithOpts<KangarooTwelve, KangarooOpts>(
  (opts?: KangarooOpts) => new KangarooTwelve(12, 168, 32, opts)
);
// MarsupilamiFourteen
export const m14 = wrapConstructorWithOpts<KangarooTwelve, KangarooOpts>(
  (opts?: KangarooOpts) => new KangarooTwelve(14, 136, 64, opts)
);
