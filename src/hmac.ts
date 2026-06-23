/**
 * HMAC: RFC2104 message authentication code.
 * @module
 */
import {
  abytes,
  aexists,
  ahash,
  aoutput,
  clean,
  type CHash,
  type Hash,
  type TArg,
  type TRet,
} from './utils.ts';

/**
 * Internal class for HMAC.
 * Accepts any byte key, although RFC 2104 §3 recommends keys at least
 * `HashLen` bytes long.
 */
export class _HMAC<T extends Hash<T>> implements Hash<_HMAC<T>> {
  oHash?: T;
  iHash: T;
  blockLen: number;
  outputLen: number;
  canXOF = false;
  private hash?: CHash;
  private oPad?: Uint8Array;
  private finished = false;
  private destroyed = false;

  constructor(hash: TArg<CHash>, key: TArg<Uint8Array>, fast = false) {
    ahash(hash);
    abytes(key, undefined, 'key');
    this.iHash = hash.create() as T;
    if (typeof this.iHash.update !== 'function')
      throw new Error('Expected instance of class which extends utils.Hash');
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    // blockLen can be bigger than outputLen
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36;
    this.iHash.update(pad);
    // Undo internal XOR && apply outer XOR.
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c;
    if (fast) {
      // Precompute the outer pad block for one-shot HMAC/KDF hot paths.
      this.oHash = hash.create() as T;
      this.oHash.update(pad);
      clean(pad);
    } else {
      // Retain only opad for long-lived states: lower RAM, one extra block update at digest.
      this.hash = hash as CHash;
      this.oPad = pad;
    }
  }
  update(buf: TArg<Uint8Array>): this {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out: TArg<Uint8Array>): void {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    // Reuse the first outputLen bytes for the inner digest; the outer hash consumes them before
    // overwriting that same prefix with the final tag, leaving any oversized tail untouched.
    this.iHash.digestInto(buf);
    if (this.oHash) {
      this.oHash.update(buf).digestInto(buf);
    } else {
      const oHash = this.hash!.create() as T;
      oHash.update(this.oPad!).update(buf).digestInto(buf);
      oHash.destroy();
    }
    this.destroy();
  }
  digest(): TRet<Uint8Array> {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out as TRet<Uint8Array>;
  }
  _cloneInto(to?: _HMAC<T>): _HMAC<T> {
    // Create new instance without calling constructor since the key
    // is already in state and we don't know it.
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { hash, oHash, iHash, oPad, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to as this;
    to.hash = hash;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    if (oHash) {
      if (to.oPad) clean(to.oPad);
      to.oPad = undefined;
      to.oHash = oHash._cloneInto(to.oHash);
    } else {
      if (to.oHash) to.oHash.destroy();
      to.oHash = undefined;
      if (!to.oPad || to.oPad.length !== oPad!.length) {
        if (to.oPad) clean(to.oPad);
        to.oPad = new Uint8Array(oPad!.length);
      }
      to.oPad.set(oPad!);
    }
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone(): _HMAC<T> {
    return this._cloneInto();
  }
  destroy(): void {
    this.destroyed = true;
    if (this.oHash) this.oHash.destroy();
    this.iHash.destroy();
    if (this.oPad) clean(this.oPad);
  }
}

export const _createHMAC = <T extends Hash<T>>(
  hash: TArg<CHash>,
  key: TArg<Uint8Array>,
  fast = false
): TRet<_HMAC<T>> => new _HMAC<T>(hash, key, fast) as TRet<_HMAC<T>>;

/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * Compute an RFC 2104 HMAC directly and with an incremental state.
 * ```ts
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const key = new Uint8Array([1, 2, 3]);
 * const message = new Uint8Array([4, 5, 6]);
 * const mac = hmac(sha256, key, message);
 * const out = new Uint8Array(sha256.outputLen);
 * hmac.create(sha256, key).update(message).digestInto(out);
 * ```
 */
type HmacFn = {
  (hash: TArg<CHash>, key: TArg<Uint8Array>, message: TArg<Uint8Array>): TRet<Uint8Array>;
  create(hash: TArg<CHash>, key: TArg<Uint8Array>): TRet<_HMAC<any>>;
};
export const hmac: TRet<HmacFn> = /* @__PURE__ */ (() => {
  const hmac_ = ((
    hash: TArg<CHash>,
    key: TArg<Uint8Array>,
    message: TArg<Uint8Array>
  ): TRet<Uint8Array> =>
    _createHMAC<any>(hash, key, true).update(message).digest()) as TRet<HmacFn>;
  hmac_.create = (hash: TArg<CHash>, key: TArg<Uint8Array>): TRet<_HMAC<any>> =>
    _createHMAC<any>(hash, key);
  return hmac_;
})();
