/**
 * HKDF (RFC 5869): extract + expand in one step.
 * See {@link https://soatok.blog/2021/11/17/understanding-hkdf/}.
 * @module
 */
import { hmac } from './hmac.ts';
import { abytes, ahash, anumber, type CHash, clean, type TArg, type TRet } from './utils.ts';

/**
 * HKDF-extract from spec. Less important part. `HKDF-Extract(IKM, salt) -> PRK`
 * Arguments position differs from spec (IKM is first one, since it is not optional)
 * Local validation only checks `hash`; `ikm` / `salt` byte validation is delegated to `hmac()`.
 * @param hash - hash function that would be used (e.g. sha256)
 * @param ikm - input keying material, the initial key
 * @param salt - optional salt value (a non-secret random value)
 * @returns Pseudorandom key derived from input keying material.
 * @example
 * Run the HKDF extract step.
 * ```ts
 * import { extract } from '@noble/hashes/hkdf.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * extract(sha256, new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
 * ```
 */
export function extract(
  hash: TArg<CHash>,
  ikm: TArg<Uint8Array>,
  salt?: TArg<Uint8Array>
): TRet<Uint8Array> {
  ahash(hash);
  // NOTE: some libraries treat zero-length array as 'not provided';
  // we don't, since we have undefined as 'not provided'
  // https://github.com/RustCrypto/KDFs/issues/15
  if (salt === undefined) salt = new Uint8Array(hash.outputLen);
  return hmac(hash, salt, ikm);
}

// Shared mutable scratch byte for the RFC 5869 block counter `N`.
// Safe to reuse because `expand()` is synchronous and resets it with `clean(...)` before returning.
const HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
// Shared RFC 5869 empty string for both `info === undefined` and the first-block `T(0)` input.
const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();

/**
 * HKDF-expand from the spec. The most important part. `HKDF-Expand(PRK, info, L) -> OKM`
 * @param hash - hash function that would be used (e.g. sha256)
 * @param prk - a pseudorandom key of at least HashLen octets
 *   (usually, the output from the extract step)
 * @param info - optional context and application specific information (can be a zero-length string)
 * @param length - length of output keying material in bytes.
 *   RFC 5869 §2.3 allows `0..255*HashLen`, so `0` returns an empty OKM.
 * @returns Output keying material with the requested length.
 * @throws If the requested output length exceeds the HKDF limit
 *   for the selected hash. {@link Error}
 * @example
 * Run the HKDF expand step.
 * ```ts
 * import { expand } from '@noble/hashes/hkdf.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * expand(sha256, new Uint8Array(32), new Uint8Array([1, 2, 3]), 16);
 * ```
 */
export function expand(
  hash: TArg<CHash>,
  prk: TArg<Uint8Array>,
  info?: TArg<Uint8Array>,
  length: number = 32
): TRet<Uint8Array> {
  ahash(hash);
  anumber(length, 'length');
  abytes(prk, undefined, 'prk');
  const olen = hash.outputLen;
  // RFC 5869 §2.3: PRK is "a pseudorandom key of at least HashLen octets".
  if (prk.length < olen) throw new Error('"prk" must be at least HashLen octets');
  // RFC 5869 §2.3 only bounds `L` by `<= 255*HashLen`; `L=0` is valid and yields empty OKM.
  if (length > 255 * olen) throw new Error('Length must be <= 255*HashLen');
  const blocks = Math.ceil(length / olen);
  if (info === undefined) info = EMPTY_BUFFER;
  else abytes(info, undefined, 'info');
  // first L(ength) octets of T
  const okm = new Uint8Array(blocks * olen);
  // Re-use HMAC instance between blocks
  const HMAC = hmac.create(hash, prk);
  const HMACTmp = HMAC._cloneInto();
  const T = new Uint8Array(HMAC.outputLen);
  for (let counter = 0; counter < blocks; counter++) {
    HKDF_COUNTER[0] = counter + 1;
    // T(0) = empty string (zero length)
    // T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
    HMACTmp.update(counter === 0 ? EMPTY_BUFFER : T)
      .update(info)
      .update(HKDF_COUNTER)
      .digestInto(T);
    okm.set(T, olen * counter);
    HMAC._cloneInto(HMACTmp);
  }
  HMAC.destroy();
  HMACTmp.destroy();
  clean(T, HKDF_COUNTER);
  return okm.slice(0, length) as TRet<Uint8Array>;
}

/**
 * HKDF (RFC 5869): derive keys from an initial input.
 * Combines hkdf_extract + hkdf_expand in one step
 * @param hash - hash function that would be used (e.g. sha256)
 * @param ikm - input keying material, the initial key
 * @param salt - optional salt value (a non-secret random value)
 * @param info - optional context and application specific information bytes
 * @param length - length of output keying material in bytes.
 *   RFC 5869 §2.3 allows `0..255*HashLen`, so `0` returns an empty OKM.
 * @returns Output keying material derived from the input key.
 * @throws If the requested output length exceeds the HKDF limit
 *   for the selected hash. {@link Error}
 * @example
 * HKDF (RFC 5869): derive keys from an initial input.
 * ```ts
 * import { hkdf } from '@noble/hashes/hkdf.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
 * const inputKey = randomBytes(32);
 * const salt = randomBytes(32);
 * const info = utf8ToBytes('application-key');
 * const okm = hkdf(sha256, inputKey, salt, info, 32);
 * ```
 */
export const hkdf = (
  hash: TArg<CHash>,
  ikm: TArg<Uint8Array>,
  salt: TArg<Uint8Array | undefined>,
  info: TArg<Uint8Array | undefined>,
  length: number
): TRet<Uint8Array> => expand(hash, extract(hash, ikm, salt), info, length);
