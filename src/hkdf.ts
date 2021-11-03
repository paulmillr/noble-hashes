// prettier-ignore
import {
  assertHash, assertNumber, CHash, Input, toBytes
} from './utils';
import { hmac } from './hmac';

// HKDF (RFC 5869)
// HKDF-Extract(IKM, salt) -> PRK NOTE: arguments position differs from spec (IKM is first one, since it is not optional)
export function hkdf_extract(hash: CHash, ikm: Input, salt?: Input) {
  assertHash(hash);
  // NOTE: some libraries treats zero-length array as 'not provided', we don't, since we have undefined as 'not provided'
  // More info: https://github.com/RustCrypto/KDFs/issues/15
  if (salt === undefined) salt = new Uint8Array(hash.outputLen); // if not provided, it is set to a string of HashLen zeros
  return hmac(hash, toBytes(salt), toBytes(ikm));
}

// HKDF-Expand(PRK, info, L) -> OKM
const HKDF_COUNTER = new Uint8Array([0]);
const EMPTY_BUFFER = new Uint8Array();
export function hkdf_expand(
  hash: CHash,
  prk: Input, // a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
  info?: Input, // optional context and application specific information (can be a zero-length string)
  length: number = 32 // length of output keying material in octets
) {
  assertHash(hash);
  assertNumber(length);
  if (length > 255 * hash.outputLen) throw new Error('Length should be <= 255*HashLen');
  const blocks = Math.ceil(length / hash.outputLen);
  if (info === undefined) info = EMPTY_BUFFER;
  // first L(ength) octets of T
  const okm = new Uint8Array(blocks * hash.outputLen);
  // Re-use HMAC instance between blocks
  const HMAC = hmac.init(hash, prk);
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
    okm.set(T, hash.outputLen * counter);
    HMAC._cloneInto(HMACTmp);
  }
  HMAC.destroy();
  HMACTmp.destroy();
  T.fill(0);
  return okm.slice(0, length);
}
// Extract+Expand
export const hkdf = (
  hash: CHash,
  ikm: Input,
  salt: Input | undefined,
  info: Input | undefined,
  length: number
) => hkdf_expand(hash, hkdf_extract(hash, ikm, salt), info, length);
