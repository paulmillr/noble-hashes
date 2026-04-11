/**
 * PBKDF (RFC 2898). Can be used to create a key from password and salt.
 * @module
 */
import { hmac } from './hmac.ts';
// prettier-ignore
import {
  ahash, anumber,
  asyncLoop, checkOpts, clean, createView, kdfInputToBytes,
  type CHash,
  type Hash,
  type KDFInput,
  type TArg,
  type TRet
} from './utils.ts';

/**
 * PBKDF2 options:
 * * c: iterations, should probably be higher than 100_000
 * * dkLen: desired length of derived key in bytes, must be `>= 1` per RFC 8018 §5.2
 * * asyncTick: max time in ms for which async function can block execution
 */
export type Pbkdf2Opt = {
  /** Iteration count. Higher values increase CPU cost. */
  c: number;
  /** Desired derived key length in bytes, must be `>= 1` per RFC 8018 §5.2. */
  dkLen?: number;
  /** Max scheduler block time in milliseconds for the async variant. */
  asyncTick?: number;
};
// Common start and end for sync/async functions
function pbkdf2Init(
  hash: TArg<CHash>,
  _password: TArg<KDFInput>,
  _salt: TArg<KDFInput>,
  _opts: TArg<Pbkdf2Opt>
) {
  ahash(hash);
  const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
  const { c, dkLen, asyncTick } = opts;
  anumber(c, 'c');
  anumber(dkLen, 'dkLen');
  anumber(asyncTick, 'asyncTick');
  if (c < 1) throw new Error('iterations (c) must be >= 1');
  // RFC 8018 §5.2 defines `dkLen` as "a positive integer".
  if (dkLen < 1) throw new Error('"dkLen" must be >= 1');
  // RFC 8018 §5.2 step 1 requires rejecting oversize `dkLen`
  // before allocating the destination buffer.
  if (dkLen > (2 ** 32 - 1) * hash.outputLen) throw new Error('derived key too long');
  const password = kdfInputToBytes(_password, 'password');
  const salt = kdfInputToBytes(_salt, 'salt');
  // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
  const DK = new Uint8Array(dkLen);
  // U1 = PRF(Password, Salt + INT_32_BE(i))
  const PRF = hmac.create(hash, password);
  // Cache PRF(P, S || ...) prefix state so each block only appends INT_32_BE(i).
  const PRFSalt = PRF._cloneInto().update(salt);
  return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}

function pbkdf2Output<T extends Hash<T>>(
  PRF: TArg<Hash<T>>,
  PRFSalt: TArg<Hash<T>>,
  DK: TArg<Uint8Array>,
  prfW: TArg<Hash<T> | undefined>,
  u: TArg<Uint8Array>
): TRet<Uint8Array> {
  // Shared sync/async cleanup point: wipe transient PRF state
  // while preserving the derived key buffer.
  PRF.destroy();
  PRFSalt.destroy();
  if (prfW) prfW.destroy();
  clean(u);
  return DK as TRet<Uint8Array>;
}

/**
 * PBKDF2-HMAC: RFC 8018 key derivation function.
 * @param hash - hash function that would be used e.g. sha256
 * @param password - password from which a derived key is generated;
 *   JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @param opts - PBKDF2 work factor and output settings. `dkLen`, if provided,
 *   must be `>= 1` per RFC 8018 §5.2. See {@link Pbkdf2Opt}.
 * @returns Derived key bytes.
 * @throws If the PBKDF2 iteration count or derived-key settings are invalid. {@link Error}
 * @example
 * PBKDF2-HMAC: RFC 2898 key derivation function.
 * ```ts
 * import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const key = pbkdf2(sha256, 'password', 'salt', { dkLen: 32, c: Math.pow(2, 18) });
 * ```
 */
export function pbkdf2(
  hash: TArg<CHash>,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<Pbkdf2Opt>
): TRet<Uint8Array> {
  const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
  let prfW: any; // Working copy
  const arr = new Uint8Array(4);
  const view = createView(arr);
  const u = new Uint8Array(PRF.outputLen);
  // DK = T1 + T2 + ⋯ + Tdklen/hlen
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    // Ti = F(Password, Salt, c, i)
    // The last Ti view can be shorter than hLen, which applies
    // RFC 8018 §5.2 step 4's T_l<0..r-1> truncation without extra copies.
    const Ti = DK.subarray(pos, pos + PRF.outputLen);
    view.setInt32(0, ti, false);
    // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
    for (let ui = 1; ui < c; ui++) {
      // Uc = PRF(Password, Uc−1)
      PRF._cloneInto(prfW).update(u).digestInto(u);
      for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
    }
  }
  return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}

/**
 * PBKDF2-HMAC: RFC 8018 key derivation function. Async version.
 * @param hash - hash function that would be used e.g. sha256
 * @param password - password from which a derived key is generated;
 *   JS string inputs are UTF-8 encoded first
 * @param salt - cryptographic salt; JS string inputs are UTF-8 encoded first
 * @param opts - PBKDF2 work factor and output settings. `dkLen`, if provided,
 *   must be `>= 1` per RFC 8018 §5.2. `asyncTick` is only a local
 *   scheduler-yield knob for this JS wrapper, not part of RFC 8018.
 *   See {@link Pbkdf2Opt}.
 * @returns Promise resolving to derived key bytes.
 * @throws If the PBKDF2 iteration count or derived-key settings are invalid. {@link Error}
 * @example
 * PBKDF2-HMAC: RFC 2898 key derivation function.
 * ```ts
 * import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const key = await pbkdf2Async(sha256, 'password', 'salt', { dkLen: 32, c: 500_000 });
 * ```
 */
export async function pbkdf2Async(
  hash: TArg<CHash>,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: TArg<Pbkdf2Opt>
): Promise<TRet<Uint8Array>> {
  const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
  let prfW: any; // Working copy
  const arr = new Uint8Array(4);
  const view = createView(arr);
  const u = new Uint8Array(PRF.outputLen);
  // DK = T1 + T2 + ⋯ + Tdklen/hlen
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    // Ti = F(Password, Salt, c, i)
    // The last Ti view can be shorter than hLen, which applies
    // RFC 8018 §5.2 step 4's T_l<0..r-1> truncation without extra copies.
    const Ti = DK.subarray(pos, pos + PRF.outputLen);
    view.setInt32(0, ti, false);
    // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
    await asyncLoop(c - 1, asyncTick, () => {
      // Uc = PRF(Password, Uc−1)
      PRF._cloneInto(prfW).update(u).digestInto(u);
      for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
    });
  }
  return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
