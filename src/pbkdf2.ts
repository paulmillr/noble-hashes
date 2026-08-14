/**
 * PBKDF (RFC 2898). Can be used to create a key from password and salt.
 * @module
 */
import { hmac } from './hmac.ts';
import { pbkdf2Get, type Pbkdf2FastFactory } from './_pbkdf2.ts';
// prettier-ignore
import {
  ahash, anumber,
  checkOpts, clean, createView, kdfInputToBytes, nextTick,
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

// Private scheduler loop. Inputs were validated by pbkdf2Init; the resume hook revalidates an
// accelerator after scheduler yields. As elsewhere, patched built-in intrinsics are unsupported.
async function pbkdf2AsyncLoop(
  iters: number,
  tick: number,
  cb: () => void,
  afterYield?: () => void
) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb();
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await nextTick();
    afterYield?.();
    ts += diff;
  }
}
// Common validation and per-call state setup for sync/async functions.
function pbkdf2Init(
  hash: TArg<CHash>,
  _password: TArg<KDFInput>,
  _salt: TArg<KDFInput>,
  _opts: Pbkdf2Opt,
  isAsync: boolean
) {
  ahash(hash);
  const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
  const { c, dkLen, asyncTick } = opts;
  anumber(c, 'c');
  anumber(dkLen, 'dkLen');
  anumber(asyncTick, 'asyncTick');
  if (c < 1) throw new Error('"c" (iterations) must be >= 1');
  // RFC 8018 §5.2 defines `dkLen` as "a positive integer".
  if (dkLen < 1) throw new Error('"dkLen" must be >= 1');
  // RFC 8018 §5.2 step 1 requires rejecting oversize `dkLen`
  // before allocating the destination buffer.
  if (dkLen > (2 ** 32 - 1) * hash.outputLen) throw new Error('derived key too long');
  const p = kdfInputToBytes(_password, 'password');
  const s = kdfInputToBytes(_salt, 'salt');
  // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
  const DK = new Uint8Array(dkLen);
  const { iHash, oHash, outputLen } = hmac.create(hash, p);
  // Drive keyed hashes directly; the wrapper is only needed to initialize their HMAC midstates.
  const u = new Uint8Array(outputLen);
  // c=1 is intentionally the exact generic path: scrypt uses PBKDF2-HMAC-SHA256(c=1), and a
  // feedback-round accelerator cannot help it. This also avoids scratch allocation and lookup.
  // The factory/guard cost is larger and less stable than the saved feedback work below this
  // conservative all-engine crossover. Async tick=0 yields every round, so its post-resume guard
  // dominates and stays on the generic path.
  const fast = c >= 1000 && (!isAsync || asyncTick > 0) ? pbkdf2Get(hash) : undefined;
  const eng = pbkdf2Engine(iHash, oHash, s, u, fast);
  return { c, dkLen, asyncTick, DK, outputLen, eng };
}

// Per-call PRF driver writes U1 into both `u` and `Ti`, then later digests into `u`;
// shared by the sync and async variants.
function pbkdf2Engine(
  iHash: TArg<Hash<any>>,
  oHash: TArg<Hash<any>>,
  salt: TArg<Uint8Array>,
  u: TArg<Uint8Array>,
  fastFactory?: TArg<Pbkdf2FastFactory>
) {
  const counter = new Uint8Array(4);
  const view = createView(counter);
  // Full clones retain tree/config state; absorb salt before async yields without cloning input.
  const salted = iHash._cloneInto().update(salt);
  // u1() overwrites the worker before reading it. Seed from the outer midstate so a long salt
  // cannot pre-populate a tree stack that the first reset would abandon without wiping.
  const work = oHash._cloneInto();
  const factory = fastFactory as Pbkdf2FastFactory | undefined;
  let attempted = !factory;
  let fast: ReturnType<Pbkdf2FastFactory>;
  const iClone = iHash._cloneInto; // Capture before mixed feedback can materialize state tuples.
  const oClone = oHash._cloneInto;
  const disableFast = (Ti: TArg<Uint8Array>, snapshot: boolean) => {
    if (!fast) return;
    if (snapshot) fast.snapshot(u, Ti);
    fast.destroy();
    fast = undefined;
  };
  return {
    u1: (ti: number, Ti: TArg<Uint8Array>) => {
      try {
        view.setInt32(0, ti, false);
        salted._cloneInto(work).update(counter).digestInto(u);
        oHash._cloneInto(work).update(u).digestInto(u);
      } catch (error) {
        // A later block can fail after keyed fast state exists; wipe it before propagating.
        disableFast(Ti, false);
        throw error;
      }
      // Delay keyed numeric-state allocation until generic U1 has completed successfully. Attempt
      // only once: a guard-disabled async engine must not be recreated for subsequent blocks.
      if (!attempted) {
        attempted = true;
        fast = factory?.(iHash, oHash);
      }
      if (fast && !fast.valid()) disableFast(Ti, false);
      if (fast) fast.start(u);
      else Ti.set(u.subarray(0, Ti.length));
    },
    // Whole `F` inner loop for the sync variant: one optimized function owns the hot loop.
    rounds: (c: number, Ti: TArg<Uint8Array>) => {
      if (fast) return fast.rounds(c - 1);
      for (let ui = 1; ui < c; ui++) {
        iClone.call(iHash, work).update(u).digestInto(u);
        oClone.call(oHash, work).update(u).digestInto(u);
        for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
      }
    },
    finish: (Ti: TArg<Uint8Array>) => fast?.finish(Ti),
    fast: () => !!fast,
    validate: (Ti: TArg<Uint8Array>) => {
      if (fast && !fast.valid()) disableFast(Ti, true);
    },
    output: (DK: TArg<Uint8Array>): TRet<Uint8Array> => {
      // Keyed templates and derived worker states are secret material.
      fast?.destroy();
      fast = undefined;
      iHash.destroy();
      oHash.destroy();
      salted.destroy();
      work.destroy();
      // Shared sync/async cleanup point: wipe transient PRF state
      // while preserving the derived key buffer.
      clean(u);
      return DK as TRet<Uint8Array>;
    },
  };
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
  opts: Pbkdf2Opt
): TRet<Uint8Array> {
  const { c, dkLen, DK, outputLen, eng } = pbkdf2Init(hash, password, salt, opts, false);
  // DK = T1 + T2 + ⋯ + Tdklen/hlen
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += outputLen) {
    // Ti = F(Password, Salt, c, i)
    // The last Ti view can be shorter than hLen, which applies
    // RFC 8018 §5.2 step 4's T_l<0..r-1> truncation without extra copies.
    const Ti = DK.subarray(pos, pos + outputLen);
    // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    eng.u1(ti, Ti);
    // Uc = PRF(Password, Uc−1); Ti ^= Uc
    eng.rounds(c, Ti);
    eng.finish(Ti);
  }
  return eng.output(DK);
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
 * @example
 * Tune the async PBKDF2 scheduler for short UI tasks.
 * ```ts
 * import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const key = await pbkdf2Async(sha256, 'password', 'salt', {
 *   dkLen: 32,
 *   c: 32,
 *   asyncTick: 1,
 * });
 * ```
 */
export async function pbkdf2Async(
  hash: TArg<CHash>,
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: Pbkdf2Opt
): Promise<TRet<Uint8Array>> {
  const { c, dkLen, asyncTick, DK, outputLen, eng } = pbkdf2Init(hash, password, salt, opts, true);
  // DK = T1 + T2 + ⋯ + Tdklen/hlen
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += outputLen) {
    // Ti = F(Password, Salt, c, i)
    // The last Ti view can be shorter than hLen, which applies
    // RFC 8018 §5.2 step 4's T_l<0..r-1> truncation without extra copies.
    const Ti = DK.subarray(pos, pos + outputLen);
    // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    eng.u1(ti, Ti);
    const afterYield = eng.fast() ? () => eng.validate(Ti) : undefined;
    await pbkdf2AsyncLoop(
      c - 1,
      asyncTick,
      () => eng.rounds(2, Ti), // c=2 executes exactly one feedback iteration.
      // Revalidate after the library yields, then either continue numeric state or snapshot U/T
      // and finish through the generic engine. Patched built-in intrinsics are unsupported.
      afterYield
    );
    eng.finish(Ti);
  }
  return eng.output(DK);
}
