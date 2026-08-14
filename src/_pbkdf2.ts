/** Internal exact-identity PBKDF2 accelerator registry. @module */
import type { CHash, Hash, TArg, TRet } from './utils.ts';

export type Pbkdf2FastEngine = {
  /** Parse U1 and reset the numeric U/T state for a new output block. */
  start(u: TArg<Uint8Array>): void;
  /** Check captured prototypes/descriptors without invoking user-controlled accessors. */
  valid(): boolean;
  /** Execute a positive number of U2..Uc feedback rounds. */
  rounds(count: number): void;
  /** Serialize the current U and T when an async prototype mutation forces generic fallback. */
  snapshot(u: TArg<Uint8Array>, out: TArg<Uint8Array>): void;
  /** Materialize the accumulated T words, including final-block truncation. */
  finish(out: TArg<Uint8Array>): void;
  /** Wipe every per-call numeric state and schedule. */
  destroy(): void;
};

export type Pbkdf2FastFactory = (
  iHash: TArg<Hash<any>>,
  oHash: TArg<Hash<any>>
) => Pbkdf2FastEngine | undefined;

const FAST = /* @__PURE__ */ new WeakMap<object, Pbkdf2FastFactory>();
const FAST_GET = /* @__PURE__ */ FAST.get.bind(FAST);
const FAST_SET = /* @__PURE__ */ FAST.set.bind(FAST);

/** Register an accelerator while returning the exact callable wrapper for pure construction. */
export function pbkdf2Register<T extends CHash>(hash: T, factory: TArg<Pbkdf2FastFactory>): T {
  FAST_SET(hash, factory as Pbkdf2FastFactory);
  return hash;
}

/** Exact wrapper identity lookup; user-created lookalikes always stay on the generic path. */
export function pbkdf2Get(hash: TArg<CHash>): TRet<Pbkdf2FastFactory | undefined> {
  return FAST_GET(hash as CHash);
}

type Descriptor = PropertyDescriptor & { owner: object };

/** Capture lookup descriptors once; later checks never read a potentially patched property. */
export function pbkdf2Guard(proto: object, keys: string[]): (hash: object) => boolean {
  const getProto = Object.getPrototypeOf;
  const getDesc = Object.getOwnPropertyDescriptor;
  const chain: object[] = [];
  for (let at: object | null = proto; at; at = getProto(at)) chain.push(at);
  const descriptors: Record<string, Descriptor> = {};
  for (const key of keys) {
    for (const owner of chain) {
      const desc = getDesc(owner, key);
      if (desc) {
        descriptors[key] = { ...desc, owner };
        break;
      }
    }
    if (!descriptors[key]) throw new Error('PBKDF2 guard method missing: ' + key);
  }
  const same = (a: PropertyDescriptor | undefined, b: Descriptor) =>
    !!a &&
    a.value === b.value &&
    a.get === b.get &&
    a.set === b.set &&
    a.writable === b.writable &&
    a.enumerable === b.enumerable &&
    a.configurable === b.configurable;
  return (hash: object) => {
    if (getProto(hash) !== proto) return false;
    for (let i = 0; i < chain.length; i++)
      if (getProto(chain[i]) !== (chain[i + 1] || null)) return false;
    for (const key of keys) {
      if (getDesc(hash, key)) return false;
      const expected = descriptors[key];
      let found = false;
      for (const owner of chain) {
        const desc = getDesc(owner, key);
        if (desc) {
          found = true;
          if (owner !== expected.owner || !same(desc, expected)) return false;
          break;
        }
      }
      if (!found) return false;
    }
    return true;
  };
}
