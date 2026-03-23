/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/**
 * Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
 * @param a - value to test
 * @returns `true` when the value is a Uint8Array-compatible view.
 * @example
 * Check whether a value is a Uint8Array-compatible view.
 * ```ts
 * isBytes(new Uint8Array([1, 2, 3]));
 * ```
 */
export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

/**
 * Asserts something is a positive integer.
 * @param n - number to validate
 * @param title - label included in thrown errors
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate a positive integer option.
 * ```ts
 * anumber(32, 'length');
 * ```
 */
export function anumber(n: number, title: string = ''): void {
  if (typeof n !== 'number') {
    const prefix = title && `"${title}" `;
    throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}

/**
 * Asserts something is Uint8Array.
 * @param value - value to validate
 * @param length - optional exact length constraint
 * @param title - label included in thrown errors
 * @returns The validated byte array.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate that a value is a byte array.
 * ```ts
 * abytes(new Uint8Array([1, 2, 3]));
 * ```
 */
export function abytes(value: Uint8Array, length?: number, title: string = ''): Uint8Array {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : '';
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + 'expected Uint8Array' + ofLen + ', got ' + got;
    if (!bytes) throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}

/**
 * Asserts something is a wrapped hash constructor.
 * @param h - hash constructor to validate
 * @throws On wrong argument types or invalid hash wrapper shape. {@link TypeError}
 * @throws On invalid hash metadata ranges or values. {@link RangeError}
 * @example
 * Validate a callable hash wrapper.
 * ```ts
 * import { ahash } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * ahash(sha256);
 * ```
 */
export function ahash(h: CHash): void {
  if (typeof h !== 'function' || typeof h.create !== 'function')
    throw new TypeError('Hash must wrapped by utils.createHasher');
  anumber(h.outputLen);
  anumber(h.blockLen);
}

/**
 * Asserts a hash instance has not been destroyed or finished.
 * @param instance - hash instance to validate
 * @param checkFinished - whether to reject finalized instances
 * @throws If the hash instance has already been destroyed or finalized. {@link Error}
 * @example
 * Validate that a hash instance is still usable.
 * ```ts
 * import { aexists } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const hash = sha256.create();
 * aexists(hash);
 * ```
 */
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

/**
 * Asserts output is a properly-sized byte array.
 * @param out - destination buffer
 * @param instance - hash instance providing output length
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Validate a caller-provided digest buffer.
 * ```ts
 * import { aoutput } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const hash = sha256.create();
 * aoutput(new Uint8Array(hash.outputLen), hash);
 * ```
 */
export function aoutput(out: any, instance: any): void {
  abytes(out, undefined, 'digestInto() output');
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('"digestInto() output" expected to be of length >=' + min);
  }
}

/** Generic type encompassing 8/16/32-byte array views, but not 64-bit variants. */
// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

/**
 * Casts a typed array view to Uint8Array.
 * @param arr - source typed array
 * @returns Uint8Array view over the same buffer.
 * @example
 * Reinterpret a typed array as bytes.
 * ```ts
 * u8(new Uint32Array([1, 2]));
 * ```
 */
export function u8(arr: TypedArray): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Casts a typed array view to Uint32Array.
 * @param arr - source typed array
 * @returns Uint32Array view over the same buffer.
 * @example
 * Reinterpret a byte array as 32-bit words.
 * ```ts
 * u32(new Uint8Array(8));
 * ```
 */
export function u32(arr: TypedArray): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}

/**
 * Zeroizes typed arrays in place. Warning: JS provides no guarantees.
 * @param arrays - arrays to overwrite with zeros
 * @example
 * Zeroize sensitive buffers in place.
 * ```ts
 * clean(new Uint8Array([1, 2, 3]));
 * ```
 */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

/**
 * Creates a DataView for byte-level manipulation.
 * @param arr - source typed array
 * @returns DataView over the same buffer region.
 * @example
 * Create a DataView over an existing buffer.
 * ```ts
 * createView(new Uint8Array(4));
 * ```
 */
export function createView(arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

/**
 * Rotate-right operation for uint32 values.
 * @param word - source word
 * @param shift - shift amount in bits
 * @returns Rotated word.
 * @example
 * Rotate a 32-bit word to the right.
 * ```ts
 * rotr(0x12345678, 8);
 * ```
 */
export function rotr(word: number, shift: number): number {
  return (word << (32 - shift)) | (word >>> shift);
}

/**
 * Rotate-left operation for uint32 values.
 * @param word - source word
 * @param shift - shift amount in bits
 * @returns Rotated word.
 * @example
 * Rotate a 32-bit word to the left.
 * ```ts
 * rotl(0x12345678, 8);
 * ```
 */
export function rotl(word: number, shift: number): number {
  return (word << shift) | ((word >>> (32 - shift)) >>> 0);
}

/** Whether the current platform is little-endian. */
export const isLE: boolean = /* @__PURE__ */ (() =>
  new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();

/**
 * Byte-swap operation for uint32 values.
 * @param word - source word
 * @returns Word with reversed byte order.
 * @example
 * Reverse the byte order of a 32-bit word.
 * ```ts
 * byteSwap(0x11223344);
 * ```
 */
export function byteSwap(word: number): number {
  return (
    ((word << 24) & 0xff000000) |
    ((word << 8) & 0xff0000) |
    ((word >>> 8) & 0xff00) |
    ((word >>> 24) & 0xff)
  );
}
/**
 * Conditionally byte-swaps a uint32 on big-endian platforms.
 * @param n - source word
 * @returns Original or byte-swapped word depending on platform endianness.
 * @example
 * Normalize a 32-bit word for host endianness.
 * ```ts
 * swap8IfBE(0x11223344);
 * ```
 */
export const swap8IfBE: (n: number) => number = isLE
  ? (n: number) => n
  : (n: number) => byteSwap(n);

/**
 * Byte-swaps every word of a Uint32Array in place.
 * @param arr - array to mutate
 * @returns The same array after mutation.
 * @example
 * Reverse the byte order of every word in place.
 * ```ts
 * byteSwap32(new Uint32Array([0x11223344]));
 * ```
 */
export function byteSwap32(arr: Uint32Array): Uint32Array {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}

/**
 * Conditionally byte-swaps a Uint32Array on big-endian platforms.
 * @param u - array to normalize for host endianness
 * @returns Original or byte-swapped array depending on platform endianness.
 * @example
 * Normalize a word array for host endianness.
 * ```ts
 * swap32IfBE(new Uint32Array([0x11223344]));
 * ```
 */
export const swap32IfBE: (u: Uint32Array) => Uint32Array = isLE
  ? (u: Uint32Array) => u
  : byteSwap32;

// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin: boolean = /* @__PURE__ */ (() =>
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();

// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);

/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @param bytes - bytes to encode
 * @returns Lowercase hexadecimal string.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Convert bytes to lowercase hexadecimal.
 * ```ts
 * bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])); // 'cafe0123'
 * ```
 */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes);
  // @ts-ignore
  if (hasHexBuiltin) return bytes.toHex();
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
  return;
}

/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @param hex - hexadecimal string to decode
 * @returns Decoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Decode lowercase hexadecimal into bytes.
 * ```ts
 * hexToBytes('cafe0123'); // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 * ```
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  if (hasHexBuiltin) {
    try {
      return (Uint8Array as any).fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError) throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new RangeError('hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError(
        'hex string expected, got non-hex character "' + char + '" at index ' + hi
      );
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}

/**
 * There is no setImmediate in browser and setTimeout is slow.
 * Call of async fn will return Promise, which will be fullfiled only on
 * next scheduler queue processing step and this is exactly what we need.
 * @example
 * Yield to the next scheduler tick.
 * ```ts
 * await nextTick();
 * ```
 */
export const nextTick = async (): Promise<void> => {};

/**
 * Returns control to the event loop every `tick` milliseconds to avoid blocking.
 * @param iters - number of loop iterations to run
 * @param tick - maximum time slice in milliseconds
 * @param cb - callback executed on each iteration
 * @example
 * Run a loop that periodically yields back to the event loop.
 * ```ts
 * await asyncLoop(2, 0, () => {});
 * ```
 */
export async function asyncLoop(
  iters: number,
  tick: number,
  cb: (i: number) => void
): Promise<void> {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await nextTick();
    ts += diff;
  }
}

// Global symbols, but ts doesn't see them: https://github.com/microsoft/TypeScript/issues/31535
declare const TextEncoder: any;

/**
 * Converts string to bytes using UTF8 encoding.
 * Built-in doesn't validate input to be string: we do the check.
 * @param str - string to encode
 * @returns UTF-8 encoded bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Encode a string as UTF-8 bytes.
 * ```ts
 * utf8ToBytes('abc'); // Uint8Array.from([97, 98, 99])
 * ```
 */
export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new TypeError('string expected');
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}

/** KDFs can accept string or Uint8Array for user convenience. */
export type KDFInput = string | Uint8Array;

/**
 * Helper for KDFs: consumes uint8array or string.
 * When string is passed, does utf8 decoding, using TextDecoder.
 * @param data - user-provided KDF input
 * @param errorTitle - label included in thrown errors
 * @returns Byte representation of the input.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Normalize KDF input to bytes.
 * ```ts
 * kdfInputToBytes('password');
 * ```
 */
export function kdfInputToBytes(data: KDFInput, errorTitle = ''): Uint8Array {
  if (typeof data === 'string') return utf8ToBytes(data);
  return abytes(data, undefined, errorTitle);
}

/**
 * Copies several Uint8Arrays into one.
 * @param arrays - arrays to concatenate
 * @returns Concatenated byte array.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Concatenate multiple byte arrays.
 * ```ts
 * concatBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

type EmptyObj = {};
/**
 * Merges default options and passed options.
 * @param defaults - base option object
 * @param opts - user overrides
 * @returns Merged option object.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Merge user overrides onto default options.
 * ```ts
 * checkOpts({ dkLen: 32 }, { asyncTick: 10 });
 * ```
 */
export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts?: T2
): T1 & T2 {
  if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
    throw new TypeError('options must be object or undefined');
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

/** Common interface for all hash instances. */
export interface Hash<T> {
  /** Bytes processed per compression block. */
  blockLen: number;
  /** Bytes produced by `digest()`. */
  outputLen: number;
  /**
   * Absorbs more message bytes into the running hash state.
   * @param buf - message chunk to absorb
   * @returns The same hash instance for chaining.
   */
  update(buf: Uint8Array): this;
  /**
   * Finalizes the hash into a caller-provided buffer.
   * @param buf - destination buffer
   * @returns Nothing. Implementations write into `buf` in place.
   */
  digestInto(buf: Uint8Array): void;
  /**
   * Finalizes the hash and returns a freshly allocated digest.
   * @returns Digest bytes.
   */
  digest(): Uint8Array;
  /** Wipes internal state and makes the instance unusable. */
  destroy(): void;
  /**
   * Copies the current hash state into an existing or new instance.
   * @param to - Optional destination instance to reuse.
   * @returns Cloned hash state.
   */
  _cloneInto(to?: T): T;
  /**
   * Creates an independent copy of the current hash state.
   * @returns Cloned hash instance.
   */
  clone(): T;
}

/** Pseudorandom generator interface. */
export interface PRG {
  /**
   * Mixes more entropy into the generator state.
   * @param seed - fresh entropy bytes
   * @returns Nothing. Implementations update internal state in place.
   */
  addEntropy(seed: Uint8Array): void;
  /**
   * Generates pseudorandom output bytes.
   * @param length - number of bytes to generate
   * @returns Generated pseudorandom bytes.
   */
  randomBytes(length: number): Uint8Array;
  /** Wipes generator state and makes the instance unusable. */
  clean(): void;
}

/**
 * XOF: streaming API to read digest in chunks.
 * Same as 'squeeze' in keccak/k12 and 'seek' in blake3, but more generic name.
 * When hash used in XOF mode it is up to user to call '.destroy' afterwards, since we cannot
 * destroy state, next call can require more bytes.
 */
export type HashXOF<T extends Hash<T>> = Hash<T> & {
  /**
   * Reads more bytes from the XOF stream.
   * @param bytes - number of bytes to read
   * @returns Requested digest bytes.
   */
  xof(bytes: number): Uint8Array;
  /**
   * Reads more bytes from the XOF stream into a caller-provided buffer.
   * @param buf - destination buffer
   * @returns The same buffer after it has been filled.
   */
  xofInto(buf: Uint8Array): Uint8Array;
};

/** Hash constructor or factory type. */
export type HasherCons<T, Opts = undefined> = Opts extends undefined ? () => T : (opts?: Opts) => T;
/** Optional hash metadata. */
export type HashInfo = {
  /** DER-encoded object identifier bytes for the hash algorithm. */
  oid?: Uint8Array;
};
/** Callable hash function type. */
export type CHash<T extends Hash<T> = Hash<any>, Opts = undefined> = {
  /** Digest size in bytes. */
  outputLen: number;
  /** Input block size in bytes. */
  blockLen: number;
} & HashInfo &
  (Opts extends undefined
    ? {
        (msg: Uint8Array): Uint8Array;
        create(): T;
      }
    : {
        (msg: Uint8Array, opts?: Opts): Uint8Array;
        create(opts?: Opts): T;
      });
/** Callable extendable-output hash function type. */
export type CHashXOF<T extends HashXOF<T> = HashXOF<any>, Opts = undefined> = CHash<T, Opts>;

/**
 * Creates a callable hash function from a stateful class constructor.
 * @param hashCons - hash constructor or factory
 * @param info - optional metadata such as DER OID
 * @returns Frozen callable hash wrapper with `.create()`.
 * @example
 * Wrap a stateful hash constructor into a callable helper.
 * ```ts
 * import { createHasher } from '@noble/hashes/utils.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const wrapped = createHasher(sha256.create, { oid: sha256.oid });
 * wrapped(new Uint8Array([1]));
 * ```
 */
export function createHasher<T extends Hash<T>, Opts = undefined>(
  hashCons: HasherCons<T, Opts>,
  info: HashInfo = {}
): CHash<T, Opts> {
  const hashC: any = (msg: Uint8Array, opts?: Opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(undefined);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts?: Opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}

/**
 * Cryptographically secure PRNG backed by `crypto.getRandomValues`.
 * @param bytesLength - number of random bytes to generate
 * @returns Random bytes.
 * @throws If the current runtime does not provide `crypto.getRandomValues`. {@link Error}
 * @example
 * Generate a fresh random key or nonce.
 * ```ts
 * const key = randomBytes(16);
 * ```
 */
export function randomBytes(bytesLength = 32): Uint8Array {
  const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;
  if (typeof cr?.getRandomValues !== 'function')
    throw new Error('crypto.getRandomValues must be defined');
  return cr.getRandomValues(new Uint8Array(bytesLength));
}

/**
 * Creates OID metadata for NIST hashes with prefix `06 09 60 86 48 01 65 03 04 02`.
 * @param suffix - final OID byte for the selected hash
 * @returns Object containing the DER-encoded OID.
 * @example
 * Build OID metadata for a NIST hash.
 * ```ts
 * oidNist(0x01);
 * ```
 */
export const oidNist = (suffix: number): Required<HashInfo> => ({
  oid: Uint8Array.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix]),
});
