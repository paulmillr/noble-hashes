// prettier-ignore
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
  Uint16Array | Int16Array | Uint32Array | Int32Array;

// Cast array to different type
export const u8 = (arr: TypedArray) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
export const u32 = (arr: TypedArray) =>
  new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));

// Cast array to view
export const createView = (arr: TypedArray) =>
  new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

// The rotate right (circular right shift) operation for uint32
export const rotr = (word: number, shift: number) => (word << (32 - shift)) | (word >>> shift);

export const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianess.
// So, just to be sure not to corrupt anything.
if (!isLE) throw new Error('Non little-endian hardware is not supported');

export function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += uint8a[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// Currently avoid insertion of polyfills with packers (browserify/webpack/etc)
// But setTimeout is pretty slow, maybe worth to investigate howto do minimal polyfill here
export const nextTick: () => Promise<unknown> = (() => {
  const nodeRequire =
    typeof module !== 'undefined' &&
    typeof module.require === 'function' &&
    module.require.bind(module);
  try {
    if (nodeRequire) {
      const { setImmediate } = nodeRequire('timers');
      return () => new Promise((resolve) => setImmediate(resolve));
    }
  } catch (e) {}
  return () => new Promise((resolve) => setTimeout(resolve, 0));
})();

// Returns control to thread each 'tick' ms to avoid blocking
export async function asyncLoop(iters: number, tick: number, cb: (i: number) => void) {
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

export type Input = Uint8Array | string;
export function toBytes(data: Input) {
  if (typeof data === 'string') data = new TextEncoder().encode(data);
  if (!(data instanceof Uint8Array))
    throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
  return data;
}

export function assertNumber(n: number) {
  if (!Number.isSafeInteger(n)) throw new Error(`Wrong integer: ${n}`);
}

export function assertBool(b: boolean) {
  if (typeof b !== 'boolean') {
    throw new Error(`Expected boolean, not ${b}`);
  }
}

export function assertHash(hash: CHash) {
  if (typeof hash !== 'function' || typeof hash.init !== 'function')
    throw new Error('Hash should be wrapped by utils.wrapConstructor');
  assertNumber(hash.outputLen);
  assertNumber(hash.blockLen);
}

// For runtime check if class implements interface
export abstract class Hash {
  abstract blockLen: number; // Bytes per block
  abstract outputLen: number; // Bytes in output
  abstract update(buf: Input): this;
  abstract digest(): Uint8Array;
  abstract clean(): void;
  // Internal methods (unsafe)
  abstract _writeDigest(buf: Uint8Array): void;
  // abstract _cloneInto(obj?: this): this; // Obj is destination. If empty new one will be created. Overwrites buffer which used for digest
}

export type HashOpts = {
  cleanup: boolean; // Force hash to clean internal sturctures on finish
};
export type PartialOpts = Partial<HashOpts>;
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj: any) =>
  Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;

export function checkOpts<T1 extends PartialOpts, T2 extends PartialOpts>(
  def: T1,
  _opts?: T2
): T1 & T2 {
  if (_opts !== undefined && (typeof _opts !== 'object' || !isPlainObject(_opts)))
    throw new TypeError('Options should be object or undefined');
  const opts = Object.assign({ cleanup: false }, def, _opts);
  assertBool(opts.cleanup);
  return opts as T1 & T2;
}

export interface Cloneable extends Hash {
  blockLen: number;
  view?: DataView;
  buffer?: Uint8Array;
  state?: Uint8Array;
  done: boolean;
  length: number;
  opts: PartialOpts;
  _get(): number[];
  _set(...values: number[]): void;
  _cloneOpts?(): any;
  pos?: any;
}

export function cloneHashInto(first: Cloneable, second?: Cloneable): Cloneable {
  const opts = typeof first._cloneOpts === 'function' ? first._cloneOpts() : first.opts;
  // TODO
  // @ts-ignore
  if (second == null) second = new first.constructor(opts) as Cloneable;
  const { blockLen, buffer, view, done, length, state, pos } = first;
  second.done = done;
  if (buffer && second.buffer) {
    // SHA2, Blake2
    second._set(...first._get());
    second.length = length;
    // Very ugly hack to optimize on sha2* (it has view)
    if (!view || length % blockLen) second.buffer.set(buffer);
  } else if (state && second.state) {
    // SHA3
    second.state.set(state);
    second.pos = pos;
  }
  return second;
}

export type CHash = ReturnType<typeof wrapConstructor>;

export function wrapConstructor<T extends Partial<HashOpts>>(_hashC: (opts: T) => Hash) {
  const hashC = (msg: Input, opts?: T): Uint8Array =>
    _hashC(checkOpts({}, opts as T))
      .update(toBytes(msg))
      .digest();
  const tmp = _hashC({} as T);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.init = (opts: T) => _hashC(checkOpts({}, opts as T));
  return hashC;
}

const crypto: { node?: any; web?: Crypto } = (() => {
  const webCrypto = typeof self === 'object' && 'crypto' in self ? self.crypto : undefined;
  // Silence webpack warnings
  const nodeRequire =
    typeof module !== 'undefined' &&
    typeof module.require === 'function' &&
    module.require.bind(module);
  return {
    node: nodeRequire && !webCrypto ? nodeRequire('crypto') : undefined,
    web: webCrypto,
  };
})();

export function randomBytes(bytesLength = 32): Uint8Array {
  if (crypto.web) {
    return crypto.web.getRandomValues(new Uint8Array(bytesLength));
  } else if (crypto.node) {
    return new Uint8Array(crypto.node.randomBytes(bytesLength).buffer);
  } else {
    throw new Error("The environment doesn't have randomBytes function");
  }
}
