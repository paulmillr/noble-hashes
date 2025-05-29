import { readFileSync } from 'node:fs';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

export const _dirname = dirname(fileURLToPath(import.meta.url));

function readRel(path, opts) {
  return readFileSync(joinPath(_dirname, path), opts);
}

export function json(path) {
  try {
    // Node.js
    return JSON.parse(readRel(path, { encoding: 'utf-8' }));
  } catch (error) {
    // Bundler
    const file = path.replace(/^\.\//, '').replace(/\.json$/, '');
    if (path !== './' + file + '.json') throw new Error('Can not load non-json file');
    // return require('./' + file + '.json'); // in this form so that bundler can glob this
  }
}

export function jsonGZ(path) {
  return JSON.parse(gunzipSync(readRel(path)).toString('utf8'));
}

function median(list) {
  const values = list.slice().sort((a, b) => a - b);
  const half = (values.length / 2) | 0;
  return values.length % 2 ? values[half] : (values[half - 1] + values[half]) / 2.0;
}
export function stats(list) {
  let [min, max, cnt, sum, absSum] = [+Infinity, -Infinity, 0, 0, 0];
  for (let value of list) {
    const num = Number(value);
    min = Math.min(min, num);
    max = Math.max(max, num);
    cnt++;
    sum += num;
    absSum += Math.abs(num);
  }
  const sumDiffPercent = (absSum / sum) * 100;
  const difference = [];
  for (let i = 1; i < list.length; i++) difference.push(list[i] - list[i - 1]);
  return {
    min,
    max,
    avg: sum / cnt,
    sum,
    median: median(list),
    absSum,
    cnt,
    sumDiffPercent,
    difference,
  };
}

// Everything except undefined, string, Uint8Array
const TYPE_TEST_BASE = [
  null,
  [1, 2, 3],
  { a: 1, b: 2, c: 3 },
  NaN,
  0.1234,
  1.0000000000001,
  10e9999,
  new Uint32Array([1, 2, 3]),
  100n,
  new Set([1, 2, 3]),
  new Map([['aa', 'bb']]),
  new Uint8ClampedArray([1, 2, 3]),
  new Int16Array([1, 2, 3]),
  new Float32Array([1]),
  new BigInt64Array([1n, 2n, 3n]),
  new ArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  { constructor: { name: 'Uint8Array' }, length: '1e30' },
  () => {},
  async () => {},
  class Test {},
  Symbol.for('a'),
  new Proxy(new Uint8Array(), {
    get(t, p, r) {
      if (p === 'isProxy') return true;
      return Reflect.get(t, p, r);
    },
  }),
];

const TYPE_TEST_OPT = [
  '',
  new Uint8Array(),
  new (class Test {})(),
  class Test {},
  () => {},
  0,
  0.1234,
  NaN,
  null,
];

const TYPE_TEST_NOT_BOOL = [false, true];
const TYPE_TEST_NOT_BYTES = ['', 'test', '1', new Uint8Array([]), new Uint8Array([1, 2, 3])];
const TYPE_TEST_NOT_HEX = [
  '0xbe',
  ' 1 2 3 4 5',
  '010203040x',
  'abcdefgh',
  '1 2 3 4 5 ',
  'bee',
  new String('1234'),
];
const TYPE_TEST_NOT_INT = [-0.0, 0, 1];

export const TYPE_TEST = {
  int: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_BOOL, TYPE_TEST_NOT_BYTES),
  bytes: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BOOL),
  boolean: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BYTES),
  hex: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BOOL, TYPE_TEST_NOT_HEX),
  opts: TYPE_TEST_OPT,
  hash: TYPE_TEST_BASE.concat(
    TYPE_TEST_NOT_BOOL,
    TYPE_TEST_NOT_INT,
    TYPE_TEST_NOT_BYTES,
    TYPE_TEST_OPT
  ),
};

export const SPACE = {
  str: ' ',
  bytes: new Uint8Array([0x20]),
};
export const EMPTY = {
  str: '',
  bytes: new Uint8Array([]),
};

export const repeat = (buf, len) => {
  // too slow: Uint8Array.from({ length: len * buf.length }, (_, i) => buf[i % buf.length]);
  let out = new Uint8Array(len * buf.length);
  for (let i = 0; i < len; i++) out.set(buf, i * buf.length);
  return out;
};
export const truncate = (buf, length) => (length ? buf.slice(0, length) : buf);
export const times = (byte, n) => new Uint8Array(n).fill(byte);
export const pattern = (toByte, len) =>
  Uint8Array.from({ length: len }, (i, j) => j % (toByte + 1));

export const getTypeTests = () => [
  [0, '0'],
  [123, '123'],
  [123.456, '123.456'],
  [-5n, '-5n'],
  [1.0000000000001, '1.0000000000001'],
  [10e9999, '10e9999'],
  [Infinity, 'Infinity'],
  [-Infinity, '-Infinity'],
  [NaN, 'NaN'],
  [true, 'true'],
  [false, 'false'],
  [null, 'null'],
  [undefined, 'undefined'],
  ['', '""'],
  ['1', '"1"'],
  ['1 ', '"1 "'],
  [' 1', '" 1"'],
  ['0xbe', '"0xbe"'],
  ['keys', '"keys"'],
  [new String('1234'), 'String(1234)'],
  [new Uint8Array([]), 'ui8a([])'],
  [new Uint8Array([0]), 'ui8a([0])'],
  [new Uint8Array([1]), 'ui8a([1])'],
  // [new Uint8Array(32).fill(1), 'ui8a(32*[1])'],
  [new Uint8Array(4096).fill(1), 'ui8a(4096*[1])'],
  [new Uint16Array(32).fill(1), 'ui16a(32*[1])'],
  [new Uint32Array(32).fill(1), 'ui32a(32*[1])'],
  [new Float32Array(32), 'f32a(32*0)'],
  [new BigUint64Array(32).fill(1n), 'ui64a(32*[1])'],
  [new ArrayBuffer(100), 'arraybuf'],
  [new DataView(new ArrayBuffer(100)), 'dataview'],
  [{ constructor: { name: 'Uint8Array' }, length: '1e30' }, 'fake(ui8a)'],
  [Array(32).fill(1), 'array'],
  [new Set([1, 2, 3]), 'set'],
  [new Map([['aa', 'bb']]), 'map'],
  [() => {}, 'fn'],
  [async () => {}, 'fn async'],
  [class Test {}, 'class'],
  [Symbol.for('a'), 'symbol("a")'],
];

export function repr(item) {
  if (item && item.isProxy) return '[proxy]';
  if (typeof item === 'symbol') return item.toString();
  return `${item}`;
}
