const fs = require('fs');
const zlib = require('zlib');
const utf8ToBytes = (str) => new TextEncoder().encode(str);
const hexToBytes = (str) => Uint8Array.from(Buffer.from(str, 'hex'));
const truncate = (buf, length) => (length ? buf.slice(0, length) : buf);

const repeat = (buf, len) => {
  // too slow: Uint8Array.from({ length: len * buf.length }, (_, i) => buf[i % buf.length]);
  let out = new Uint8Array(len * buf.length);
  for (let i = 0; i < len; i++) out.set(buf, i * buf.length);
  return out;
};

function concatBytes(...arrays) {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
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
  new Uint8ClampedArray([1, 2, 3]),
  new Int16Array([1, 2, 3]),
  new ArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  () => {},
  async () => {},
  class Test {},
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
const TYPE_TEST_NOT_INT = [-0.0, 0, 1];

const TYPE_TEST = {
  int: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_BOOL).concat(TYPE_TEST_NOT_BYTES),
  bytes: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT).concat(TYPE_TEST_NOT_BOOL),
  boolean: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT).concat(TYPE_TEST_NOT_BYTES),
  opts: TYPE_TEST_OPT,
  hash: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_BOOL)
    .concat(TYPE_TEST_NOT_INT)
    .concat(TYPE_TEST_NOT_BYTES)
    .concat(TYPE_TEST_OPT),
};

function median(list) {
  const values = list.slice().sort((a, b) => a - b);
  const half = (values.length / 2) | 0;
  return values.length % 2 ? values[half] : (values[half - 1] + values[half]) / 2.0;
}

function stats(list) {
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

const times = (byte, n) => new Uint8Array(n).fill(byte);
const pattern = (toByte, len) => Uint8Array.from({ length: len }, (i, j) => j % (toByte + 1));

const jsonGZ = (path) => JSON.parse(zlib.gunzipSync(fs.readFileSync(`${__dirname}/${path}`)));

module.exports = {
  utf8ToBytes,
  hexToBytes,
  truncate,
  repeat,
  concatBytes,
  TYPE_TEST,
  SPACE: {
    str: ' ',
    bytes: new Uint8Array([0x20]),
  },
  EMPTY: {
    str: '',
    bytes: new Uint8Array([]),
  },
  stats,
  times,
  pattern,
  jsonGZ,
};
