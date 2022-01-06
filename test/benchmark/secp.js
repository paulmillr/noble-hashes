const bench = require('micro-bmark');
const { run, mark } = bench; // or bench.mark
const crypto = require('crypto');
const { sha256 } = require('../../sha256');
const { hmac } = require('../../hmac');
const { concatBytes } = require('../utils');

const hmac256 = (key, ...msgs) => {
  const h = crypto.createHmac('sha256', key);
  msgs.forEach((msg) => h.update(msg));
  return Uint8Array.from(h.digest());
};

const hmac256noble = (key, ...msgs) => {
  const h = hmac.create(sha256, key);
  msgs.forEach((msg) => h.update(msg));
  return h.digest();
};

const hmac256nobleConcat = (key, ...msgs) => {
  return hmac(sha256, key, concatBytes(...msgs));
};

const CASES = [
  { key: new Uint8Array(32).fill(1), msgs: [new Uint8Array(32).fill(2)] },
  // [ 32, 1, 32, 32 ]
  {
    key: new Uint8Array(32).fill(1),
    msgs: [
      new Uint8Array(32).fill(2),
      new Uint8Array([3]),
      new Uint8Array(32).fill(4),
      new Uint8Array(32).fill(5),
    ],
  },
];

const FNS = [hmac256, hmac256noble];
const samples = 20000;

run(async () => {
  for (const c of CASES) {
    console.log(`==== ${c.key.length} (${c.msgs.map((i) => i.length)}) ====`);
    for (const fn of FNS) await mark(`${fn.name}`, samples, () => fn(c.key, ...c.msgs));
  }
});
