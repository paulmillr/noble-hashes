import { scrypt } from '../../scrypt.js';

let pass = 'abcabcabc';
let salt = 'abcababc';
for (let i = 16; i < 26; i++) {
  const N = Math.pow(2, i);
  const start = Date.now();
  const key = scrypt(pass, salt, { N: N, r: 8, p: 1, dkLen: 32, maxmem: 2 ** 40 });
  const diff = Date.now() - start;
  const sec = (diff / 1000).toFixed(1) + 's';
  const ram = process.memoryUsage().arrayBuffers / 1024 ** 2;
  console.log(`N=2^${i}`, sec, ram.toFixed(0) + 'MB');
}
