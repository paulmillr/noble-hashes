/** Derive and check the fixed PBKDF2-HMAC-SHA2 feedback-block geometry. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const source = readFileSync(resolve(root, 'src/sha2.ts'), 'utf8');

const geometry = [
  { name: 'SHA-256', blockLen: 64, outputLen: 32, padWord: 8, bitLength: 768 },
  { name: 'SHA-512', blockLen: 128, outputLen: 64, padWord: 8, bitLength: 1536 },
];

for (const { name, blockLen, outputLen, padWord, bitLength } of geometry) {
  const derived = (blockLen + outputLen) * 8;
  if (derived !== bitLength)
    throw new Error(`${name}: bad bit length ${bitLength}, want ${derived}`);
  const derivedPadWord = outputLen / (name === 'SHA-256' ? 4 : 8);
  if (derivedPadWord !== padWord)
    throw new Error(`${name}: bad padding word ${padWord}, want ${derivedPadWord}`);
  const pad = name === 'SHA-256' ? `W[${padWord}] = 0x80000000;` : `Wh[${padWord}] = 0x80000000;`;
  if (!source.includes(pad)) throw new Error(`${name}: source padding word drift`);
  const length = name === 'SHA-256' ? `W[15] = ${bitLength};` : `Wl[15] = ${bitLength};`;
  if (!source.includes(length)) throw new Error(`${name}: source bit length drift`);
}

// The feedback input is always exactly one digest. Both geometries must therefore leave enough
// room for 0x80 plus their standard SHA-2 length field in one block.
if (32 + 1 + 8 > 64 || 64 + 1 + 16 > 128) throw new Error('feedback block needs two compressions');

console.log('PBKDF2-HMAC-SHA2 fixed geometry: OK');
