/** Derive and check the fixed PBKDF2-HMAC-SHA512 feedback-block geometry. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const source = readFileSync(resolve(root, 'src/sha2.ts'), 'utf8');

// SHA-256 has no numeric feedback accelerator (PBKDF2-HMAC-SHA256 uses the generic engine), so
// only the SHA-512 geometry is hardcoded in src/sha2.ts.
const geometry = [{ name: 'SHA-512', blockLen: 128, outputLen: 64, padWord: 8, bitLength: 1536 }];

for (const { name, blockLen, outputLen, padWord, bitLength } of geometry) {
  const derived = (blockLen + outputLen) * 8;
  if (derived !== bitLength)
    throw new Error(`${name}: bad bit length ${bitLength}, want ${derived}`);
  const derivedPadWord = outputLen / 8;
  if (derivedPadWord !== padWord)
    throw new Error(`${name}: bad padding word ${padWord}, want ${derivedPadWord}`);
  if (!source.includes(`Wh[${padWord}] = 0x80000000;`))
    throw new Error(`${name}: source padding word drift`);
  if (!source.includes(`Wl[15] = ${bitLength};`))
    throw new Error(`${name}: source bit length drift`);
}

// The feedback input is always exactly one digest. The geometry must therefore leave enough
// room for 0x80 plus the standard SHA-512 length field in one block.
if (64 + 1 + 16 > 128) throw new Error('feedback block needs two compressions');

console.log('PBKDF2-HMAC-SHA512 fixed geometry: OK');
