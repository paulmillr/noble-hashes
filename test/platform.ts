import {
  argon2d,
  argon2dAsync,
  argon2i,
  argon2iAsync,
  argon2id,
  argon2idAsync,
} from '../src/argon2.ts';
import * as blake1 from '../src/blake1.ts';
import * as blake2 from '../src/blake2.ts';
import { blake3 } from '../src/blake3.ts';
import { expand, extract, hkdf } from '../src/hkdf.ts';
import { hmac } from '../src/hmac.ts';
import * as legacy from '../src/legacy.ts';
import { pbkdf2, pbkdf2Async } from '../src/pbkdf2.ts';
import { scrypt, scryptAsync } from '../src/scrypt.ts';
import * as sha2 from '../src/sha2.ts';
import * as addons from '../src/sha3-addons.ts';
import * as sha3 from '../src/sha3.ts';
import * as web from '../src/webcrypto.ts';

const SLOT = '__NOBLE_TEST_PLATFORMS__';
const shared = (globalThis as Record<string, any>)[SLOT];

const local = {
  ...blake1,
  ...blake2,
  blake3,
  hmac,
  ...legacy,
  ...sha2,
  ...addons,
  ...sha3,
  hkdf,
  extract,
  expand,
  pbkdf2,
  pbkdf2Async,
  scrypt,
  scryptAsync,
  argon2d,
  argon2dAsync,
  argon2i,
  argon2iAsync,
  argon2id,
  argon2idAsync,
  web,
};
export const PLATFORMS = shared?.hashes || { noble: local };
