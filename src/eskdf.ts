import { hkdf } from './hkdf.js';
import { sha256 } from './sha256.js';
import { pbkdf2 as _pbkdf2 } from './pbkdf2.js';
import { scrypt as _scrypt } from './scrypt.js';
import { assertBytes, createView, toBytes } from './utils.js';

// A tiny KDF for various applications like AES key-gen

const SCRYPT_FACTOR = 2 ** 19;
const PBKDF2_FACTOR = 2 ** 17;
const PROTOCOLS_ALLOWING_STR = ['ssh', 'tor', 'file'];

function strHasLength(str: string, min: number, max: number): boolean {
  return typeof str === 'string' && str.length >= min && str.length <= max;
}

// Scrypt KDF
export function scrypt(password: string, salt: string): Uint8Array {
  return _scrypt(password, salt, { N: SCRYPT_FACTOR, r: 8, p: 1, dkLen: 32 });
}

// PBKDF2-HMAC-SHA256
export function pbkdf2(password: string, salt: string): Uint8Array {
  return _pbkdf2(sha256, password, salt, { c: PBKDF2_FACTOR, dkLen: 32 });
}

// Combines two 32-byte byte arrays
function xor32(a: Uint8Array, b: Uint8Array): Uint8Array {
  assertBytes(a, 32);
  assertBytes(b, 32);
  const arr = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}

/**
 * Derives main seed. Takes a lot of time.
 * Prefer `eskdf` method instead.
 */
export function deriveMainSeed(username: string, password: string): Uint8Array {
  if (!strHasLength(username, 8, 255)) throw new Error('invalid username');
  if (!strHasLength(password, 8, 255)) throw new Error('invalid password');
  const scr = scrypt(password + '\u{1}', username + '\u{1}');
  const pbk = pbkdf2(password + '\u{2}', username + '\u{2}');
  const res = xor32(scr, pbk);
  scr.fill(0);
  pbk.fill(0);
  return res;
}

/**
 * Derives a child key. Prefer `eskdf` method instead.
 * @example deriveChildKey(seed, 'aes', 0)
 */
export function deriveChildKey(
  seed: Uint8Array,
  protocol: string,
  accountId: number | string = 0,
  keyLength = 32
): Uint8Array {
  assertBytes(seed, 32);
  // Note that length here also repeats two lines below
  // We do an additional length check here to reduce the scope of DoS attacks
  if (!(strHasLength(protocol, 3, 15) && /^[a-z0-9]{3,15}$/.test(protocol))) {
    throw new Error('invalid protocol');
  }
  const allowsStr = PROTOCOLS_ALLOWING_STR.includes(protocol);
  let salt: Uint8Array; // Extract salt. Default is undefined.
  if (typeof accountId === 'string') {
    if (!allowsStr) throw new Error('accountId must be a number');
    if (!strHasLength(accountId, 1, 255)) throw new Error('accountId must be valid string');
    salt = toBytes(accountId);
  } else if (Number.isSafeInteger(accountId)) {
    if (accountId < 0 || accountId > 2 ** 32 - 1) throw new Error('invalid accountId');
    // Convert to Big Endian Uint32
    salt = new Uint8Array(4);
    createView(salt).setUint32(0, accountId, false);
  } else {
    throw new Error(`accountId must be a number${allowsStr ? ' or string' : ''}`);
  }
  const info = toBytes(protocol);
  return hkdf(sha256, seed, salt, info, keyLength);
}

// We are not using classes because constructor cannot be async
type ESKDF = Promise<
  Readonly<{
  /**
   * Derives a child key. Child key will not be associated with any
   * other child key because of properties of underlying KDF.
   * @param protocol - 3-15 character protocol name
   * @param accountId - numeric identifier of account
   * @param keyLength - (default: 32) key length
   * @example deriveChildKey('aes', 0)
   */
    deriveChildKey: (protocol: string, accountId: number | string) => Uint8Array;
    /**
     * Deletes the main seed from eskdf instance
     */
    expire: () => void;
    /**
     * Account fingerprint
     */
    fingerprint: string;
  }>
>;

/**
 * ESKDF
 * @param username - username, email, or identifier, min: 8 characters, should have enough entropy
 * @param password - password, min: 8 characters, should have enough entropy
 * @example
 * const kdf = await eskdf('example-university', 'beginning-new-example');
 * const key = kdf.deriveChildKey('aes', 0);
 * console.log(kdf.fingerprint);
 * kdf.expire();
 */
export async function eskdf(username: string, password: string): ESKDF {
  // We are using closure + object instead of class because
  // we want to make `seed` non-accessible for any external function.
  let seed: Uint8Array | undefined = await deriveMainSeed(username, password);
  function derive(protocol: string, accountId: number | string = 0): Uint8Array {
    assertBytes(seed!, 32);
    return deriveChildKey(seed!, protocol, accountId);
  }
  function expire() {
    seed?.fill(1);
    seed = undefined;
  }
  // prettier-ignore
  const fingerprint = Array.from(derive('fingerprint', 0))
    .slice(0, 6)
    .map((char) => char.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
  return Object.freeze({ deriveChildKey: derive, expire, fingerprint });
}
