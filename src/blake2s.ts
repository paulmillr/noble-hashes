/**
 * Blake2s hash function. Focuses on 8-bit to 32-bit platforms. blake2b for 64-bit, but in JS it is slower.
 * @module
 */
import { G1s as G1s_n, G2s as G2s_n } from './_blake.ts';
import { SHA256_IV } from './_md.ts';
import { BLAKE2s as B2S, blake2s as b2s, compress as compress_n } from './blake2.ts';
/** @deprecated Use import from `noble/hashes/blake2` module */

/** Blake2s iv */
export const B2S_IV: Uint32Array = SHA256_IV;
export const G1s: typeof G1s_n = G1s_n;
export const G2s: typeof G2s_n = G2s_n;
export const compress: typeof compress_n = compress_n;
export const BLAKE2s: typeof B2S = B2S;
export const blake2s: typeof b2s = b2s;
