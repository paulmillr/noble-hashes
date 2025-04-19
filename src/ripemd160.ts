/**
 * RIPEMD-160 legacy hash function.
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 * @module
 */
import { RIPEMD160 as RIPEMD160n, ripemd160 as ripemd160n } from './legacy.ts';
/** @deprecated Use import from `noble/hashes/legacy` module */
/** Ripemd160 */
export const RIPEMD160: typeof RIPEMD160n = RIPEMD160n;
export const ripemd160: typeof ripemd160n = ripemd160n;
