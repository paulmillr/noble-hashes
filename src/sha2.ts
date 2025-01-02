/**
 * SHA2. A.k.a. sha256, sha512, sha512_256, etc.
 * @module
 */
// Usually you either use sha256, or sha512. We re-export them as sha2 for naming consistency.
export { sha256, sha224 } from './sha256.js';
export { sha512, sha512_224, sha512_256, sha384 } from './sha512.js';
