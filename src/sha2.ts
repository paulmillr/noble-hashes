// Usually you either use sha256, or sha512. We re-export them as sha2 for naming consistency.
export { sha256, sha224, sha256 as sha2_256, sha224 as sha2_224 } from './sha256.js';
// prettier-ignore
export {
  sha512, sha512_224, sha512_256, sha384,
  sha512 as sha2_512, sha512_224 as sha2_512_224, sha512_256 as sha2_512_256, sha384 as sha2_384
} from './sha512.js';
