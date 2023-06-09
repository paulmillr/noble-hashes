import { isLE } from './utils.js';

// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
if (!isLE) throw new Error('Non little-endian hardware is not supported');
