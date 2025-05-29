import { should } from 'micro-should';
// import './blake.test.js';
// Generic hash tests
import { init } from './hashes.test.ts';
// Specific vectors for hash functions if available
import './blake.test.ts';
import './keccak.test.ts';
// Tests generated from rust
import './hmac.test.ts';
import './kdf.test.ts';
// import './argon2.test.js';
import './async.test.ts';
import './clone.test.ts';
import './eskdf.test.ts';
import './u64.test.ts';
import './utils.test.ts';

init();
should.runWhen(import.meta.url);
