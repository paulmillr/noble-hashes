import { should } from 'micro-should';
// import './blake.test.js';
// Generic hash tests
import { init } from './hashes.test.js';
// Specific vectors for hash functions if available
import './keccak.test.js';
import './blake.test.js';
// Tests generated from rust
import './hmac.test.js';
import './kdf.test.js';
// import './argon2.test.js';
import './eskdf.test.js';
import './async.test.js';
import './clone.test.js';
import './u64.test.js';
import './utils.test.js';

init();
should.opts.STOP_AT_ERROR = false;
should.runWhen(import.meta.url);
