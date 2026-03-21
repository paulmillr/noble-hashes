import { should } from '@paulmillr/jsbt/test.js';
// import './blake.test.js';
// Generic hash tests
import { init } from './hashes.test.ts';
import { PLATFORMS } from './platform.ts';
import { executeKDFTests } from './generator.ts';
import { test as async } from './async.test.ts';
// Specific vectors for hash functions if available
import { test as blake } from './blake.test.ts';
import { test as keccak } from './keccak.test.ts';
// Tests generated from rust
import { test as hmac } from './hmac.test.ts';
import { test as kdf } from './kdf.test.ts';
// import './argon2.test.js';
import { avcpTests } from './acvp.test.ts';
import { test as clone } from './clone.test.ts';
import './eskdf.test.ts';
import { test as info } from './info.test.ts';
import './u64.test.ts';
import './utils.test.ts';
// import './errors.test.ts';
const variant = 'noble';
const platform = PLATFORMS[variant] || Object.values(PLATFORMS)[0];
init(variant, platform);
avcpTests(false, variant, platform);
async(variant, platform);
blake(variant, platform);
keccak(variant, platform);
hmac(variant, platform);
kdf(variant, platform);
executeKDFTests(variant, platform, true);
clone(variant, platform);
info(variant, platform);
should.runWhen(import.meta.url);
