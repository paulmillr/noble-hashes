const { should } = require('micro-should');
// Generic hash tests
require('./hashes.test.js').init();
// Specific vectors for hash functions if available
require('./keccak.test.js');
require('./blake.test.js');
// Tests generated from rust
require('./hmac.test.js');
require('./kdf.test.js');
require('./argon2.test.js');
require('./eskdf.test.js');
require('./async.test.js');
require('./clone.test.js');
require('./u64.test.js');
require('./utils.test.js');

should.run();
