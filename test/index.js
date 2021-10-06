const { should } = require('micro-should');

require('./hashes.test.js').init();
require('./hmac.test.js');
require('./kdf.test.js');
require('./async.test.js');
require('./u64.test.js');
require('./utils.test.js');

should.run();
