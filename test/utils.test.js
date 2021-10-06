const assert = require('assert');
const { should } = require('micro-should');
const { optional, integer, gen } = require('./generator');

// Here goes test for tests...
should(`Test generator`, () => {
  assert.deepStrictEqual(
    gen({
      N: integer(0, 5),
      b: integer(2, 7),
      c: optional(integer(5, 10)),
    }),
    [
      { N: 0, b: 2, c: undefined },
      { N: 4, b: 3, c: 9 },
      { N: 3, b: 4, c: 8 },
      { N: 2, b: 5, c: 7 },
      { N: 1, b: 6, c: 6 },
      { N: 0, b: 2, c: 5 },
    ]
  );
});

if (require.main === module) should.run();
