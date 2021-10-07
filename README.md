# noble-hashes ![Node CI](https://github.com/paulmillr/noble-hashes/workflows/Node%20CI/badge.svg) [![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

Fast, secure & minimal JS implementation of SHA2, SHA3, RIPEMD, BLAKE2, HMAC, HKDF, PBKDF2 & Scrypt.

Matches following specs:

- SHA2 aka SHA256 / SHA512 [(RFC 4634)](https://datatracker.ietf.org/doc/html/rfc4634)
- SHA3 & Keccak ([FIPS PUB 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), [Website](https://keccak.team/keccak.html))
- RIPEMD-160 ([RFC 2286](https://datatracker.ietf.org/doc/html/rfc2286), [Website](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html))
- BLAKE2b, BLAKE2s ([RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693), [Website](https://www.blake2.net))
- HMAC [(RFC 2104)](https://datatracker.ietf.org/doc/html/rfc2104)
- HKDF [(RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869)
- PBKDF2 [(RFC 2898)](https://datatracker.ietf.org/doc/html/rfc2898)
- Scrypt ([RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914), [Website](https://www.tarsnap.com/scrypt.html))

Overall size of all primitives is ~1800 TypeScript LOC, or 35KB minified (12KB gzipped).
You can select specific functions, SHA256-only would be ~400 LOC / 6.5KB minified (3KB gzipped).

The library's initial development was funded by [Ethereum Foundation](https://ethereum.org/).

### This library belongs to *noble* crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, small files
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-hashes/releases):

> npm install noble-hashes

The library does not have an entry point. It allows you to select specific primitives and drop everything else. If you only want to use sha256, just use the library with rollup or other bundlers. This is done to make your bundles tiny.

```js
const { sha256 } = require('noble-hashes/lib/sha256');
console.log(sha256(new Uint8Array([1, 2, 3])));
// Uint8Array(32) [3, 144,  88, 198, 242, 192, 203,  73, ...]

// you could also pass strings that will be UTF8-encoded to Uint8Array
console.log(sha256('abc'))); // == sha256(new TextEncoder().encode('abc'))

const { sha512, sha512_256 } = require('noble-hashes/lib/sha512');
// prettier-ignore
const {
  sha3_224, sha3_256, sha3_384, sha3_512,
  keccak_224, keccak_256, keccak_384, keccak_512
} = require('noble-hashes/lib/sha3');
const { ripemd160 } = require('noble-hashes/lib/ripemd160');
const { blake2b } = require('noble-hashes/lib/blake2b');
const { blake2s } = require('noble-hashes/lib/blake2s');
const { hmac } = require('noble-hashes/lib/hmac');
const { hkdf } = require('noble-hashes/lib/hkdf');
const { pbkdf2, pbkdf2Async } = require('noble-hashes/lib/pbkdf2');
const { scrypt, scryptAsync } = require('noble-hashes/lib/scrypt');

// small utility method that converts bytes to hex
const { toHex } = require('noble-hashes/lib/utils');
console.log(toHex(sha256('abc')));
// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## API

Any hash function:

1. Can be called directly, like `sha256(new Uint8Array([1, 3]))`,
or initialized as a class: `sha256.init().update(new Uint8Array([1, 3]).digest()`
2. Can receive either an `Uint8Array`, or a `string` that would be
automatically converted to `Uint8Array` via `new TextEncoder().encode(string)`.
  The output is always `Uint8Array`.
3. Can receive an option object as a second argument: `sha256('abc', {cleanup: true})`;
  or `sha256.init({cleanup: true}).update('abc').digest()`

##### SHA2 (sha256, sha512, sha512_256)

```typescript
import { sha256 } from 'noble-hashes/lib/sha256.js';
// function sha256(data: Uint8Array): Uint8Array;
const hash1 = sha256('abc');
const hash2 = sha256.init().update(Uint8Array.from([1, 2, 3])).digest();
```

```typescript
import { sha512 } from 'noble-hashes/lib/sha512.js';
const hash3 = sha512('abc');
const hash4 = sha512.init().update(Uint8Array.from([1, 2, 3])).digest();

// SHA512/256 variant
import { sha512_256 } from 'noble-hashes/lib/sha512.js';
const hash3_a = sha512_256('abc');
const hash4_a = sha512_256.init().update(Uint8Array.from([1, 2, 3])).digest();
```

To lean more about SHA512/256, check out [the paper](https://eprint.iacr.org/2010/548.pdf).

##### SHA3 (sha3_256, keccak_256, etc)

```typescript
import {
  sha3_224, sha3_256, sha3_384, sha3_512,
  keccak_224, keccak_256, keccak_384, keccak_512
} from 'noble-hashes/lib/sha3.js';
const hash5 = sha3_256('abc');
const hash6 = sha3_256.init().update(Uint8Array.from([1, 2, 3])).digest();
const hash7 = keccak_256('abc');
```

##### RIPEMD-160

```typescript
import { ripemd160 } from 'noble-hashes/lib/ripemd160.js';
// function ripemd160(data: Uint8Array): Uint8Array;
const hash8 = ripemd160('abc');
const hash9 = ripemd160().init().update(Uint8Array.from([1, 2, 3])).digest();
```

##### BLAKE2b, BLAKE2s

```typescript
import { blake2b } from 'noble-hashes/lib/blake2b.js';
import { blake2s } from 'noble-hashes/lib/blake2s.js';
const hash10 = blake2s('abc');
const b2params = {key: new Uint8Array([1]), personalization: t, salt: t, dkLen: 32};
const hash11 = blake2s('abc', b2params);
const hash12 = blake2s.init(b2params).update(Uint8Array.from([1, 2, 3])).digest();
```

##### HMAC

```typescript
import { hmac } from 'noble-hashes/lib/mac.js';
import { sha256 } from 'noble-hashes/lib/sha256.js';
const mac1 = hmac(sha256, 'key', 'message');
const mac2 = hmac.init(sha256, Uint8Array.from([1, 2, 3])).update(Uint8Array.from([4, 5, 6]).digest();
```

##### HKDF

```typescript
import { hkdf } from 'noble-hashes/lib/kdf.js';
import { sha256 } from 'noble-hashes/lib/sha256.js';
import { randomBytes } from 'noble-hashes/utils.js';
const inputKey = randomBytes(32);
const salt = randomBytes(32);
const info = 'abc';
const dkLen = 32;
const hk1 = hkdf(sha256, inputKey, salt, info, dkLen);

// == same as
import { hkdf_extract, hkdf_expand } from 'noble-hashes/lib/kdf.js';
import { sha256 } from 'noble-hashes/lib/sha256.js';
const prk = hkdf_extract(sha256, inputKey, salt)
const hk2 = hkdf_expand(sha256, prk, info, dkLen);
```

##### PBKDF2

```typescript
import { pbkdf2, pbkdf2Async } from 'noble-hashes/lib/kdf.js';
import { sha256 } from 'noble-hashes/lib/sha256.js';
const pbkey1 = pbkdf2(sha256, 'password', 'salt', { c: 32, dkLen: 32 });
const pbkey2 = await pbkdf2Async(sha256, 'password', 'salt', { c: 32, dkLen: 32 });
const pbkey3 = await pbkdf2Async(
  sha256, Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5, 6]), { c: 32, dkLen: 32 }
);
```

##### Scrypt

```typescript
import { scrypt, scryptAsync } from 'noble-hashes/lib/scrypt.js';
const scr1 = scrypt('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
const scr2 = await scryptAsync('password', 'salt', { N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
const scr3 = await scryptAsync(
  Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5, 6]),
  {
    N: 2 ** 22,
    r: 8,
    p: 1,
    dkLen: 32,
    onProgress(percentage) { console.log('progress', percentage); },
    maxmem: 2 ** 32 + (128 * 8 * 1) // N * r * p * 128 + (128*r*p)
  }
);
```

- `N, r, p` are work factors. To understand them, see [the blog post](https://blog.filippo.io/the-scrypt-parameters/).
- `dkLen` is the length of output bytes
- It is common to use N from `2**10` to `2**22` and `{r: 8, p: 1, dkLen: 32}`
- `onProgress` can be used with async version of the function to report progress to a user.

Memory usage of scrypt is calculated with the formula `N * r * p * 128 + (128 * r * p)`, which means
`{N: 2 ** 22, r: 8, p: 1}` will use 4GB + 1KB of memory. To prevent DoS, we limit scrypt to `1GB + 1KB` of RAM used,
which corresponds to `{N: 2 ** 20, r: 8, p: 1}`. If you want to use higher values, increase `maxmem` using the formula above.

*Note:* noble supports `2**22` (4GB RAM) which is the highest amount amongst JS libs. Many other implementations don't support it.
We cannot support `2**23`, because there is a limitation in JS engines that makes allocating
arrays bigger than 4GB impossible, but we're looking into other possible solutions.

##### utils

```typescript
import { bytesToHex as toHex, randomBytes } from 'noble-hashes/lib/scrypt.js';
console.log(toHex(randomBytes(32)));
```

- `bytesToHex` will convert `Uint8Array` to a hex string
- `randomBytes(bytes)` will produce cryptographically secure random `Uint8Array` of length `bytes`

## Security

Noble is production-ready.

The library will be audited by an independent security firm in the next few months.

A note on [timing attacks](https://en.wikipedia.org/wiki/Timing_attack): *JIT-compiler* and *Garbage Collector* make "constant time" extremely hard to achieve in a scripting language. Which means *any other JS library can't have constant-timeness*. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

We consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading rootkits with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmarks measured with Apple M1. Note that PBKDF2 and Scrypt are tested with extremely high
work factor. To run benchmarks, execute `npm run bench-install` and then `npm run bench`

```
SHA256 32 B x 954,198 ops/sec @ 1μs/op
SHA512 32 B x 440,722 ops/sec @ 2μs/op
SHA512-256 32 B x 423,549 ops/sec @ 2μs/op
SHA3 32 B x 184,331 ops/sec @ 5μs/op
BLAKE2s 32 B x 487,567 ops/sec @ 2μs/op
BLAKE2b 32 B x 282,965 ops/sec @ 3μs/op
HMAC-SHA256 32 B x 270,343 ops/sec @ 3μs/op
RIPEMD160 32 B x 962,463 ops/sec @ 1μs/op
HKDF-SHA256 32 x 112,688 ops/sec @ 8μs/op
PBKDF2-HMAC-SHA256 262144 x 3 ops/sec @ 319ms/op
PBKDF2-HMAC-SHA512 262144 x 1 ops/sec @ 986ms/op
Scrypt r: 8, p: 1, n: 262144 x 1 ops/sec @ 646ms/op
```

Compare to native node.js implementation that uses C bindings instead of pure-js code:

```
SHA256 32 B node x 569,151 ops/sec @ 1μs/op
SHA512 32 B node x 551,267 ops/sec @ 1μs/op
SHA512-256 32 B node x 534,473 ops/sec @ 1μs/op
SHA3 32 B node x 545,553 ops/sec @ 1μs/op
BLAKE2s 32 B node x 545,256 ops/sec @ 1μs/op
BLAKE2b 32 B node x 583,090 ops/sec @ 1μs/op
HMAC-SHA256 32 B node x 500,751 ops/sec @ 1μs/op
RIPEMD160 32 B node x 509,424 ops/sec @ 1μs/op
HKDF-SHA256 32 node x 207,856 ops/sec @ 4μs/op
PBKDF2-256 262144 node x 23 ops/sec @ 42ms/op
Scrypt 262144 node x 1 ops/sec @ 564ms/op
// `scrypt.js` package
Scrypt 262144 scrypt.js x 0 ops/sec @ 1678ms/op
```

It is possible to [make this library 4x+ faster](./test/benchmark/README.md) by
*doing code generation of full loop unrolls*. We've decided against it. Reasons:

- the library must be auditable, with minimum amount of code, and zero dependencies
- most method invocations with the lib are going to be something like hashing 32b to 64kb of data
- hashing big inputs is 10x faster with low-level languages, which means you should probably pick 'em instead

The current performance is good enough when compared to other projects; SHA256 is 1.6x faster than native C bindings.

## Contributing & testing

1. Clone the repository.
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests. See [our approach to testing](./test/README.md)
5. `npm run test-dos` will test against DoS; by measuring function complexity. **Takes ~20 minutes**
6. `npm run test-big` will execute hashing on 4GB inputs,
  scrypt with 1024 different `N, r, p` combinations, etc. **Takes several hours**. Using 8-32+ core CPU helps.

## License

The MIT License (MIT)

Copyright (c) 2021 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
