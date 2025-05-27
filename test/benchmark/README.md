# Can noble-hashes be faster?

Yes, 3x, but auditability and code size would suffer.
Here are speed-up results for sha3:

sha3_256 x 282,965 ops/sec => 780,031 ops/sec
303 lines => 631 lines  noble-sha3.js
5.03 kb   => 7.57 kb    noble-sha3.min.js
2.24 kb   => 3.54 kb    noble-sha3.min.js.gz

The size increase would need to be done for all functions.
Check out `test/misc/unrolled-sha3.js` for fast SHA3 drop-in replacement.

### Loop unrolling

Consider "hot", performant code:

```js
for (let x = 0; x < 10; x++)
  B[x] = s[x] ^ s[x+10] ^ s[x+20] ^ s[x+30] ^ s[x+40];
```

Array access such as `B[x]`, `s[x]` is slow because of bound checks.
To make it fast, libraries resort to loop unrolling:

```js
let B0 = s0 ^ s10 ^ s20 ^ s30 ^ s40;
let B1 = s1 ^ s11 ^ s21 ^ s31 ^ s41; // ...
```

There are two ways of doing unrolling: run-time and build-time.

1. Run-time is using eval (`new Function`) to build fast function:

```js
let out = ''
for (let x = 0; x < 10; x++)
 out += `let B${x} = s${x} ^ s${x + 10} ^ s${x + 20} ^ s${x + 30} ^ s${x + 40};\n`;
const UNROLLED_FN = new Function('state', out);
```

2. Constructing function during build-time is the same, but executed at some point during build.
   The result function is

### Loop unrolling issues

Run-time doesn't work with popular CSP policy `unsafe-eval`. So, we can't use it.

Build-time construction will make the code much harder to audit and reason about.
Auditors would need to check code generation script in addition to code itself.
It would also increase bundle size.
So, for now we don't do unrolling.

If you have a concrete use-case for "very fast" hashing in JS, open an issue - we will discuss it.
