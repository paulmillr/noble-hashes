# Can noble-hashes be faster?

tl;dr: Yes, 4x+; but auditability would be bad.

CSP policy treats this construction as 'unsafe-eval':

```js
const unrolled = (() => { let out = 'let a = 1;'; ... return new Function(..., out) })();
```

There are websites and extensions that force this policy. Which means there is no way to do unrolling directly in JS without build systems.
Adding a build system will make the code hard to audit and reason about.
TypeScript is fine, since it generates very similar code and it is easy to read,
but for loop unrolling it is pretty hard to verify the generated code is the same.

Why does it matter? Loop unrolling itself doesn't impact performance much,
however it also eliminates branches and array access which significantly impacts performance. For example, small expression:

```js
a[x] ^= b;
```

Can be just one xor instruction, but with array access it will be compiled to something like this:

```js
ptr = array_ptr + 8 * x; // can be even worse if there is different array elements sizes
if (x < 0 || x >= array_len) throw Error;
*ptr ^= b;
```

Now we have a lot of overhead for a simple operation which will take significantly more time than operation itself.

So, how bad it is? Almost x4!

```
SHA3 32 B    x 184,331 ops/sec => 640,614   ops/sec unrolled
BLAKE2s 32 B x 464,468 ops/sec => 1,820,714 ops/sec unrolled
BLAKE2b 32 B x 282,965 ops/sec => 749,857   ops/sec unrolled
```

This is why we can't have nice things. Contact your W3C representative about it!
