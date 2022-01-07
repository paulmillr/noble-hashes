# Security considerations

See information about audit and fuzzing in root [README](../README.md).

This library re-uses some internal state for hash functions which is not freed after hashing:

```js
// not exposed externally; used atomically
const BUF = new Uint8Array(32);
class SHA256 {
  update() {
    // instead of
    // tmp = new Uint8Array(4);
    // we do
    tmp = BUF.subarray(0, 4)
    // in order to not allocate new memory

    // cleanup
    BUF.fill(0);
  }
}
```

How this impacts security? There can be sensitive parts of data which will stay in memory forever,
however, JS is garbage-collected language and there is no guarantee when (and if it all)
memory region will be freed.

The only thing we can do is overwriting "sensitive information" memory regions with zeros.
This library does that by default if you feel extra paranoid, just make sure that you also
clean input data manually, since any hash output can be restored from input.

But this is actually a security theater, because if an attacker can read application memory,
you are doomed anyway:

- Input at some point will be string and they are immutable in JS (there is no way to overwrite them with zeros)
- For example: Deriving key from `scrypt(login, password)` where login and password are user-provided strings
- Input from file will stay in file buffers
- Input / output will be re-used multiple times in application which means it should stay in memory
- With async functions / Promises there are no guarantees when next operator or function call will be executed which means attacker can have plenty of time to read data from memory
  For example: `await anything()` always will write all internal variables (including numbers) to memory.

Also, there is no way to guarantee anything about zeroing sensitive data without complex tests-suite which will dump process memory and verify that there is no sensitive data left. For JS it means testing all browsers (incl. mobile), which is not too simple. And of course it will be useless without using the same test-suite in the actual application that consumes noble-hashes.
