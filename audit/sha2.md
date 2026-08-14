# SHA2 JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmark: one-shot SHA-256
hashing of `32 B / 1 MiB`; results below use Mops/s / MiB/s. Engines: Node 26.6.0
(V8 14.6), JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%. Every
implementation and prototype was pure JavaScript; no WASM was initialized or measured.

## Result

| Engine         |                   Before |                  Current |         Gain |
| -------------- | -----------------------: | -----------------------: | -----------: |
| V8             | 1.462 Mops / 258.3 MiB/s | 3.534 Mops / 304.7 MiB/s | +141% / +19% |
| JavaScriptCore | 1.728 Mops / 217.2 MiB/s | 3.177 Mops / 220.1 MiB/s |   +83% / +2% |
| SpiderMonkey   |  0.555 Mops / 68.7 MiB/s |  1.933 Mops / 90.9 MiB/s | +247% / +32% |

The final paired check used a fresh process per case pinned to CPU 11, interleaved warmup, three
timed calibration rounds, ten samples split five/five between before-first and current-first order,
and digest verification before timing. Before/current are per-implementation medians; gains are
medians of the ten within-pair speed ratios. The table reports 32 B / 1 MiB; the 10 MiB gains were
`+19% / +1% / +30%`, and SHA-512 warm throughput remained neutral. SHA-224 uses the same optimized
paths; its 32 B / 1 MiB gains were `+140% / +17%`, `+91% / neutral`, and `+241% / +32%` on the same
three engines.

The two classes of gain are independent:

- for eligible same-realm plain `Uint8Array` inputs through 119 B, whose complete padding fits one
  or two specialized blocks, construction, generic buffering, finalization, and class-state
  serialization are bypassed; at 32 B this accounts for nearly all of the 1.8-3.5x speedup;
- for long inputs, a 16-word rolling schedule, compact boolean identities, and two straight rounds
  per loop improve the shared SHA-224/SHA-256 compressor; the isolated 1 MiB gains on V8, JSC, and
  SpiderMonkey were `+20.9%`, `+2.6%`, and `+31.8%`;
- SHA-384, SHA-512, SHA-512/224, and SHA-512/256 retain their compressor. Relative to runtime BigInt
  construction, their generated constants improve size and startup, while warm hashing remains
  within noise.

Further universal SHA-256 improvement is constrained by **engine-specific JIT shapes, not the
wrapper around long messages**:

- before this change, `SHA2_32B.process` was 99.3% of V8's 1 MiB profile; update and surrounding
  code together were under 1%;
- a one-round rolling schedule is weak on V8/JSC, four-round grouping loses substantially on
  V8/JSC, and wider straight unrolling triggers a severe SpiderMonkey tier cliff;
- putting the schedule into 16 scalar locals approximately halves V8 throughput, while fully
  spelling all 64 rounds grows too far beyond the size budget;
- no tested compressor shape beats the shipped two-round ring on all three engines.

SHA-512 is a separate representation problem. Its compressor was 99.5% of V8's 1 MiB profile, but
portable JavaScript must synthesize 64-bit rotates and carry-propagating additions from pairs of
32-bit words. Flattening additions and boolean helpers gained approximately 4% on V8 and 3% on JSC
but lost 2% on SpiderMonkey, so it is not shipped as a universal default.

Measured with `bismar -bsm ./sha2.js` against a built 2.3.0 archive, the complete `sha2.js` bundle
grows from 11762 / 5533 bytes to 14154 / 6187 bytes minified / gzip: `+20.3% / +11.8%`. The
`sha256` export grows from 5623 / 2806 to 8384 / 4041 bytes: `+49.1% / +44.0%`. The `sha512`
export remains effectively flat at 8528 / 4120 versus 8573 / 4121 bytes (`+0.5% / +0.0%`),
confirming that the direct SHA-224/SHA-256 core tree-shakes away. In an isolated constant-only
comparison, replacing load-time BigInt parsing with generated split-u32 constants reduced median
import time by 19% / 11% / 15% on V8 / JSC / SpiderMonkey.

## Shipped wins

| Change                                                                         |                                     Result |
| ------------------------------------------------------------------------------ | -----------------------------------------: |
| Direct one-/two-block core for eligible plain-`Uint8Array` calls through 119 B |               32 B: `+141% / +83% / +247%` |
| Specialize the second padded block instead of falling back after 55 B          |                56 B: `+82% / +50% / +174%` |
| Keep hot loops outside the lexical scratch-cleanup region                      | V8 one-block prototype: ~1.96 → 3.9 Mops/s |
| Replace the 64-word SHA-256 schedule with a 16-word rolling ring               |      less scratch traffic; enables x2 form |
| Execute two straight rounds per stateful compression loop                      |             best portable size/speed shape |
| Spell `Ch` and `Maj` as compact equivalent boolean identities                  |       V8 large-input gain; no helper calls |
| Lease shared scratch, allocate on reentry, and wipe on every exit              |         fast, reentrant, no retained input |
| Emit verified split-u32 SHA-512 constants instead of parsing BigInts at import |         smaller gzip; 11-19% faster import |
| Derive constants from FIPS 180-4 and check emitted source byte-for-byte        |              auditability; no runtime cost |

The direct path applies only to the ordinary frozen `sha224` and `sha256` wrappers; `.create()`,
streaming, clone/destroy, and `digestInto` remain stateful. Only an intrinsically branded, same-realm
`Uint8Array` whose prototype is exactly `Uint8Array.prototype` and which has no own `length`,
`buffer`, `byteOffset`, or `byteLength` property enters it. Buffer, cross-realm views, subclasses,
proxies, forged typed-array brands, and metadata-shadowing views call the original stateful wrapper
before any user-visible getter or index access, preserving constructor/copy-IV-before-input-access
ordering. The fast path reads the mutable exported IV on each call, leases and wipes scratch, and
returns fresh output. Its hot compression loops live in separate callees outside the lexical cleanup
region; putting a loop itself inside `try/finally` prevented V8 from fully optimizing it.

The common eligibility/fallback policy is documented in the
[shared short one-shot wrapper audit](./one-shot.md); SHA-2 retains its own schedule lease and core.

The rolling schedule implements the FIPS 180-4 recurrence modulo 16, like the small fixed schedule
used by portable native implementations. Two explicit rounds reduce loop/control overhead without
crossing the register-pressure and JIT-size cliffs of wider forms. See
[FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),
[RFC 6234](https://www.rfc-editor.org/rfc/rfc6234.html), and the portable
[OpenSSL SHA-256](https://github.com/openssl/openssl/blob/master/crypto/sha/sha256.c) and
[SHA-512](https://github.com/openssl/openssl/blob/master/crypto/sha/sha512.c) implementations.

## Rejected single-thread changes

| Change                                                          |                                                                          Result |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------: |
| Retain the 64-word SHA-256 schedule and generic helper calls    |                            baseline; compressor is 99.3% of V8 large-input time |
| Use a 16-word ring but retain one round per loop                |                           264 / 209 / 81 MiB/s on V8 / JSC / SM; weaker overall |
| Group four rolling-schedule rounds                              |                        SM can improve; V8/JSC regress and show unstable tiering |
| Unroll two/four rounds without the rolling schedule             |                  near neutral or slower; four rounds falls to 19-25 MiB/s on SM |
| Unroll eight or all 64 rounds                                   |                      V8 -5-6% in x8 form; excessive source, parse, and JIT size |
| Put all 16 schedule words in scalar locals                      |                                        approximately 149 versus 277 MiB/s on V8 |
| Generate an awasm-style fully static SHA-256 core               |                   approximately 53.7 kB raw / 10.7 kB gzip; outside size budget |
| Change only `Ch` / `Maj` identities                             |                 V8 +17%; JSC +2%; SpiderMonkey neutral; retained only with ring |
| Split schedule extension and compression into separate loops    |                loses the rolling ring's locality; severe SM/V8 tier regressions |
| Lease and reset one reusable class instance for one-shot calls  | reentrant fallback worked; +123% / +55% / +45% at 32 B; private reset semantics |
| Stop the direct SHA-256 path at 55 B                            |                   56 B SM -22%; leaves a visible two-compression fallback cliff |
| Specialize SHA-512 one-shot calls by resetting class state      |                promising prototype; private-state/reset semantics need redesign |
| Flatten SHA-512 add helpers and compact its boolean expressions |                                               V8 +4%; JSC +3%; SpiderMonkey -2% |
| Generate SHA-512 constants at module initialization             |                  warm neutral but larger/slower startup than emitted u32 tables |
| Fully unroll the split-u32 SHA-512 core                         |                    approximately 191 kB raw / 43.9 kB gzip; outside size budget |
| Remove schedule/scratch wiping or skip validation               |                                     not reentrant, security-, or API-equivalent |

The two-padded-block cutoff is deliberate. A one-block integration checkpoint had left 56 B 22%
below the old implementation on SpiderMonkey. The final two-block path measured 2.026 / 1.695 /
1.022 Mops/s versus 1.110 / 1.137 / 0.373 before on V8 / JSC / SpiderMonkey: `+82% / +50% / +174%`.
At 64 B the paired gains were `+88% / +46% / +187%`, and at 119 B `+88% / +54% / +204%`.
Two-block prototypes added approximately 140-181 gzip bytes over their one-block counterparts,
depending on factoring; the final total bundle cost is reported above. Inputs at 120 B and above
remain stateful.

Full static unrolling is especially unattractive here. Unlike BLAKE3, SHA-256 has 64 rounds and a
recursively extended message schedule; unlike SHA3, it does not have fixed lane movement that lets
code generation remove table dispatch. The generated code pays large source/JIT cost without a
portable arithmetic win. SHA-512 doubles the split-word arithmetic and makes this tradeoff worse.

Small, unshipped candidates:

| Change                                                      |                                          Expected result |
| ----------------------------------------------------------- | -------------------------------------------------------: |
| Hypothetical packed `hashMany` API for independent messages | 32 B prototype: 5.03 / 3.72 / 2.21 Mhash/s V8 / JSC / SM |
| Interleave two independent SHA-256 compression lanes        |           +9% / +9% / +18%; three and four lanes regress |
| Safe leased SHA-512 default one-shot object                 | measurable short-message gain; private reset needs proof |
| Engine-specific SHA-512 add/boolean build                   |                           V8/JSC +3-4%; SpiderMonkey -2% |

The batch candidates need an API decision, output ownership/layout, length grouping, exception
semantics, and differential tests. The awasm-noble `hash.chunks([a, b])` API is scatter/gather for
one logical digest, equivalent to hashing the concatenation; it cannot use independent-message lane
interleaving. The measured prototype instead hashes many separate messages. A marginal isolated
gain is not enough to add a second public path.

## Independent-message batching and workers

SHA-2 compression is serial within one message: block `i + 1` consumes the chaining state produced
by block `i`. Workers cannot accelerate one standard SHA-256 or SHA-512 digest without changing the
algorithm. Independent messages can be batched safely.

A synchronous pure-JS prototype hashed 1024 independent 32-byte SHA-256 messages into a packed
output buffer. Its pre-shipped `inputs.map(sha256)` baseline measured `1.36 / 1.58 / 0.60` Mhash/s;
the specialized batch measured `5.03 / 3.72 / 2.21` on V8 / JSC / SpiderMonkey. Batching loop and
output ownership alone accounted for only approximately 4-5%; the direct padded-block core produced
most of the gain. The hypothetical API must be rebenchmarked against the now-shipped scalar direct
path before its incremental value is known.

Interleaving two independent compression lanes on the same thread added `+9% / +9% / +18%` over
the direct batch core on V8 / JSC / SpiderMonkey. Three and four lanes regressed from register
pressure. This is useful only inside a many-message API; it adds work and code to ordinary scalar
hashing and cannot combine blocks of one message.

An async persistent worker pool remains possible for many independent large messages. As with the
SHA3 audit, pool construction and message handoff dominate small calls; per-call worker creation is
not appropriate. A production API would need a bounded reusable pool, ordering and error handling,
transfer/ownership policy, and a sequential fallback. No worker topology belongs in the synchronous
compression core.

## Remaining directions

- Prototype a safe leased SHA-512 one-shot core without relying on private class reset semantics.
  Its split-u32 compressor makes short-call setup proportionally important, but duplicating 80
  rounds is too large.
- If an independent-message API is desired, start with a synchronous packed-output path and one/two
  direct lanes. Benchmark it against repeated calls to the shipped one-shot wrapper before
  considering workers.
- Standard SHA-2 is serial. Tree hashing or independently hashing input slices changes the digest;
  only independent-message parallelism is transparent.
- ECMAScript has no standard explicit integer SIMD primitive. With WASM excluded, scalar JIT
  specialization and workers for independent messages are the portable CPU paths.
- Re-run schedule and boolean-shape searches as engine tiering changes. The large V8/SpiderMonkey
  ring gain and near-neutral JSC result already show that the optimum is engine-dependent.

## Priority

1. Keep the eligible direct, reentrant SHA-224/SHA-256 path through 119 B and two-round rolling
   compressor as the portable defaults.
2. Keep generated SHA-512 constants; do not duplicate or fully unroll the 80-round compressor.
3. Consider a packed synchronous `hashMany` API for many independent short messages.
4. Revisit safe SHA-512 one-shot specialization and engine-specific arithmetic only with all-engine
   evidence and a clear size allowance.

## Validation

All SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 vectors and library tests
passed. The direct SHA-224/SHA-256 path was differentially checked against `.create().update().digest()`
across padding boundaries, byte offsets, backing-buffer excess, Buffer and cross-realm views,
subclassed/spoofed typed-array metadata, Proxy reentry, constructor/IV getter ordering, invalid-input
recovery, input immutability, fresh output ownership, mutable exported IVs, and alternating
SHA-224/SHA-256 calls. Stateful tests cover split/unaligned updates, padding's extra block, clone,
destroy, and `digestInto`.

The SHA-512 constant generator derives the first 64 fractional cube-root bits for the first 80
primes with integer arithmetic, splits each word into exact high/low halves, and `--check` compares
the emitted source exactly. Main timings used fresh processes pinned to CPU 11, interleaved warmup,
three timed calibration rounds, ten samples split five/five between before-first and current-first
order, and medians. The complete test, type/lint, build, constant-generator, bundle, and three-engine
benchmark suites were rerun after the final hardened one-shot wrapper changes.
