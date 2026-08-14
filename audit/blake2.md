# BLAKE2 JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmarks: one-shot BLAKE2s
and BLAKE2b at `32 B / 1 MiB`. Engines: Node 26.6.0 (V8 14.6), JavaScriptCore
2.52.5, and SpiderMonkey 128. Variance: ±3-5%. All implementations were pure JavaScript; no
WASM was loaded.

## Result

BLAKE2s:

| Engine       |                   Before |                  Current |         Gain |
| ------------ | -----------------------: | -----------------------: | -----------: |
| V8           |  0.872 Mops / 78.1 MiB/s | 1.587 Mops / 393.1 MiB/s | +80% / +385% |
| JSC          | 1.317 Mops / 177.3 MiB/s | 1.517 Mops / 488.4 MiB/s | +15% / +176% |
| SpiderMonkey |  0.635 Mops / 87.4 MiB/s | 1.132 Mops / 516.4 MiB/s | +78% / +490% |

BLAKE2b:

| Engine       |                  Before |                 Current |        Gain |
| ------------ | ----------------------: | ----------------------: | ----------: |
| V8           | 0.398 Mops / 61.4 MiB/s | 0.520 Mops / 87.5 MiB/s | +30% / +42% |
| JSC          | 0.383 Mops / 60.0 MiB/s | 0.446 Mops / 78.1 MiB/s | +17% / +30% |
| SpiderMonkey | 0.201 Mops / 28.6 MiB/s | 0.241 Mops / 36.1 MiB/s | +20% / +26% |

### 2026-08-14 BLAKE2s one-shot follow-up

Default BLAKE2s calls of at most one 64-byte block now use a closed path around the existing
generated compressor. A nine-sample alternating V8 comparison at 32 bytes measured `120.0 ns`
direct versus `490.1 ns` through `.create().update().digest()`: `4.08x` as many operations, or
`75.5%` lower latency. Three runs of `FILTER=blake2s node benchmark/thirdparty/hashes.ts` measured
the shipped wrapper at `176 / 177 / 201 ns` (median `177 ns`) and `887 / 890 / 893 MiB/s` at 10
MiB. Large inputs retain the stateful path and its throughput is unchanged within noise.

The implementation captures the exact generated compressor before callers can mutate the exported
class prototype, but invokes it only on an unexported eight-word numeric record. It privately owns
little-endian decode, default RFC initialization, final counter/flag handling, serialization,
reentry storage, and `finally` cleanup. Options, even `{}`, plus keyed/configured, Buffer, subclass,
proxy, cross-realm, forged, and longer calls remain stateful; `.create()`, HMAC/KDF users, and
BLAKE2b are unchanged.

The common eligibility/fallback policy is documented in the
[shared short one-shot wrapper audit](./one-shot.md); BLAKE2s retains its closed state and cleanup.

At 10 MiB, BLAKE2s gained `+474% / +174% / +485%` and BLAKE2b gained
`+36% / +32% / +26%` on V8 / JSC / SpiderMonkey. V8 tiered the generated BLAKE2s core
inconsistently, sometimes reaching 858 MiB/s; the table conservatively reports the final paired
median.

The two algorithms need different shapes:

- BLAKE2s uses a generated ten-round compressor with scalar state/message words, fixed SIGMA
  selections, and four staged G chains;
- BLAKE2b keeps a typed split-u64 work vector, combines the half-G helpers, uses numeric carries,
  and statically emits all 96 G calls;
- buffering, keyed/configured initialization, final-block retention, serialization, cloning, and
  the documented generic `_compress` export remain unchanged.

Profiles put 97-98% of large-input time in the old compressors, helpers, and BLAKE2s allocation
GC; `update` was under 1%. Further universal BLAKE2b improvement is constrained by engine-specific
split-u64 representation and register allocation:

- fully scalar BLAKE2b reached 169 / 3 / 144 MiB/s on V8 / JSC / SpiderMonkey;
- four-16-bit-limb carries reached 77 / 66 / 52 MiB/s;
- the shipped floating-low-sum form gives the best compact V8/JSC balance without JSC's scalar
  tier cliff.

## Shipped wins

| Change                                                      |                                 Result |
| ----------------------------------------------------------- | -------------------------------------: |
| Generate all ten BLAKE2s rounds                             |       `+385% / +176% / +490%` at 1 MiB |
| Keep BLAKE2s state/message words in scalar locals           | removes indexing and 160 objects/block |
| Stage four independent BLAKE2s G chains                     |          best portable scheduler shape |
| Combine BLAKE2b half-G helpers and use numeric carries      |          `+42% / +30% / +26%` at 1 MiB |
| Statically emit BLAKE2b's 96 G calls                        |        no runtime SIGMA/round dispatch |
| Retain typed BLAKE2b state and per-block wiping             | avoids JSC cliff; clears keyed scratch |
| Preserve public generic `_compress`                         | documented arbitrary-round API remains |
| Generate from asserted RFC SIGMA rows with `--check`        |      auditability without runtime cost |
| Close default one-block BLAKE2s around captured compression |                  `4.08x` at 32 B on V8 |

The generated cores track [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693). BLAKE2s uses the
module's IV snapshot and a private fixed schedule; public `_compress(s, offset, msg, rounds,
v0..v15)` retains its arbitrary schedule, offset, round count, and returned-state object. BLAKE2b
keeps its 32-word work vector and wipes it after every block.

Bundle cost against 2.3.0:

| Export               | Before min / gzip | Current min / gzip |           Growth |
| -------------------- | ----------------: | -----------------: | ---------------: |
| Complete `blake2.js` |    10890 / 4201 B |     22174 / 5267 B | +103.6% / +25.4% |
| `blake2s`            |     7234 / 3077 B |     15980 / 3445 B | +120.9% / +12.0% |
| `blake2b`            |     8396 / 3492 B |      9347 / 3650 B |   +11.3% / +4.5% |

The repetitive BLAKE2s core compresses well and tree-shakes out of BLAKE2b-only bundles.

Relative to the immediately preceding optimized worktree build, the one-shot follow-up changes
complete `blake2.js` from `22170 / 5268` to `23375 / 5819` bytes minified/gzip (`+5.4% / +10.5%`)
and the tree-shaken `blake2s` export from `15980 / 3445` to `17181 / 3999` (`+7.5% / +16.1%`). The
tree-shaken `blake2b` export remains exactly `9347 / 3650`.

## Rejected single-thread changes

| Change                                                 |                                      Result |
| ------------------------------------------------------ | ------------------------------------------: |
| Dynamic one-/two-round scalar BLAKE2s loops            |           453-462 / 287-293 / 179-186 MiB/s |
| Static BLAKE2s with repeated message reads             |   618 / 188 / 371 MiB/s; JSC loses on loads |
| Static BLAKE2s with ordinary scheduling                | 857 / 365 / 461 MiB/s; loses to staged form |
| Typed-vector BLAKE2s with complete-G helper            |                         86 / 278 / 63 MiB/s |
| File-local split BLAKE2b helpers                       |         71 / 69 / 30 MiB/s; traffic remains |
| Dynamic combined-G BLAKE2b                             |  88 / 75 / 36 MiB/s; fixed calls are faster |
| Four-16-bit-limb BLAKE2b carries                       |          77 / 66 / 52 MiB/s; V8/JSC regress |
| Fully scalar/static split-u64 BLAKE2b                  | 169 / 3 / 144 MiB/s; catastrophic JSC cliff |
| Fully generated awasm-style BLAKE2b                    |                ~176.9 kB raw / 34.7 kB gzip |
| Reusable exported-class instance for one-shot hashing  |   unsafe under overrides and retained state |
| Remove BLAKE2b scratch wiping                          |     at most ~1%; retains keyed-derived data |
| Replace zero-copy aligned traversal with byte decoding |     no benefit; current path is appropriate |

A default-only reusable-object prototype improved current 32-byte BLAKE2s by
`+75% / +46% / +60%` and BLAKE2b by `+15% / +19% / +7%`. It was rejected because exported class
methods can be overridden to expose or corrupt persistent cross-call state. A safe short-input
path must own initialization, compression, serialization, reentry storage, and cleanup privately.

BLAKE2 hashing no longer observes mutation of package-internal `BSIGMA` after initialization; the
private core fixes the RFC schedule while public generic `_compress` remains dynamic. Required
BLAKE2b work-vector wiping measured within 0-2% of unwiped forms and was retained.

Small, unshipped candidates:

| Change                                   |                                     Result |
| ---------------------------------------- | -----------------------------------------: |
| Engine-specific 16-bit-carry BLAKE2b     |           SpiderMonkey +45%; V8/JSC slower |
| Engine-specific scalar BLAKE2b           | large V8/SM gain; catastrophic JSC tiering |
| Packed `hashMany` API                    |      may amortize wrapper/output ownership |
| Local counters through aligned traversal |    likely small; division occurs per block |

## Independent-message batching and workers

Compression is serial within one standard BLAKE2 digest. Workers can only parallelize independent
messages. BLAKE2sp/bp and tree hashing produce different digests.

A persistent Node `worker_threads` prototype, measured with the pre-optimization core, produced:

| Algorithm / batch     |   Sequential | 2 workers | 4 workers | 8 workers |
| --------------------- | -----------: | --------: | --------: | --------: |
| BLAKE2s, 32768 × 32 B | 0.829 Mmsg/s |     1.728 |     3.178 |     2.944 |
| BLAKE2s, 32 × 1 MiB   |   88.8 MiB/s |     174.6 |     330.6 |     631.1 |
| BLAKE2b, 32768 × 32 B | 0.430 Mmsg/s |     0.818 |     1.576 |     1.878 |
| BLAKE2b, 32 × 1 MiB   |   68.9 MiB/s |     126.3 |     256.5 |     359.1 |

Pool setup took 17-42 ms, excluding per-call workers for short inputs. Production support would
need a bounded reusable pool, packed output ownership, ordering and error semantics, transfer
policy, and sequential fallback. Remeasure against the current compressors before proceeding.

## Remaining directions

- Re-run the bounded BLAKE2s path on JSC and SpiderMonkey and retain it only with portable gains.
- Revisit compact BLAKE2b carries as engines change; scalar and 16-bit forms prove
  engine-specific, not universal, headroom.
- Start independent-message work with synchronous packed `hashMany`; add workers only for large
  batches.
- Test local low/high counters through aligned updates, requiring an all-engine win.
- Keep standard single-message BLAKE2 serial. JavaScript has no portable explicit integer SIMD or
  prefetch primitive.

## Priority

1. Keep generated four-chain BLAKE2s, its bounded default one-shot path, and compact BLAKE2b.
2. Preserve configured/stateful hashing and the public generic `_compress` contract.
3. Validate the new wrapper on JSC and SpiderMonkey before considering a BLAKE2b analogue.
4. Consider packed independent-message batching before workers or engine-specific builds.

## Validation

Official BLAKE2s/BLAKE2b KATs, Python-option vectors, lifecycle, clone, HMAC/PBKDF2, Argon2, and
library tests passed. Coverage includes 512 keyed and unkeyed KAT rows per family, every digest
length, keys, salt, personalization, unaligned inputs/options, partial updates, clone/destroy,
`digestInto`, Node differentials, exact-full final blocks, and high counter halves.

The generator asserts the ten RFC SIGMA permutations, repeats rows 0/1 for BLAKE2b rounds 10/11,
and checks both emitted source regions byte-for-byte. The final source passed formatting, types,
build, generator `--check`, and the complete test suite. Benchmarks used fresh CPU-pinned processes,
interleaved warmup, nine alternating samples, medians, and digest verification.
The one-shot follow-up additionally checked every length through 70 bytes and unaligned offsets,
exact-full final blocks, options fallback, output ownership, exotic and forged inputs, exported
prototype mutation, forced reentry and exceptions, and scratch restoration. The complete 711-test
suite, 12 repository checks, build, formatting, and BLAKE2 generator check passed.
