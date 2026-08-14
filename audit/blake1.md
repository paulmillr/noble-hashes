# BLAKE1 JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmarks: one-shot
BLAKE-256 and BLAKE-512 at `32 B / 1 MiB`. Engines: Node 26.6.0 (V8 14.6),
JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%. All implementations were pure
JavaScript; no WASM was loaded.

## Result

BLAKE-256 (also the BLAKE-224 core):

| Engine       |                   Before |                  Current |          Gain |
| ------------ | -----------------------: | -----------------------: | ------------: |
| V8           |  0.730 Mops / 58.9 MiB/s | 1.713 Mops / 458.1 MiB/s | +135% / +677% |
| JSC          | 1.325 Mops / 163.1 MiB/s | 1.381 Mops / 164.3 MiB/s |     +4% / +1% |
| SpiderMonkey |  0.420 Mops / 51.1 MiB/s | 1.078 Mops / 319.7 MiB/s | +157% / +526% |

BLAKE-512 (also the BLAKE-384 core):

| Engine       |                  Before |                 Current |        Gain |
| ------------ | ----------------------: | ----------------------: | ----------: |
| V8           | 0.330 Mops / 49.1 MiB/s | 0.439 Mops / 68.0 MiB/s | +33% / +38% |
| JSC          | 0.281 Mops / 41.9 MiB/s | 0.404 Mops / 60.3 MiB/s | +44% / +44% |
| SpiderMonkey | 0.127 Mops / 17.8 MiB/s | 0.211 Mops / 34.0 MiB/s | +66% / +90% |

At 10 MiB, BLAKE-256 gained `+601% / +1% / +522%` and BLAKE-512 gained
`+40% / +46% / +88%` on V8 / JSC / SpiderMonkey.

The two word families need different shapes:

- BLAKE-224/256 uses a generated fourteen-round compressor with scalar message and work words,
  fixed SIGMA/constant selections, and serial complete Gs;
- BLAKE-384/512 keeps typed split-u64 vectors, combines the two half-G helpers, uses numeric carry
  formulas, and statically emits all 128 G calls;
- buffering, padding, counters, salt, serialization, cloning, destruction, and virtual `compress`
  dispatch remain on the stateful path.

Profiles put almost all large-input time in the old compressors and their helpers; `update` was
negligible. BLAKE-256 also spent 8.1% of V8 ticks in GC from 224 helper-result objects per block.
BLAKE-512's remaining portable headroom is limited by split-u64 register-allocation tradeoffs.

## Shipped wins

| Change                                                    |                                     Result |
| --------------------------------------------------------- | -----------------------------------------: |
| Generate all fourteen BLAKE-224/256 rounds                |             `+677% / +1% / +526%` at 1 MiB |
| Keep BLAKE-256 message and work words in scalar locals    | removes object allocation and hot indexing |
| Resolve SIGMA and companion constants during generation   |               no runtime schedule dispatch |
| Use serial complete-G scheduling for BLAKE-256            |       best portable JSC/SpiderMonkey shape |
| Combine BLAKE-512 half-G helpers and use numeric carries  |       removes 256 result objects per block |
| Statically emit BLAKE-512's 128 G calls                   | `+3-5% / ~0% / +35-44%` over dynamic calls |
| Retain typed BLAKE-512 work/message vectors and wipe them |     portable JIT shape and bounded scratch |
| Preserve stateful and virtual paths                       |      API, salt, and override compatibility |

The generated schedule follows BLAKE version 1.3: fourteen/sixteen rounds, ten SIGMA rows repeated
modulo ten, column then diagonal Gs, pi-derived companion constants, salt injection, counters, and
the algorithm's distinct finalization bits.

Bundle cost against 2.3.0:

| Export               | Before min / gzip | Current min / gzip |           Growth |
| -------------------- | ----------------: | -----------------: | ---------------: |
| Complete `blake1.js` |    12074 / 4674 B |     29275 / 6003 B | +142.5% / +28.4% |
| `blake256`           |     7688 / 3232 B |     23296 / 4275 B | +203.0% / +32.3% |
| `blake512`           |     8835 / 3729 B |      9951 / 3818 B |   +12.6% / +2.4% |

The repetitive BLAKE-256 core compresses well and tree-shakes out of BLAKE-384/512-only bundles.

## Rejected single-thread changes

| Change                                                |                                                         Result |
| ----------------------------------------------------- | -------------------------------------------------------------: |
| Scalar BLAKE-256 with a dynamic round loop            |                                far below the fully static core |
| Typed BLAKE-256 state with complete-G helper          |                            only `1.39x / 1.62x` baseline on V8 |
| Static BLAKE-256 with repeated `DataView` reads       |                   JSC -44% at 32 B; SpiderMonkey tier collapse |
| Four-chain staged static BLAKE-256                    |                V8 close; JSC -8%; SpiderMonkey unstable/slower |
| Dynamic combined-G BLAKE-512                          |        smaller; loses up to 44% to fixed calls on SpiderMonkey |
| Four-16-bit-limb BLAKE-512 carries                    |                                 failed differential validation |
| Fully scalar split-u64 BLAKE-512                      |       not completed; expected severe register/tiering pressure |
| Fully generated awasm-style BLAKE-512                 |                        ~243 kB source plus fixed 20 MiB buffer |
| Reusable exported-class instance for one-shot hashing |     unsafe under overrides, retention, reentry, and exceptions |
| Closed one-block BLAKE-224/256 path                   | `1.72-2.72x` current at 32 B; +33% full gzip; audit incomplete |
| Remove BLAKE-512 scratch wiping                       |                   security regression for at most a small gain |
| Replace aligned traversal or padding                  |                                        not visible in profiles |

The closed short-input prototype raised V8 / JSC / SpiderMonkey from
`1.714 / 1.341 / 1.091` to `4.658 / 2.305 / 2.373 Mops/s` at 32 bytes, but covered only inputs
through 55 bytes and grew complete gzip from 6003 to 7989 bytes. A safe version must use private
state, fresh output, disjoint storage on reentry, and `finally` cleanup without overridable class
methods.

BLAKE1 now fixes SIGMA and companion-constant selections to the official schedule instead of
observing the unsupported package-internal `BSIGMA` array. Runtime-visible instance `constants`
and `salt` still affect initialization and feed-forward. BLAKE-512 scratch clearing remains
normal-return cleanup, matching prior exception behavior.

Small, unshipped candidates:

| Change                                   |                                      Result |
| ---------------------------------------- | ------------------------------------------: |
| Closed short one-shot cores              |  faster setup; substantial size/safety cost |
| Engine-specific staged BLAKE-256         |     smaller gzip; loses on JSC/SpiderMonkey |
| Engine-specific dynamic-call BLAKE-512   |            smaller; large SpiderMonkey loss |
| Packed `hashMany` API                    |   may amortize wrapper and output ownership |
| Local counters through aligned traversal | likely small; compressor dominated profiles |

## Independent-message batching and workers

Compression is serial within one standard BLAKE digest. Workers can only parallelize independent
messages; hashing chunks or building a tree changes the result.

A persistent Node `worker_threads` prototype, measured with the pre-optimization core, produced:

| Algorithm / batch       |   Sequential | 2 workers | 4 workers | 8 workers |
| ----------------------- | -----------: | --------: | --------: | --------: |
| BLAKE-256, 32768 × 32 B | 0.672 Mmsg/s |     1.268 |     2.271 |     2.437 |
| BLAKE-256, 32 × 1 MiB   |   61.1 MiB/s |     115.5 |     227.4 |     401.1 |
| BLAKE-512, 32768 × 32 B | 0.329 Mmsg/s |     0.616 |     1.157 |     1.542 |
| BLAKE-512, 32 × 1 MiB   |   50.0 MiB/s |      93.2 |     184.0 |     303.1 |

Pool setup took 16-34 ms, excluding per-call workers for short inputs. Production support would
need a bounded reusable pool, ordering and error semantics, transfer policy, packed output
ownership, and sequential fallback. Remeasure against the current compressors before proceeding.

## Remaining directions

- Revisit a private short one-shot path only if its setup gain justifies the size and safety cost.
- Re-run serial versus staged BLAKE-256 scheduling when engines materially change.
- Revisit compact BLAKE-512 carry shapes only with independent differential validation.
- Start independent-message work with synchronous packed `hashMany`; add workers only for large
  batches.
- Keep standard single-message BLAKE serial. JavaScript has no portable explicit integer SIMD or
  prefetch primitive.
- Track shared unsalted-array mutation and partial-buffer wiping as separate hardening work.

## Priority

1. Keep scalar serial BLAKE-224/256 and typed fixed-call BLAKE-384/512 as portable defaults.
2. Preserve stateful wrappers, salt/padding/counters, virtual `compress`, and lifecycle behavior.
3. Revisit closed short one-shot hashing only after safety and bundle-size requirements are met.
4. Consider packed independent-message batching before workers or engine-specific builds.

## Validation

All four variants passed 5,056 dense differential cases against an independent reference, the
frozen pre-work implementation, and awasm JavaScript across four salt modes. Additional coverage
included offsets, every streaming split, byte-wise updates, cloning, immutability, `digestInto`,
output ownership, padding boundaries, counters, direct compression, runtime state mutation, and
unsupported `BSIGMA` mutation.

The landed source passed formatting, types, build, generator `--check`, 22 focused BLAKE tests,
the complete 705-test suite, and the independent safety harness. Benchmarks used one frozen build
per fresh CPU-pinned process, long warmup, calibration trials, and medians of nine samples to avoid
cross-implementation JIT tier contamination.
