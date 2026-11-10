# BLAKE3 JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmark: one-shot unkeyed
hashing of `32 B / 1 MiB`; results below use Mops/s / MiB/s. Engines: Node 26.6.0
(V8 14.6), JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%. Every
implementation and prototype was pure JavaScript; no WASM was initialized or measured.

## Result

| Engine         |                Before |                Current |          Gain |
| -------------- | --------------------: | ---------------------: | ------------: |
| V8             | 0.89 Mops / 123 MiB/s | 8.27 Mops / 1044 MiB/s | +829% / +749% |
| JavaScriptCore | 1.01 Mops / 173 MiB/s |  6.29 Mops / 502 MiB/s | +523% / +190% |
| SpiderMonkey   | 0.53 Mops / 113 MiB/s |  5.32 Mops / 600 MiB/s | +904% / +431% |

The final comparison used fresh processes, pinned CPU 11, nine samples per cell, forward/reverse
size order, and a third tie-break pass on V8 and JSC. Every digest was checked before timing.

Further portable single-thread improvement on large inputs is likely **1-5%, not another 2x**:

- current and the aggressively specialized vendor reference are within 3% at both large sizes;
- before the one-shot traversal, a no-op-compressor experiment attributed approximately 81% of 1
  MiB time to compression and 19% to calls, tree handling, buffering, allocation, and output; the
  shipped traversal removed nearly all of that measured surrounding gap;
- the vendor is not API-equivalent: it relies on uncleared global scratch, truncated length and
  counter arithmetic, and omits streaming, clone/destroy, keyed cleanup, and incremental XOF;
- for `N` full chunks, leaf work is `16N` compressions and tree work is `N-1`, so parent nodes are
  asymptotically only `1/17` (5.9%) of compression calls.

The dedicated default one-shot path confirms that small-call headroom was construction,
validation, cleanup, and serialization rather than compression arithmetic. The generated
compressor and one-shot path grow `src/blake3.ts` from 12.6 to 35.5 kB (+182%); gzip size grows from
4.53 to 7.93 kB (+75%).

### 2026-11-09 arm64 follow-up

Tested on Apple M5 Pro with Node 26.10.0 (V8) and system JavaScriptCore; method, bundle tables,
branch-drift caveats, and the JSC pitfall are in [arm64.md](./arm64.md).

| Case (V8 / JSC)     |          2.4.0 |       before |        after | after / 2.4.0 |
| ------------------- | -------------: | -----------: | -----------: | ------------: |
| blake3 32 B         |  846 / 1240 ns | 115 / 125 ns | 107 / 108 ns | 7.83x / 11.6x |
| blake3 1 MiB        | 8.54 / 2.71 ms |  1.04 / 1.38 |  1.02 / 1.34 | 8.38x / 1.87x |
| blake3 keyed 32 B   |  980 / 1680 ns | 550 / 527 ns | 153 / 150 ns | 6.42x / 9.58x |
| blake3 context 32 B |                |              |              | 8.49x / 13.2x |

| Change                                                                                 |                                                    Result |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------: | ------------------- |
| Extend the one-shot traversal to keyed, derive-key context, and XOF output             |                                  keyed 32 B 550 -> 153 ns |
| Flat scratch: CV, block, key words, XOF block, 54-entry CV stack, 4 KiB staging window |                                      one wiped allocation |
| Copy unaligned inputs of at least one chunk into the staging window in 4 KiB pieces    |                                     1 MiB unaligned ~1.4x |
| Return root `blockLen                                                                  | flags << 8` so digest and XOF share one Output descriptor | no second traversal |
| `Int32Array` alias of the scratch for all glue code; compressor keeps `Uint32Array`    |                                     JSC 1 KiB -16% -> -2% |

The 4 KiB staging window exists because one native copy is far cheaper than decoding every word
from bytes; the vendor-shaped byte decode that was rejected above stays rejected. The first `after`
candidate lost 16% at 1 KiB on JSC in 17 of 20 processes: the one-shot glue read `Uint32Array`
words, and chaining values with bit 31 set trapped it in Baseline. Reading the same words through
an `Int32Array` alias restored 1220-1232 ns versus 1195-1207 ns for `before`; the compressor sees
only `Uint32Array` so its type feedback stays monomorphic.

#### Size/speed frontier

A loop-form compressor was revisited, because "inline G but keep the seven-round loop" above kept
the schedule table and typed message reads. The new loop variants keep the 16 state and 16 message
words in locals and permute the message in locals between rounds: `k1` runs one spelled-out round
seven times, `k2` runs two spelled-out rounds three times plus one tail round, `k7` is the shipped
full unroll. `s0` has no one-shot path, `sc2` has the default-option one-shot through 1 KiB via
`_wrapShortHash`, `s2` has `after`'s full keyed / context / XOF one-shot. All inline the wrapper
(-19 B). gzip bytes of the `blake3` export; speeds versus 2.4.0 as V8 / JSC.

| Variant              |   min / gzip | vs 2.4.0 |        32 B |       1 MiB |  keyed 32 B | XOF 64 KiB |
| -------------------- | -----------: | -------: | ----------: | ----------: | ----------: | ---------: |
| 2.4.0                |  9294 / 3733 |          |             |             |             |            |
| k1, no one-shot      |  8890 / 3728 |     -5 B | 2.0x / 5.1x | 8.1x / 1.3x | 1.8x / 4.1x |       5.7x |
| k2, no one-shot      | 10722 / 3843 |   +110 B | 2.0x / 4.8x | 7.9x / 1.6x | 1.8x / 4.2x |       5.7x |
| k2, default one-shot | 12040 / 4382 |   +649 B |  7.5x / 15x | 8.1x / 1.7x | 1.8x / 4.0x |       5.7x |
| k7, default one-shot | 15597 / 4608 |   +875 B |  7.7x / 12x | 8.2x / 1.8x | 1.8x / 4.4x |       6.0x |
| k2, full one-shot    | 14347 / 5330 |  +1597 B |  7.5x / 15x | 8.8x / 1.8x |  6.4x / 12x |       7.5x |
| k7, full one-shot    | 17901 / 5561 |  +1828 B |  8.2x / 16x | 9.1x / 1.9x |  6.8x / 13x |       7.7x |
| `after`              | 17956 / 5581 |  +1848 B |  8.1x / 15x | 9.2x / 1.9x |  6.7x / 13x |       8.0x |

JSC 32 B ratios are loose (±25-30%) because 2.4.0 itself is bimodal there. Streaming
`.create().update(1 MiB).digest()` is 7.9-8.7x on V8 and 1.3-1.7x on JSC for every row.

- The loop-form compressor is nearly free on arm64: `k2` is within 3-8% of the full unroll on V8 at
  every size and smaller than 2.4.0's generic code. This contradicts the x64 result above, where
  the loop was 570 versus 997 MiB/s; that loop kept the schedule table and typed reads, which the
  new form does not. `k1` is weak on JSC (1.3x at 1 MiB) and was bimodal at 4 KiB and 1 MiB.
- The default-only one-shot through 1 KiB is where almost all of the short-input gain is; keyed,
  context, and XOF one-shots add about 950 B gzip and help only MAC, KDF, and XOF callers.
- Full unroll over `k2` costs about 230 B gzip and 3.6 KB minified for 3-8%.

#### Applied on `speedup-pareto` (2026-11-09)

The `k2, default one-shot` row is applied on the branch rebased onto 2.4.0. `b3Compress` keeps the
16 state and 16 message words in locals and spells out two rounds inside a loop that runs three
times, then one tail round; the message locals are permuted by P^2 (four 4-cycles, one temporary) at
the end of each iteration, so there is no schedule table and no typed-array message read inside a
round. `test/misc/unrolled-blake3.js` generates the function and symbolically checks that every
round reads the official schedule. The one-shot path is reduced to `b3HashChunk`: default options,
plain `Uint8Array`, at most one 1 KiB chunk, routed by `_wrapShortHash(..., 1024, b3HashChunk, true)`
with a 24-word wiped scratch whose glue reads go through an `Int32Array` alias. Keyed, derive-key,
custom-`dkLen` and longer calls use the `_BLAKE3` class with the same compressor; the keyed / context
/ XOF one-shot, flat CV stack and staging window were removed, and the `b2Compress` wrapper is
inlined. All 2.4.0 hardening for inputs of 2^32 chunks and more is unchanged. Removing the old
one-shot also restores 2.4.0's rejection of a `Uint8Array` with a forged own `length`, which the
previous tree hashed using the forged length. `blake3` is 12168 min / 4427 gzip (2.4.0: 3738 gzip,
before: 18071 / 5630). V8 versus 2.4.0: 8.2x at 32 B, 8.7x at 1 KiB, 7.6-8.1x at 1 MiB, 1.7x keyed
32 B, 5.6x XOF 64 KiB; keyed 32 B is 0.29x and XOF 64 KiB 0.73x of the previous tree because those
calls lost their one-shot. JSC: about 13x at 32 B, 1.6-2.2x at 1 KiB, 1.6x at 1 MiB, with no 1 KiB
regression. The machine was under load; the JSC 1 MiB figure should be re-measured. A 460,000-check
differential against 2.4.0 found no mismatch.

## Shipped wins

| Change                                                                        |                 1 MiB result (V8 / JSC / SM) |
| ----------------------------------------------------------------------------- | -------------------------------------------: |
| Replace the generic compressor and result object with a local, inlined G core |   127 -> 570 / 180 -> 336 / 115 -> 231 MiB/s |
| Preload 16 message words and fully spell the fixed seven-round schedule       |   570 -> 997 / 336 -> 474 / 231 -> 523 MiB/s |
| Seed the four fixed IV words as immediates                                    |     V8 +2.3%; SM +2.2%; JSC prefers loads 5% |
| Write the second eight output words only for root/XOF output                  |         avoids unneeded stores; not isolated |
| Generate and verify the large compressor from the official permutation        |                auditability; no runtime cost |
| Default one-shot traversal with a flat, wiped CV stack and manual output      | 32 B: +474% / +456% / +639% on V8 / JSC / SM |
| Decode sub-64-byte blocks instead of reading past a short u32 view            |               32 B: +9% / +51% / +53% on top |
| Avoid class construction and per-node allocations on one-shot large inputs    |      1 MiB: approximately +11% / +10% / +16% |

The fully static schedule with one complete G at a time is the best universal shape. It mirrors
the [official portable implementation](https://github.com/BLAKE3-team/BLAKE3/blob/master/src/portable.rs),
which forces G/round inlining and explicitly calls all seven rounds. Literal IV words are retained
because they win on V8 and SpiderMonkey and avoid four typed-array reads.

## Rejected single-thread changes

Some rows below are isolated experiments in the vendor-shaped one-shot harness. They compare code
shapes, not the complete library's before/current API.

| Change                                                      |                                                        Result |
| ----------------------------------------------------------- | ------------------------------------------------------------: |
| Keep the shared generic `_compress` core                    |                        127 / 180 / 115 MiB/s on V8 / JSC / SM |
| Inline G but retain the seven-round loop and schedule table |      570 / 336 / 231 MiB/s; much slower than static unrolling |
| Call a G helper from all unrolled sites                     |                       77 MiB/s versus 119 MiB/s generic on V8 |
| Interleave four G chains                                    |            V8 921 -> 905; JSC 455 -> 493; SM 531 -> 549 MiB/s |
| Read message words from the typed array at every use        |               828 MiB/s versus 1123 MiB/s with message locals |
| Load fixed IV words from `B3_IV`                            |                                 V8 -2.3%; SM -2.2%; JSC +5.0% |
| Flatten the per-instance CV stack and reuse leaf state      |                        neutral/noisy; small 1 KiB regressions |
| Cache chunk-counter low/high halves                         |                                                 neutral/noisy |
| Combine the vendor tree with the old generic compressor     |                      116 MiB/s; tree shape alone did not help |
| Allocate a flat scratch stack per one-shot call             |      vendor 32 B: 7.5 -> 2.4 Mops/s; 1 KiB: 1115 -> 826 MiB/s |
| Reuse module-global scratch without leasing or wiping       | fast short path; non-reentrant and retains keyed/KDF material |
| Wipe the entire maximum-depth reusable scratch              | 8.43 -> 6.84 Mops/s at 32 B; approximately neutral when large |
| Force byte decoding for all aligned full blocks             |  vendor 1115 -> 840 MiB/s; current unaligned 974 -> 726 MiB/s |
| Emit XOF bytes one at a time                                |        657 MiB/s versus 708 MiB/s for bulk typed-array copies |
| Always materialize all 16 output words                      |       approximately -4% after digest/XOF type-feedback mixing |
| Truncate lengths to signed 32-bit or omit counter-high      |         invalid beyond 2 GiB / `2^32` chunks or output blocks |
| Remove validation, clone/destroy state, or secret wiping    |                               not API- or security-equivalent |

Four-chain interleaving was correct across all tested modes but is rejected as the default: it
trades approximately 2% of dominant V8 throughput for +8% JSC and +3% SpiderMonkey, with no stable
32-byte win. The vendor's low-only counter is incorrect after `2^32` 1 KiB chunks (4 TiB input) or
`2^32` 64-byte XOF blocks (256 GiB output). Its `length | 0`, shared scratch, and missing cleanup are
not transferable optimizations.

Small, unshipped candidates:

| Change                                                      |                                          Expected result |
| ----------------------------------------------------------- | -------------------------------------------------------: |
| Separate truncated-CV/default-root and full-XOF compressors | up to approximately 4%; nearly duplicates the large core |
| Engine-specific interleaved build                           |                                  JSC +8%; SM +3%; V8 -2% |

These overlap, can increase parse/JIT cost, and must be tested in isolated digest, isolated XOF,
and mixed workloads on all three engines before landing.

## Worker subtree parallelism

A pure-JS Node `worker_threads` prototype used a persistent pool and copied ordinary input once
into a reusable `SharedArrayBuffer`. Workers received disjoint, aligned, power-of-two subtrees with
the real global chunk counter, folded their local CV stacks, and returned one 32-byte CV. The
coordinator performed only `W-1` parent compressions and applied `PARENT | ROOT` at the final node.
The shared input was read-only, so the fork/join needed no Atomics or phase barriers. Its scalar
core was the vendor-shaped unroll with counter-high restored, so these numbers measure the worker
topology rather than the complete library API.

Warm compute-only medians, with input already shared:

| Size   | Sequential |  2 workers |  4 workers |  8 workers |
| ------ | ---------: | ---------: | ---------: | ---------: |
| 1 MiB  |  981 MiB/s | 1914 MiB/s | 3364 MiB/s | 4238 MiB/s |
| 16 MiB | 1035 MiB/s | 2058 MiB/s | 3998 MiB/s | 7709 MiB/s |
| 64 MiB | 1084 MiB/s | 2068 MiB/s | 3790 MiB/s | 7501 MiB/s |

Two and four workers scaled consistently. Eight workers were scheduling/contention-sensitive: 64
MiB runs ranged from approximately 4.1 to 7.7 GiB/s. Including the copy into a reusable shared
buffer, 64 MiB throughput was 1.86 / 3.17 / 5.15 GiB/s with 2 / 4 / 8 workers. Reusing the shared
buffer matters: the 64 MiB copy took 3.29 ms, while fresh allocation plus copy took 7.29 ms.

Cold four-worker pool:

| Size   | Sequential | Ready + first hash | With reusable-buffer copy |
| ------ | ---------: | -----------------: | ------------------------: |
| 32 MiB |    29.5 ms |            32.7 ms |                   34.1 ms |
| 64 MiB |    59.1 ms |            39.1 ms |                   42.4 ms |

Cold crossover is between 32 and 64 MiB. A persistent pool crossed over experimentally around
256-512 KiB; `>= 1 MiB` is a conservative initial policy.

Task granularity for four workers hashing 1 MiB:

| Subtree tasks |        4 |       16 |       64 |      256 |     1024 |
| ------------: | -------: | -------: | -------: | -------: | -------: |
|          Time | 0.461 ms | 0.321 ms | 0.480 ms | 1.087 ms | 3.322 ms |

A few coarse tasks per worker smooth stragglers. One message per 1 KiB chunk is approximately 3.3x
slower than serial and moves too much parent work to the coordinator.

The prototype is research-only: it covers unkeyed 32-byte output and exact power-of-two full-chunk
messages. Production needs an async API, reusable bounded pool, canonical uneven tree scheduler,
root Output descriptor for XOF, keyed/derive-key cleanup, immutable shared input or a defensive
copy, and sequential fallback. Browsers additionally require cross-origin isolation for shared
memory. Spawning workers per call, independently hashing slices, or equal-splitting non-power-of-two
subtrees is incorrect or slower.

## Remaining directions

- ECMAScript has no standard explicit SIMD primitive; the old SIMD.js proposal is
  [inactive](https://github.com/tc39/proposals/blob/main/inactive-proposals.md). With WASM excluded,
  scalar specialization and workers are the portable CPU paths.
- The [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) reports that
  native threading loses below 128 KiB and scales almost linearly through 16 threads before memory
  bandwidth dominates. JavaScript worker startup moves the cold threshold much higher.
- WebGPU could expose many chunks for large batches, but device startup, transfer, portability, and
  root-tree integration need a concrete prototype before it is justified.
- Re-run scheduling and code-generation searches when engines materially change. The current 18 kB
  compressor is large enough that inlining budgets, parse time, and register allocation can move.

## Priority

1. Keep the generated scalar core and safe one-shot traversal as the portable defaults.
2. Build an opt-in async persistent worker pool for large one-shot inputs.
3. Consider separate safe one-shot keyed/XOF paths only with material gains and complete wiping.
4. Revisit interleaving and further scratch-layout changes only with V8, JSC, and SpiderMonkey
   evidence.

## Validation

The library passed all 35 official lengths from 0 through 102400 in hash, keyed, and derive-key
modes with 131-byte output, plus XOF, streaming split, alignment, clone, destroy, `digestInto`, and
`xofInto` tests. The one-shot path was differentially checked against the stateful API across tree
boundaries, byte offsets, reentrant calls, spoofed typed-array metadata, input immutability, and
output ownership. The generator was compared with an independent loop reference for 1000
randomized compressions in truncated and full-output modes, including nonzero counter-high and
message offsets. The worker prototype matched the official 16 KiB vector and the library at every
timed size. Main timings used paired warm runs, forced GC where exposed, and medians.
