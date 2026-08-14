# Argon2 JS optimization audit

Tested 2026-08-12 on Ryzen 9 9900X, Linux 6.12. Main benchmark: Argon2id,
`m = 65536`, `p = 1`, `t = 1 / 4`. Variance: ±3-5%.

## Result

| Engine |         Before |        Current |        Gain |
| ------ | -------------: | -------------: | ----------: |
| V8     | 343 / 361 MB/s | 544 / 585 MB/s | +58% / +62% |
| JSC    | 234 / 241 MB/s | 321 / 332 MB/s | +37% / +38% |

Further single-thread improvement is likely **1-3%, not 30-50%**:

- compression is ~87% of runtime; memory and surrounding work are ~13%;
- +30% overall requires compression to become ~36% faster;
- +50% overall requires compression to become ~62% faster;
- deleting all measured memory cost would improve total time by only ~15%;
- optimized `P()` has ~3512 instructions, including ~1400 moves/spills from 52 live values on
  16 general-purpose registers.

Large gains require extra CPU cores.

## Shipped wins

| Change                                                                             |                   Gain |
| ---------------------------------------------------------------------------------- | ---------------------: |
| Keep the 16-word `P` state in locals instead of mutating scratch per quarter-round |                   +26% |
| Interleave four independent G chains                                               |            +19% on top |
| Recover multiply-high with exact double arithmetic; keep `Math.imul` for low half  | best tested arithmetic |
| Yield the generator every 32 blocks instead of every block                         |                    +3% |

Keep `block()` and `P()` separate. Four-chain `P()` is the best tested shape on V8 and JSC.

## Rejected single-thread changes

| Change                                          |                                                        Result |
| ----------------------------------------------- | ------------------------------------------------------------: |
| Fuse `block()` and `P()`                        |                V8 +2%; JSC falls to 10 MB/s (~30x regression) |
| Fully unroll all 16 `P()` bodies                |                                                          -65% |
| Eight interleaved chains                        |                                                390 / 406 MB/s |
| Two interleaved chains                          |                                                466 / 495 MB/s |
| One chain                                       |                                                443 / 469 MB/s |
| Load/compute/store each G quartet separately    |                                                444 / 470 MB/s |
| Split `P()` into a half-round helper            |                                                          -14% |
| Separate row/column versions of `P()`           |                                                           -3% |
| Keep the previous block in scratch across calls |                                                     -1% / -2% |
| Remove generator from the synchronous traversal |                                                     -1% / -2% |
| Second scratch half to touch destination once   |                                                454 / 480 MB/s |
| Ordinary array scratch                          |                                                          -10% |
| `Float64Array` scratch                          |                                                           -5% |
| `Int32Array` scratch or full memory             |                                        neutral/slightly worse |
| 16-bit integer multiply-high                    |                                        370-379 / 390-398 MB/s |
| Integer multiply-high plus float carry          |                                                493 / 525 MB/s |
| Integer low-half addition                       |                                                       neutral |
| Fused high-half expression                      |                                                       neutral |
| Statement-level chain scheduling                |                                                       neutral |
| Extra integer coercions on indices              |                                                neutral to -3% |
| Carry via comparisons with `2^32` / `2^33`      |                                                           -4% |
| Remove per-block 1 KiB scratch clear            |                                                       neutral |
| Remove final full-memory clear                  | ~+3%; rejected because password-derived memory must be erased |

Small, unshipped candidates:

| Change                                                          |                            Result |
| --------------------------------------------------------------- | --------------------------------: |
| Explicitly spell out the 16 `P()` calls, without inlining `P()` |                             +1-2% |
| Shorten rotation temporary live ranges                          | ~+1% at `t = 1`; noise at `t = 4` |
| Skip the no-op progress callback on the fast path               |          +0.5-3%, shape-dependent |

These may overlap and require V8, JSC, and SpiderMonkey benchmarks before landing.

## Worker lane parallelism (`p >= 2`)

Each slice's lanes are independent. Use one worker per lane and synchronize only at the `4t` slice
barriers.

| Config                | Sequential |   Workers | Speedup |
| --------------------- | ---------: | --------: | ------: |
| `m=64 MiB, p=2, t=1`  |   537 MB/s | 1013 MB/s |   1.88x |
| `m=64 MiB, p=4, t=1`  |   543 MB/s | 1620 MB/s |   2.98x |
| `m=64 MiB, p=4, t=3`  |   560 MB/s | 1977 MB/s |   3.53x |
| `m=256 MiB, p=8, t=1` |   522 MB/s | 2237 MB/s |   4.29x |

Cold `p=4`: 82 ms with worker creation versus 118 ms sequential. This is the preferred large
speedup.

Requirements: async API, shared memory, worker-safe zeroization, bundler-compatible worker entry,
job queue, and sequential fallback when shared memory is unavailable.

## Worker intra-block parallelism (`p = 1`)

Each block has eight independent row `P()` calls, a barrier, then eight independent column `P()`
calls. A prototype used the coordinator plus three workers, two `P()` calls per participant, a
shared 1 KiB scratch block, busy-spin phase barriers, and cache-line-padded acknowledgements.

| Config                                 | Sequential | Four participants |   Gain |
| -------------------------------------- | ---------: | ----------------: | -----: |
| `m=64 MiB, p=1, t=1`                   | 568.8 MB/s |        677.7 MB/s | +19.1% |
| `m=64 MiB, p=1, t=4`                   | 594.5 MB/s |        791.7 MB/s | +33.2% |
| `m=64 MiB, p=4, t=1`, sequential lanes | 556.7 MB/s |        721.7 MB/s | +29.6% |
| `m=1 MiB, p=1, t=16`                   | 608.4 MB/s |        749.2 MB/s | +23.1% |

Synchronization:

- wait/wake per phase: ~3.5 µs; too slow versus ~1.7 µs per block;
- busy-spin handshake: ~70-170 ns;
- two participants: +8%; three: +14%; four: best; eight: 364 MB/s;
- row-only parallelism: +8%; scratch transpose: no net gain;
- sleeping workers while idle reduced 750 ms idle CPU from ~2.27 CPU-seconds to ~9 ms without
  reducing the synchronous `t=4` gain.

Cold start loses: ~190 ms including worker loading/first hash versus ~152 ms sequential. Warm hashes
were ~92-94 ms versus ~115-116 ms. Use only for warm, latency-sensitive `p=1` work, preferably
`t >= 3`. It spends four cores for a 1.2-1.33x latency gain and is poor for total throughput.

Do not normally combine it with lane workers; oversubscription erases the gain. For many independent
hashes, use a bounded job pool instead.

## Remaining directions

- Prefetching cannot deliver a large gain. Argon2d addresses are data-dependent. Argon2i and early
  Argon2id addresses are predictable, but JavaScript has no prefetch hint and memory is only ~13%.
- WebGPU lacks a concrete 64-bit integer scalar, so BlaMka needs paired halves and limb
  multiply-high. One hash exposes too little parallel work. It may help large batches, not
  single-hash latency; no implementation was justified by these results.
- Re-run shape/code-generation searches when engines materially change; register allocation,
  inlining, and optimization size limits may move.

## Priority

1. Implement lane workers for `p >= 2`.
2. Consider an opt-in warm intra-block pool only for `p = 1` latency.
3. Test explicit `P()` call sites plus a callback-free fast path; expect 1-3%.
4. Keep compact four-chain `P()` as the default.

## Validation

Every variant was checked across Argon2d/i/id, multiple parameter shapes including `p = 4`, and
independently cross-checked vectors. Main timings used paired runs, warm-ups, forced GC, and medians.
