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

### 2026-11-09 arm64 follow-up

Tested on Apple M5 Pro with Node 26.10.0 (V8) and system JavaScriptCore; method, bundle tables,
branch-drift caveats, and the JSC pitfall are in [arm64.md](./arm64.md). Main benchmark:
Argon2id `t = 1, p = 1`, 128 MiB.

| Case (V8 / JSC)     |            2.4.0 |        before |         after | after / 2.4.0 |
| ------------------- | ---------------: | ------------: | ------------: | ------------: |
| argon2id 128 MiB    | 257.8 / 249.5 ms | 191.1 / 246.7 | 169.7 / 167.0 | 1.51x / 1.49x |
| argon2id 1 MiB      |                  |               |               | 1.47x / 1.51x |
| argon2id 64 KiB     |                  |               |               | 1.57x / 1.42x |
| argon2id t=3, 8 MiB |                  |               |               |         1.60x |

`before`'s four-chain `P()` gained nothing on JSC at 128 MiB; `after` gains on both engines.

| Change                                                                                        |                                                  Result |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------: | ----------- |
| Load all 16 `P()` words into 32 u32 locals once and store once at the end                     |                                no per-quarter-round I/O |
| Fuse the block-level XORs of `G` into `P()`: rows load `R = X ^ Y` directly, park in a buffer |                                no separate 1 KiB passes |
| Column pass finishes `G` in place: `x[o..] ^= R ^ Z`, rereading the still-hot `X` / `Y`       |                               one write per output word |
| `                                                                                             | 0` on index sums so the JIT drops int32 overflow checks | small, free |
| Reuse one pristine BLAKE2b-512 hasher for the `H'` variable-length blocks                     |                               no per-block construction |
| Separate `tmp` block so `block()` outputs never overlap its inputs                            |                                       correctness guard |

"Fuse `block()` and `P()`" above fell to 10 MB/s on x64 JSC; this is a different fusion. `block()`
remains the driver, and only the 1 KiB XOR passes moved into `P()`'s loads and stores. Pass 0
writes each non-initial block once into still-zero memory, so XOR there equals overwrite, which
keeps the `0x10` version's overwrite semantics without a flag in the hot loop.

#### Size/speed frontier

The sweep was built on 2.4.0 sources, so these rows include the argon2 zeroization and scheduler
hardening that the branch is missing. gzip bytes of the `argon2id` export; speeds versus 2.4.0 as
V8 / JSC.

| Variant                                  |   min / gzip | vs 2.4.0 |         1 MiB |       128 MiB |
| ---------------------------------------- | -----------: | -------: | ------------: | ------------: |
| 2.4.0                                    | 14500 / 5824 |          |               |               |
| 2.4.0 permutation, small fixes           | 14572 / 5850 |    +26 B | 1.02x / 1.04x | 1.01x / 1.04x |
| loop-form four-chain permutation         | 18527 / 6860 |  +1036 B | 1.32x / 1.36x | 1.29x / 1.37x |
| loop-form permutation with fused XORs    | 19667 / 7296 |  +1472 B | 1.44x / 1.58x | 1.45x / 1.59x |
| `after` rebased onto 2.4.0 (full unroll) | 22301 / 7594 |  +1770 B | 1.44x / 1.58x | 1.52x / 1.51x |
| `after` as-is (missing hardening)        | 21791 / 7383 |  +1559 B | 1.47x / 1.51x | 1.44x / 1.50x |

Argon2id has no variant that is both smaller and faster than 2.4.0: the gain is the permutation
itself, and the cheapest form of it costs about 1 KB gzip. The fused loop form saves 298 B gzip
and 2.6 KB minified against the unrolled `after` for 0-4% on V8 and gains 3-6% on JSC. JSC spreads
at 1 MiB were ±14-19%.

#### Applied on `speedup-pareto` (2026-11-09)

`src/argon2.ts` is now 2.4.0 (option parsing, zeroization, per-block generator yield,
`nextTick(abort)` cleanup) with the permutation replaced by the fused loop form. `P` keeps 16 words
in 32 locals and runs one four-chain interleaved half-round twice; rows 1..3 rotate by local moves,
so the column code also does the diagonals. Row calls load `X ^ Y` and column calls finish
`out ^= X ^ Y ^ Z`. H′ reuses a pristine BLAKE2b state. Address generation uses a fourth scratch
block because `block()` outputs must not overlap its inputs, so the address scratch is 1024 words and
the scheduler-abort test expects `[1024, 2048]` whole-array wipes. The August "yield every 32
blocks" was dropped: it never yields when `segmentLen < 32`, which is why `argon2idAsync` never
yielded on the old branch, and restoring the per-block yield costs only 1-2%. Scheduler hand-offs at
`asyncTick: 0` now equal 2.4.0 exactly. `argon2id` is 19651 min / 7293 gzip (2.4.0: 5830 gzip, full
unroll: 7598). Apple M5, t=1..3, 1 MiB and 128 MiB: V8 1.44-1.55x and JSC 1.53-1.57x versus 2.4.0;
versus the full unroll, 3-5% slower on V8 and 5-8% faster on JSC. A 12,668-check differential
against 2.4.0 and OpenSSL (d / i / id, 0x10 / 0x13, t 1-4, p 1-4, m 8p to 8 MiB, six dkLens, key and
personalization, sync and async) found no mismatch, and the 100 Argon2 cases of
`test/slow-kdf.test.ts` pass, so the earlier crosstest report does not reproduce. The permutation is
generated by `test/misc/unrolled-argon2.js` between BEGIN/END markers.

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
