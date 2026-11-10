# SHA3 JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmark: one-shot SHA3-256
hashing of `32 B / 1 MiB`; results below use Mops/s / MiB/s. Engines: Node 26.6.0
(V8 14.6), JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%. Every
implementation and prototype was pure JavaScript; no WASM was initialized or measured.

## Result

| Engine         |                  Before |                  Current |          Gain |
| -------------- | ----------------------: | -----------------------: | ------------: |
| V8             | 0.420 Mops / 64.8 MiB/s | 0.815 Mops / 161.8 MiB/s |  +94% / +150% |
| JavaScriptCore | 0.546 Mops / 85.6 MiB/s | 1.126 Mops / 228.8 MiB/s | +106% / +167% |
| SpiderMonkey   | 0.181 Mops / 27.9 MiB/s |  0.301 Mops / 53.7 MiB/s |   +67% / +92% |

### 2026-08-14 fixed-output one-shot follow-up

Fixed-output SHA3 and Keccak now use a closed one-rate-block path for ordinary same-realm
`Uint8Array` inputs shorter than the variant's rate. A nine-sample alternating V8 comparison at 32
bytes measured SHA3-256 at `771.1 ns` direct versus `1136.1 ns` through
`.create().update().digest()`: `1.47x` as many operations, or `32.1%` lower latency. Three runs of
`FILTER=sha3_256 node benchmark/thirdparty/hashes.ts` measured the shipped wrapper at `824 / 838 /
845 ns` (median `838 ns`) and `181 / 182 / 182 MiB/s` at 10 MiB. The large-input result is unchanged
within noise because rate-sized and longer messages retain the stateful path.

The direct path owns its 200-byte state inside the fixed-hash factory, uses the existing generated
24-round permutation, returns a fresh output, and wipes every state byte in `finally`. Reentry gets
private state. A strict intrinsic gate keeps Buffer, subclasses, proxies, cross-realm and forged
typed arrays, own metadata, and all rate-sized/longer inputs on the old stateful path. SHAKE, XOF,
streaming, add-on hashes, and public `Keccak` / `keccakP` behavior are unchanged.

The common eligibility/fallback policy is documented in the
[shared short one-shot wrapper audit](./one-shot.md); SHA3 retains its sponge-state lease and wipe.

The final paired check used fresh processes, pinned CPU 11, nine alternating samples per case, and
verified every digest before timing. The gain transfers to SHAKE128 and streaming XOF output: at 1
MiB, the generated core improved absorb throughput by `+142% / +169% / +80%` and squeeze throughput
by `+151% / +161% / +80%` on V8 / JSC / SpiderMonkey.

Further universal single-thread improvement is constrained by **engine-specific representation
tradeoffs, not surrounding sponge code**:

- before this change, permutation arithmetic was 96.6% of V8's 1 MiB profile; update, cleanup, and
  wrapper code together were under 2.2%; a no-op permutation raised throughput from 70.6 MiB/s to
  5386 MiB/s;
- after this change, the generated permutation is 97.1% of the same profile, so a 10% faster core
  would improve the whole hash by approximately 9.7%;
- the best typed-state schedule wins on V8 and JSC, while a 50-local state is approximately 2x
  faster on SpiderMonkey but 28-40% slower on V8/JSC;
- no tested arithmetic shape beats the shipped schedule on all three engines.

Measured with `bismar -bsm ./sha3.js` against a built 2.3.0 archive, the `sha3_256` bundle grows
from 6389 / 2752 bytes to 8972 / 3498 bytes minified / gzip: `+40.4% / +27.1%`. The complete
`sha3.js` bundle grows `+37.4% / +25.3%`. Hardcoded Iota words remove runtime BigInt setup, so import
plus first hash was 6-40% faster rather than paying a cold-start penalty.

Relative to that immediately preceding optimized build, the one-shot follow-up changes the
tree-shaken `sha3_256` bundle from `8972 / 3498` to `9700 / 3814` bytes minified/gzip (`+8.1% /
+9.0%`) and complete `sha3.js` from `9460 / 3689` to `10197 / 4006` (`+7.8% / +8.6%`). Keeping its
state inside `genKeccak` leaves SHAKE-only and `keccakP` bundles unchanged.

### 2026-11-09 arm64 follow-up

Tested on Apple M5 Pro with Node 26.10.0 (V8) and system JavaScriptCore; method, bundle tables,
branch-drift caveats, and the JSC pitfall are in [arm64.md](./arm64.md). The plane-by-plane /
early-parity generator listed under "Remaining directions" was built and is now the shipped core.

| Case (V8 / JSC)     |           2.4.0 |         before |        after | after / 2.4.0 |
| ------------------- | --------------: | -------------: | -----------: | ------------: |
| sha3_256 32 B       |  1.76 / 1.67 µs | 949 ns / 41 µs | 518 / 496 ns | 3.40x / 3.39x |
| sha3_256 1 MiB      | 12.16 / 9.78 ms |    6.70 / 5.62 |  3.65 / 3.22 | 3.33x / 3.09x |
| turboshake128 1 MiB |  5.08 / 3.88 ms |    2.86 / 2.33 |  1.60 / 1.32 | 3.18x / 2.96x |
| kmac256 32 B        |  6.14 / 4.33 µs |    3.96 / 2.83 |  1.53 / 1.09 | 4.01x / 3.96x |

| Change                                                                               |                          Result |
| ------------------------------------------------------------------------------------ | ------------------------------: |
| Plane-by-plane rounds: Theta, Rho, Pi into ten locals per plane, Chi into the output |               ~1.8x over before |
| Early parity: next round's column parities accumulated while Chi stores              |          no separate Theta pass |
| Two round bodies per loop iteration, alternating caller state and a module buffer    | `s -> t -> s`; odd count copies |
| All permutation reads through `Int32Array` views                                     |             JSC 41 µs -> 496 ns |
| sha3-addons: safe-integer length encoding, shared zero pad, KMAC precomputed prefix  |               kmac256 32 B 2.6x |

The shared module buffer is reentrancy-safe because the permutation never runs caller code, and
it is zeroed before every return. Subclasses that replace `state` / `state32` (as `_KMAC`'s clone
does) are followed through an `Int32Array` view of the same buffer. In `before`, JSC's SHA3-256 at
32 B ranged from 801 ns to 40 µs per process because the generated permutation read `Uint32Array`
words and kept deoptimizing; the `Int32Array` views remove that entirely.

The addons change encodes lengths with `%` and `/` by 256 on safe integers, falling back to BigInt
only past `Number.MAX_SAFE_INTEGER`; KMAC without a customization string reuses the sponge state
after absorbing `bytepad(encode_string("KMAC") || encode_string(""), rate)`, kept per rate.

#### Size/speed frontier

gzip bytes of the tree-shaken `sha3_256` export; speeds versus 2.4.0 as V8 / JSC.

| Variant                                             | gzip | vs 2.4.0 |          32 B |         1 MiB |  kmac256 32 B |
| --------------------------------------------------- | ---: | -------: | ------------: | ------------: | ------------: |
| 2.4.0                                               | 2821 |          |               |               |               |
| 2.4.0 permutation, cheaper plumbing                 | 2598 |   -223 B | 1.01x / 1.03x | 1.00x / 1.00x | 1.65x / 1.57x |
| compact two-pass loop                               | 2750 |    -71 B | 1.31x / 1.39x | 1.36x / 1.38x | 2.02x / 1.98x |
| two-pass loop, Chi in locals                        | 2881 |    +60 B | 1.40x / 1.66x | 1.47x / 1.78x | 2.22x / 2.66x |
| straight-line permutation, no short path            | 3436 |   +615 B | 2.58x / 2.61x | 3.34x / 3.09x | 3.93x / 4.01x |
| straight-line + short path, deduplicated round body | 3781 |   +960 B | 3.47x / 3.30x | 3.36x / 3.12x | 3.99x / 4.23x |
| `after`                                             | 4095 |  +1274 B | 3.42x / 3.37x | 3.31x / 3.08x | 4.05x / 4.07x |

Other exports for the same rows, gzip: `keccakP` 1237 / 1091 / 1194 / 1319 / 1847 / 1847 / 2161;
`kmac256` 3252 / 3126 / 3218 / 3413 / 3993 / 3993 / 4306. Full-length results also covered
SHA3-512, SHAKE256 64 KiB XOF, TurboSHAKE128 at 32 B and 1 MiB, and KT128; the ratios track the
SHA3-256 rows within a few percent, except KT128 at 32 B where `after` is 2.2x / 2.3x.

- Deduplicated round body: `after`'s two round bodies are textually different because the second
  writes to different names. Writing both under the same block-scoped names (`a`, `b`) lets gzip
  store the second body as a back-reference, and deriving Iota with the FIPS 202 LFSR in `Number`
  arithmetic at import replaces the 48 emitted words. Speed is identical and it is 314 B smaller
  than `after`; the saving was verified with esbuild/bismar only, not terser.
- The compact loops reach 1.3-1.8x and are smaller than 2.4.0, but the only step beyond them is the
  straight-line permutation at +555 B over the best loop. The compact two-pass loop relies on
  variable shift counts, which the 2026-08 pass found weak on x64.

#### Applied on `speedup-pareto` (2026-11-09)

The straight-line + short path, deduplicated round body row is applied on the branch rebased onto
2.4.0. The permutation still runs two rounds per loop iteration (`s -> t -> s`), but both round
bodies are emitted as the same text: each sits in its own block with `const a = <src>, b = <dst>`,
reads `a[...]`, writes `b[...]`, and `round` is incremented between them so both index Iota with
`[round]`. The 48 emitted Iota words are replaced by the FIPS 202 rc() LFSR run once at import in
`Number` arithmetic into two `Int32Array(24)`; the generator re-derives them with BigInt and checks
both halves against the official table. Int32Array views, the short-input path and the sha3-addons
changes are unchanged. The saving holds with terser as well as esbuild: terser keeps the block
aliases and gives both bodies the same mangled names. gzip for `sha3_256` / `keccakP` / `kmac256`:
4140 / 2170 / 4375 before, 3825 / 1857 / 4061 after with esbuild (bismar), and 3899 / 1914 / 4155 to
3577 / 1600 / 3828 with terser. Speed equals the previous tree on V8 and JSC (0.98-1.01 at 32 B,
1 MiB and KMAC256 32 B), and JSC per-process timings at 32 B stay unimodal at 565-706 ns. A
48,146-check differential against `node:crypto` and the previous implementation found no mismatch.
Regenerate or verify with `node test/misc/unrolled-sha3.js [--check]`.

## Shipped wins

| Change                                                                    |                                Result |
| ------------------------------------------------------------------------- | ------------------------------------: |
| Statically spell Theta column parity and diffusion                        |      V8 `+25% / +33%` at 32 B / 1 MiB |
| Statically spell the fixed Rho rotations and Pi lane cycle                |   V8 `+23% / +29%`; JSC `+44% / +52%` |
| Keep the 24-round loop and partially in-place Chi                         |        best portable size/speed shape |
| Emit verified 32-bit Iota constants instead of generating BigInts at load |       smaller gzip and faster startup |
| Remove the shared permutation scratch array                               | reentrant core; no persistent scratch |
| Generate the core from FIPS 202 schedules and check it byte-for-byte      |         auditability; no runtime cost |
| Close fixed-output one-rate-block hashing around the generated core       |        SHA3-256 `1.47x` at 32 B on V8 |

The shipped form mutates the existing 50-word `Uint32Array` state and statically specializes the
fixed work inside each round. The round loop remains dynamic so the public `keccakP` API and
TurboSHAKE/KangarooTwelve can execute the last `1..24` rounds exactly. This follows the five FIPS
202 mappings while preserving the library's split-u32 lane representation. See [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202),
the [Keccak implementation overview](https://keccak.team/files/Keccak-implementation-3.2.pdf), and
the canonical [XKCP](https://github.com/XKCP/XKCP).

## Rejected single-thread changes

| Change                                                            |                                                            Result |
| ----------------------------------------------------------------- | ----------------------------------------------------------------: |
| Keep dynamic Theta loops, Rho/Pi table reads, and rotate dispatch |                 baseline; permutation arithmetic is 96.6% of time |
| Put all 50 state words in scalar locals for every permutation     |     V8 -31%; JSC -40%; SpiderMonkey +102% at 1 MiB versus shipped |
| Load/store locals every 1 / 2 / 4 rounds                          |   balanced variants were larger and slower; 4-round SM tier cliff |
| Execute two-round local groups through an inner loop              |         engines did not unroll it; dominated by static scheduling |
| Hold only Rho/Pi output in scalar locals                          |        118 / 213 / 77 MiB/s on V8 / JSC / SM; slower than shipped |
| Fully duplicate all 24 rounds                                     | excessive source/JIT size; grouped forms deoptimized at 6+ rounds |
| Duplicate a fixed 24-round function beside reduced rounds         |                            approximately +1%; large gzip increase |
| Factor-2 bit-interleaved lanes                                    |                 V8 near neutral; JSC 226 -> 86; SM 50 -> 49 MiB/s |
| Lane-complementing transform                                      |    V8 +1%; JSC +4%; SM -2%, with larger code and boundary hazards |
| Full-row scalar capture for Chi                                   |          slower and larger than retaining four original row words |
| `Int32Array` state                                                |                     severe regressions in typed-state experiments |
| Pure-JS js-sha3 / StableLib layouts                               |                slower on V8/JSC; StableLib wins SpiderMonkey only |
| Runtime `new Function` specialization                             |                  fast historically; rejected for CSP/auditability |
| Remove public permutation validation                              |                            0-3%; not worth a second semantic path |
| Remove scratch cleanup from the old core                          |            +0-2%; obsolete once the shared scratch was eliminated |
| Dedicated one-shot large-input sponge path                        |                      surrounding-work ceiling is approximately 2% |

Bit interleaving is useful in some native 32-bit implementations, but ordinary-to-interleaved and
back conversion erased its 13% raw-core V8 gain. Its raw core was already slower on JSC and
SpiderMonkey, and keeping state permanently interleaved would duplicate absorb/extract logic and
change the exposed state convention. Lane complementing likewise did not reproduce the native
instruction savings: JavaScript already expresses `~x & y` compactly, while the complemented
representation adds entry/exit and auditing costs.

Fresh-process pure-JS comparisons at 1 MiB measured generated / js-sha3 / StableLib as 165 / 81 /
124 MiB/s on V8, 228 / 100 / 166 on JSC, and 50 / 52 / 71 on SpiderMonkey. StableLib reinforces
the engine split, but its separate high/low state and bytewise adapter are not an API-equivalent
replacement for the exposed Keccak state and streaming class.

Small, unshipped candidates:

| Change                                      |                                         Expected result |
| ------------------------------------------- | ------------------------------------------------------: |
| Engine-specific 50-local SpiderMonkey build | approximately 2x over the portable core; separate build |
| Plane-by-plane / early-parity generator     |   unmeasured; official next scalar scheduling direction |
| Fused fast-loop absorb with state locals    |   likely small outside specialized fixed-rate workloads |

These require a fresh V8, JSC, and SpiderMonkey sweep. A marginal improvement in one engine is not
enough to replace the portable default.

## Independent-message worker parallelism

SHA3 absorption is serial: every message block depends on the state produced by the preceding
permutation. Workers therefore cannot accelerate one standard SHA3 digest. A pure-JS Node
`worker_threads` prototype instead distributed independent messages through a persistent pool.

| Batch                 | Sequential | 2 workers | 4 workers | 8 workers |
| --------------------- | ---------: | --------: | --------: | --------: |
| 32768 messages × 32 B |   39.35 ms |  19.58 ms |   9.88 ms |  10.01 ms |
| 32 messages × 1 MiB   |  184.02 ms |  92.20 ms |  47.91 ms |  43.07 ms |
| 8 messages × 10 MiB   |  452.36 ms | 228.68 ms | 119.12 ms |  93.28 ms |

Two and four workers scale nearly linearly for sufficiently large batches. Eight workers saturate
on tiny messages and reach 4.85x on the 80 MiB batch. Pool creation took 19-42 ms, and one 32-byte
message through a warm pool cost approximately 0.08-0.12 ms versus 0.0012 ms directly. This belongs
in an opt-in batch API with a persistent bounded pool, transferable inputs, ordering/error handling,
and a sequential fallback; it does not belong in the synchronous hash core.

With four workers, structured clone / transfer / shared-memory handoff reached 614 / 668 / 707
MiB/s for the 1 MiB batch. Clone preserves ownership but copies input, transfer detaches the caller's
backing buffer, and shared memory requires immutability until completion; browser shared memory also
requires cross-origin isolation.

## Remaining directions

- The official implementation overview describes plane-by-plane scheduling and early parity. A
  generator could test whether they reduce typed-state traffic without creating the 50-local
  engine split.
- Standard SHA3 is a serial sponge. ParallelHash and KangarooTwelve expose algorithm-level tree
  parallelism, but substituting either changes the function and digest; independent-message workers
  are the only transparent parallel path.
- Explicit SIMD is unavailable in portable ECMAScript. With WASM excluded, WebGPU is potentially
  useful for large independent batches, not ordinary single-message latency.
- Re-run representation and code-generation searches as engine register allocation and tiering
  change. SpiderMonkey already demonstrates that the optimal state representation is engine-specific.

## Priority

1. Keep the generated typed-state round and bounded fixed-output one-shot path.
2. Re-run the one-shot path on JSC and SpiderMonkey before widening it to SHAKE options.
3. Prototype plane-by-plane / early-parity scheduling across all three engines.
4. Consider a separate async worker batch API only for many independent messages.

## Validation

All SHA3-224/256/384/512, Keccak, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash, TurboSHAKE,
KangarooTwelve, and KeccakPRG tests passed, including odd rates, unaligned updates, padding's extra
block, clone/destroy, oversized `digestInto`, multi-block XOF, and 12-round modes. An independent
BigInt-lane FIPS 202 reference checked three nonzero states for every round count `1..24`; earlier
prototype sweeps checked 1536 raw permutations. The generator independently derives Iota with the
FIPS LFSR and derives/asserts the Rho/Pi schedule before `--check` compares emitted source exactly.
Main timings used fresh processes, paired warm runs, pinned CPU affinity, nine samples, and medians.
The one-shot follow-up additionally checked every SHA3/Keccak rate boundary and unaligned offset,
output ownership, exotic and forged inputs, prototype mutation, forced reentry and exceptions, and
scratch restoration. The complete 711-test suite, 12 repository checks, build, formatting, and
permutation generator check passed.
