# 2026-11-09 arm64 follow-up

Second optimization pass on the `speedup-unroll` branch, run on Apple M5 Pro (arm64, 18 cores,
macOS 27.2) with Node 26.10.0 (V8) and the system JavaScriptCore (`jsc -m` from the
JavaScriptCore.framework helpers). SpiderMonkey and x64 hardware were not available; the 2026-08
x64 results in the sibling files were not re-measured. Everything was pure JavaScript.

Three trees are compared throughout:

- `2.4.0`: the release tag. It does not contain the 2026-08 optimization pass; the branch forked
  from `c0bb7516`, before the release;
- `before`: branch commit `64b83f45` "Speed-up everything", the 2026-08 x64 pass;
- `after`: the working tree produced by this follow-up (SHA-512, SHA-3, BLAKE3, Argon2 changes,
  described in [sha2.md](./sha2.md), [sha3.md](./sha3.md), [blake3.md](./blake3.md),
  [argon.md](./argon.md)).

## Method

- One fresh process per sample. Each sample warms up for 300 ms, then times seven 80 ms windows and
  keeps the best; the digest of the first call is printed and compared across trees.
- Trees are interleaved: in round `r` the tree order rotates by `r`, so load drift affects all trees
  equally. Reported speed-ups are medians of within-round ratios, with min/max spread.
- Other sessions kept the machine at load 4-5 during the Pareto sweep, so ratios there carry ±3-10%
  spread; the three-way 2.4.0 / before / after runs were quieter (±2-5%).
- Correctness: `npm test` (712 tests including ACVP), every `test/misc/*.js --check` generator,
  prettier, and a 27,736-case differential check of every variant against `node:crypto`,
  OpenSSL's argon2, and the baseline tree (random lengths 0-400 plus 511-1000003, byte offsets
  0/1/3, streaming splits, interleaved one-shot and stateful calls, HMAC, PBKDF2 sync/async).
- Bundle sizes: `bismar -bsm` on a `tsc` build. Per-export sizes use a one-line entry
  (`export { sha256 } from './sha2.js';`).

JavaScriptCore short-input cases are bimodal (see below), so per-process distributions, not
medians alone, were inspected for every JSC regression claim.

## Bundle size

Minified / gzip bytes:

| Entry            |         2.4.0 |         before |          after |
| ---------------- | ------------: | -------------: | -------------: |
| whole package    | 72001 / 25091 | 134259 / 36874 | 139258 / 38378 |
| `sha2.js`        |  12013 / 5571 |   18661 / 7884 |   18362 / 7749 |
| `sha3.js`        |   7137 / 3019 |   10262 / 4003 |   12477 / 4361 |
| `sha3-addons.js` |  16271 / 5436 |   17899 / 5902 |   20205 / 6308 |
| `blake3.js`      |   9297 / 3738 |   16383 / 4904 |   17959 / 5586 |
| `argon2.js`      |  15160 / 6039 |   20909 / 7006 |   22245 / 7514 |

Tree-shaken exports, gzip bytes:

| Export     | 2.4.0 | before | after |
| ---------- | ----: | -----: | ----: |
| `sha256`   |  2843 |   4972 |  4973 |
| `sha512`   |  4177 |   5315 |  5315 |
| `sha384`   |  4174 |   4022 |  4564 |
| `sha3_256` |  2828 |   3813 |  4102 |
| `keccakP`  |  1245 |   1880 |  2171 |
| `blake3`   |  3738 |   4904 |  5586 |
| `argon2id` |  5830 |   6887 |  7387 |

`before` and `after` are understated: the branch lacks thirteen `src` commits that are in 2.4.0
(see "Branch drift"), worth roughly 210 gzip bytes on `argon2id` and 40-50 bytes per SHA-3 export.

## Speed, after versus 2.4.0

Medians, V8 / JSC. `before` is included where it differs from `after`.

| Case                  |            2.4.0 |         before |         after | after / 2.4.0 |
| --------------------- | ---------------: | -------------: | ------------: | ------------: |
| sha256 32 B           |     408 / 381 ns |   254 / 224 ns |  236 / 217 ns | 1.73x / 1.71x |
| sha256 1 MiB          |   3.48 / 3.86 ms |    2.42 / 2.97 |   2.44 / 2.97 | 1.44x / 1.30x |
| sha512 32 B           |   1.11 / 1.03 µs |    1.12 / 1.04 |  665 / 778 ns | 1.66x / 1.33x |
| sha512 1 MiB          |   7.14 / 7.13 ms |    7.15 / 7.11 |   4.73 / 4.83 | 1.51x / 1.47x |
| pbkdf2-sha256 c=16384 |          9.96 ms |           4.87 |          4.87 |         2.04x |
| pbkdf2-sha512 c=4096  |   8.06 / 8.05 ms |    6.13 / 5.19 |   4.66 / 4.90 | 1.73x / 1.65x |
| sha3_256 32 B         |   1.76 / 1.67 µs | 949 ns / 41 µs |  518 / 496 ns | 3.40x / 3.39x |
| sha3_256 1 MiB        |  12.16 / 9.78 ms |    6.70 / 5.62 |   3.65 / 3.22 | 3.33x / 3.09x |
| turboshake128 1 MiB   |   5.08 / 3.88 ms |    2.86 / 2.33 |   1.60 / 1.32 | 3.18x / 2.96x |
| kmac256 32 B          |   6.14 / 4.33 µs |    3.96 / 2.83 |   1.53 / 1.09 | 4.01x / 3.96x |
| blake3 32 B           |    846 / 1240 ns |   115 / 125 ns |  107 / 108 ns | 7.83x / 11.6x |
| blake3 1 MiB          |   8.54 / 2.71 ms |    1.04 / 1.38 |   1.02 / 1.34 | 8.38x / 1.87x |
| blake3 keyed 32 B     |    980 / 1680 ns |   550 / 527 ns |  153 / 150 ns | 6.42x / 9.58x |
| argon2id m=128 MiB    | 257.8 / 249.5 ms |  191.1 / 246.7 | 169.7 / 167.0 | 1.51x / 1.49x |
| scrypt N=2^15 r=8     |                  |                |               | 1.12x / 3.86x |

JSC `sha512` 32 B is bimodal in `after` (656-951 ns per process), so its ratio is 1.33-1.56x.

Regressions versus 2.4.0 that were observed but not investigated, all introduced by `before` and
unchanged by `after`, all JSC only: BLAKE2s 1 MiB 0.64x (2.31 → 3.58 ms), BLAKE-256 1 MiB 0.80x
(3.42 → 4.27 ms), and BLAKE2s 32 B flat (289 → 286 ns) where V8 gains 6.8x. See
[blake2.md](./blake2.md). Resolved on 2026-11-10 by the loop forms below: the cause was the unrolled
bodies running slowly in JSC's top tier, not `Uint32Array` speculation.

## JavaScriptCore JIT pitfall

Three separate regressions in this pass had one cause. JSC's DFG speculates that `Uint32Array`
loads fit in int32. A word with bit 31 set then takes an Overflow OSR exit; after repeated exits the
function is stuck in Baseline and never reaches FTL. Symptoms are bimodal or 2-50x slower
short-input timings that depend on the data, so a single median hides them.

- `before` SHA3-256 at 32 B on JSC ranged 801 ns to 40 µs per process; `after` is a steady
  418-496 ns.
- BLAKE3 one-shot glue in the first `after` candidate lost 16% at 1 KiB in 17 of 20 processes.
- The SHA-512 compressor was about 10% slower with `Uint32Array` state.

The fix is to read through `Int32Array` views wherever the value is only XORed, stored, or
compared: the SHA-3 permutation and state, the BLAKE3 one-shot glue (the compressor itself keeps
seeing a single `Uint32Array` so it stays monomorphic), and the SHA-512 chaining state (including
`S.set(IV)` from an `Int32Array` copy). The 2026-08 SHA-3 audit rejected an `Int32Array` state on
x64; the new result is that the view type matters on JSC and costs nothing on V8.

## Branch drift

`git log 64b83f45..2.4.0 -- src` lists thirteen commits the branch does not have: webcrypto
snapshot options and hardening, scheduler cancellation, `utils` option parsing, keccakprg nonzero
entropy and system PRNG, blake1 message wipe, `nextTick` behavior, `utf8ToBytes` zeroization,
BLAKE3 inputs of a TiB and more, argon2/pbkdf2 zeroization, and scrypt's default `maxmem` of 1 GiB.
Confirmed consequence: on the branch, `argon2idAsync` with `m = 16 MiB, asyncTick = 1` lets zero
`setInterval` callbacks run, where 2.4.0 lets 50 through. The branch must be rebased onto `main`
before merging; conflicts are expected in `argon2.ts`, `blake3.ts`, and `utils.ts`. Every size and
speed figure for `before` and `after` should be re-taken afterwards.

Resolved on `speedup-pareto`: the August commit was rebased onto 2.4.0. Git reported conflicts in
`blake3.ts`, `pbkdf2.ts`, `scrypt.ts`, and `noble-hashes-only.test.ts`; 2.4.0 behavior was kept
wherever the two sides disagreed (full-width BLAKE3 chunk counter, PBKDF2 input wiping and
`nextTick(onReject)` abort cleanup, scrypt abort cleanup). Two regressions merged without a
conflict and were caught only by 2.4.0's tests: scrypt's private PBKDF2-HMAC-SHA256(c=1) helper
did not wipe UTF-8 password/salt copies, and Argon2's yield-every-32-blocks generator never yielded
when a segment is shorter than 32 blocks. Both now follow 2.4.0.

## Pareto frontier summary

Each primitive was swept for variants that are both smaller and faster than 2.4.0, and for the
cheapest variant that keeps `after`'s speed. Details and the unshipped variant tables are in each
primitive's file.

| Export     | Strictly better than 2.4.0                          | `after` speed for fewer bytes                        |
| ---------- | --------------------------------------------------- | ---------------------------------------------------- |
| `sha256`   | compressor only: -11 B, 1.2x / 1.4x at 32 B / 1 MiB | short path on a shared core: +791 B instead of +2130 |
| `sha512`   | array state, compressor only: -473 B, 1.3-1.5x      | -411 B at the same speed; -1327 B with derived K     |
| `sha3_256` | compact two-pass loop: -71 B, 1.3-1.4x              | -314 B at the same speed (deduplicated rounds)       |
| `blake3`   | one-round loop, no one-shot: -5 B, 2-8x on V8       | -251 B at 3-8% lower speed (two-round loop)          |
| `argon2id` | none; closest +26 B for 0-7%                        | -298 B, 0-5% slower on V8, 0-5% faster on JSC        |

Recurring cost centers that every importer pays and tree shaking cannot remove:

- PBKDF2 feedback accelerators are attached to the `sha256` / `sha512` objects through
  `pbkdf2Register`: roughly 0.7-1.0 KB gzip each, useful only to PBKDF2 callers.
- BLAKE3 keyed / derive-key / XOF one-shot support: about 950 B gzip over the default-only short
  path, useful only to MAC, KDF, and XOF callers.
- Fully unrolled compressors versus two-round loop bodies: 230 B gzip and 3.6 KB minified for
  BLAKE3, 300 B gzip and 2.6 KB minified for Argon2, 555 B gzip for the straight-line Keccak
  permutation, for 0-8% of speed on arm64.

## Applied on `speedup-pareto`

Variants chosen from the frontier and applied on top of the rebased branch, one per primitive:
SHA-256 two-round compressor with a shared-core short path and no PBKDF2 accelerator; SHA-512 array
state, short path, PBKDF2 accelerator and derived constants; SHA-3 straight-line permutation with
the deduplicated round body; BLAKE3 two-round loop with the default-options one-shot only; Argon2
loop-form permutation with fused XORs. Details and speeds are in each primitive's file. gzip bytes
from bismar on tsc builds; `before` is the rebased tree with the full November pass.

| Export     | 2.4.0 | before | final | final - 2.4.0 | final - before |
| ---------- | ----: | -----: | ----: | ------------: | -------------: |
| package    | 25091 |  39072 | 35183 |        +10092 |          -3889 |
| `sha256`   |  2843 |   5011 |  3673 |          +830 |          -1338 |
| `sha512`   |  4177 |   5360 |  4027 |          -150 |          -1333 |
| `sha384`   |  4174 |   4606 |  3330 |          -844 |          -1276 |
| `sha3_256` |  2828 |   4140 |  3825 |          +997 |           -315 |
| `kmac256`  |  3267 |   4375 |  4061 |          +794 |           -314 |
| `blake3`   |  3738 |   5630 |  4427 |          +689 |          -1203 |
| `argon2id` |  5830 |   7598 |  7293 |         +1463 |           -305 |
| `scrypt`   |  5079 |   7852 |  6501 |         +1422 |          -1351 |
| `blake2s`  |  3137 |   4023 |  4023 |          +886 |             +0 |
| `blake256` |  3304 |   4293 |  4293 |          +989 |             +0 |

`scrypt` shrinks because it imports `sha256`, which no longer carries the PBKDF2 accelerator. The
remaining package growth over 2.4.0 also includes the August BLAKE1, BLAKE2, legacy and scrypt changes,
which this pass did not revisit. The combined tree passes all 727 tests and every generator
`--check`. The per-primitive speed figures were measured while the five implementations were
benchmarked concurrently (load average up to about 90), so they should be re-measured on a quiet
machine before release.

### 2026-11-10: BLAKE2s, BLAKE-256, RIPEMD-160, scrypt

The same sweep was then run, one primitive at a time on a quiet machine (load average about 2), for
the four primitives the August pass had grown most outside the five above. gzip bytes from bismar;
"last commit" is the tree above.

| Export      | 2.4.0 | last commit |   now | now - 2.4.0 | now - last commit |
| ----------- | ----: | ----------: | ----: | ----------: | ----------------: |
| package     | 25091 |       35183 | 32204 |       +7113 |             -2979 |
| `blake2s`   |  3137 |        4023 |  3714 |        +577 |              -309 |
| `blake256`  |  3304 |        4293 |  3427 |        +123 |              -866 |
| `ripemd160` |  2584 |        3291 |  3052 |        +468 |              -239 |
| `scrypt`    |  5079 |        6501 |  5131 |         +52 |             -1370 |
| `eskdf`     |  6631 |        8662 |  8105 |       +1474 |              -557 |

- BLAKE2s and BLAKE-256: loop-form compressors reading message words through `BSIGMA`. They are
  11-27% slower than the unrolled code on V8 but still 5.1-6.6x 2.4.0 at 1 MiB, and on JSC they turn
  0.67x / 0.79x of 2.4.0 into 1.72x / 1.38x.
- RIPEMD-160: one fixed-group compressor shared by the class and a two-block one-shot path; 1 MiB
  is 1.98x 2.4.0 on V8 (was 1.0x) and 1.15x on JSC.
- scrypt: one compact scalar BlockMix for every `r`, and a private SHA-256 hasher so scrypt no longer
  bundles `sha256`'s one-shot path; speed equals the previous tree (1.09-1.14x 2.4.0 on V8).

Details, variant tables and differentials are in [blake2.md](./blake2.md),
[blake1.md](./blake1.md), [legacy.md](./legacy.md), and [scrypt.md](./scrypt.md).

## Not verified

- x64 and SpiderMonkey for every change in this pass. Loop-form compressors (BLAKE3, Argon2,
  compact SHA-3) depend on JIT register allocation and carry the most risk there.
- Big-endian hosts.
- An agent-reported `test/slow-kdf.test.ts` "argon2 crosstest" failure at branch HEAD.
- An agent-reported BLAKE3 difference between the one-shot and stateful paths for a `Uint8Array`
  with a spoofed own `length`. With own lengths 10, 100, and 2000 on a 64-byte array both paths
  behaved identically in 2.4.0, `after`, and the loop-form variants: length 10 hashes the first 10
  bytes, 100 and 2000 throw `RangeError`. Treat the report as unconfirmed.
