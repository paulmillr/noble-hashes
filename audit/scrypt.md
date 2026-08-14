# scrypt JS optimization audit

Tested 2026-08-14 on Ryzen 9 9900X, Linux 6.12. Main benchmark:
`scrypt(password, salt, { N: 16384, r: 8, p: 1, dkLen: 32 })`; lower is better. Engines: Node
26.6.0 (V8 14.6), JavaScriptCore 2.52.5, and SpiderMonkey 128. Library candidates were pure
JavaScript. WASM was used only for a separately labeled external comparison.

## Result

| Engine       | Predecessor | Scalar final |   Gain |
| ------------ | ----------: | -----------: | -----: |
| V8           |   24.483 ms |    21.368 ms | +14.6% |
| JSC          |   25.888 ms |    25.196 ms |  +2.7% |
| SpiderMonkey |   43.247 ms |    37.470 ms | +15.4% |

“Predecessor” already includes copyless first-pair BlockMix, x8 phase-2 xor, and the private
PBKDF2(`c = 1`) orchestrator. The earlier portable-core landing gained
`+3.6% / +2.6% / +3.3%`; composing ratios gives approximate original-pre-work to final gains of
`+18.7% / +5.4% / +19.2%`. Absolute times from the two harnesses are not mixed.

The scalar gain remains positive across geometry:

| Case                |     V8 |   JSC | SpiderMonkey |
| ------------------- | -----: | ----: | -----------: |
| `N=2^20, r=8, p=1`  | +15.5% | +1.0% |       +15.2% |
| `N=16384, r=1, p=1` |  +0.5% | +0.5% |        +0.3% |
| `N=8192, r=8, p=2`  | +13.2% | +3.6% |       +14.6% |

The long-`N` V8 row used the exact final source. JSC/SpiderMonkey used the same `r = 8` scalar core
with an earlier `r === 1` selector; the final `r < 4` selector only affects small `r`, but an
exact-final-source long-`N` rerun remains a provenance gap. Scalar async performance was not timed.

The main change is scalar-carry BlockMix for `r >= 4`: keep its 16-word chaining state in locals,
emit Salsa20/8 in the same function, and execute two straight double rounds inside a two-iteration
loop. At `r = 8` this removes the helper boundary and 15 intermediate 64-byte reloads. Smaller `r`
uses the compact baseline core because scalar code regressed JSC at `r = 2`.

A V8 `N = 2^20` profile showed why: the engine refused to inline `XorAndSalsa` into BlockMix,
leaving 33,554,432 helper calls. Fill was the gap versus generated awasm JavaScript; random mix and
zeroization were already tied.

## Shipped wins

| Change                                               |                                     Result |
| ---------------------------------------------------- | -----------------------------------------: |
| Scalar-carry BlockMix for `r >= 4`                   | `+14.6% / +2.7% / +15.4%` at practical `N` |
| Read BlockMix's initial chaining block directly      |        removes one 16-word copy and branch |
| Hoist the random-V base and xor eight words per loop |              portable sync/async core gain |
| Use a scrypt-local PBKDF2(`c = 1`) orchestrator      |      -1,066 raw / -409 gzip; speed neutral |
| Preserve one V reused across sequential `p` lanes    |         exact `128*r*(N+p+1)` maxmem model |
| Preserve one progress point per BlockMix             | callbacks and `asyncTick = 0` remain exact |
| Keep all buffers and counters call-local             |        reentrant and concurrent-async safe |

The required `4*N*r*p` Salsa applications, phase-2 `B xor V[j]`, password-dependent reads, two
PBKDF2 stages, and RFC output permutation remain unchanged. Integerify still uses the low word of
the final 64-byte block; big-endian hosts still swap around ROMix. A generated region plus
`test/misc/unrolled-scrypt.js --check` fixes the Salsa schedule and rotations.

The local `c = 1` helper reuses canonical HMAC/SHA-256 rather than adding another hash core. It
preserves allocation order, full `U1` then final truncation, dynamic `hmac.create`, canonical
`sha256` identity, mutable input timing, and otherwise-unused clone property reads. It gets no
speed credit: same-core practical-`N` runs stayed within ±0.4%.

Scalar specialization bundle cost versus the predecessor:

| Entry               | Before min / gzip | Current min / gzip |          Growth |
| ------------------- | ----------------: | -----------------: | --------------: |
| Complete sync+async |    17152 / 7300 B |     22133 / 8127 B | +29.0% / +11.3% |
| Sync                |    16333 / 7032 B |     21300 / 7853 B | +30.4% / +11.7% |
| Async               |    16599 / 7148 B |     21568 / 7974 B | +29.9% / +11.6% |

Against the original pre-work complete entry, final growth is `+24.0% / +7.1%`; against 2.3.0 it
is `+80.1% / +55.4%`, still below 2x. Complete ESKDF grows `+22.7% / +9.1%` versus its predecessor
because it retains generic PBKDF2 for another export.

## Rejected single-thread changes

Practical-`N` deltas are V8 / JSC / SpiderMonkey:

| Change                                   |                     Result |
| ---------------------------------------- | -------------------------: |
| Fuse phase-2 xor into BlockMix           |   `-0.5% / -19.1% / +1.3%` |
| Share one fused Salsa helper             | `-11.5% / -14.1% / -44.3%` |
| Early scalar carry with shared helper    |   `+11.5% / -3.5% / +5.7%` |
| Change work arrays to `Int32Array`       |   `-8.0% / -5.9% / -29.2%` |
| Ping-pong phase 2 between B/tmp          |    `+0.2% / -0.3% / -1.4%` |
| Execute two Salsa double rounds per loop |    `+1.1% / +0.7% / -3.4%` |
| Fully unroll Salsa                       |   `-3.1% / -17.2% / -2.3%` |
| Inline rotate arithmetic alone           |    `+2.9% / -1.1% / +1.1%` |
| Split a callback-free path               |            lost up to 6.6% |

The retained scalar form succeeds because it combines local `s/y/x` state, an in-function Salsa
body, direct rotates, two double-round bodies, and a small-`r` fallback. Full unrolling still
regressed JSC. Multiple V arrays, default `p`-lane batching, or reusable global workspace were
rejected because they change maxmem, multiply resident memory, or break reentrancy.

At `N = 2^20` on V8, the final candidate was 0.74% faster than `@awasm/noble`'s explicit
JavaScript target and produced the same output. Predecessor Noble was faster on JSC and tied on
SpiderMonkey, so awasm's generated batching is not a universal replacement. Its separate WASM
target was 41% faster than the predecessor on V8; that is an external comparator, not shipped,
initialized, bundled, or used by this implementation.

## Parallel lanes and workers

One ROMix lane is serial: fill chains BlockMix outputs, and phase-2 addresses depend on prior
output. The `p` lanes are independent but Noble processes them sequentially with one V. Parallel
lanes require about `p` V arrays and therefore a different maxmem/API contract.

A baseline persistent-worker sweep for independent derivations at `N=16384, r=8, p=1` produced:

| Workers |    1 |    2 |     4 |     8 |    12 |    24 |
| ------- | ---: | ---: | ----: | ----: | ----: | ----: |
| Jobs/s  | 41.0 | 76.5 | 135.0 | 224.7 | 301.6 | 340.9 |

RSS reached about 1.35 GB at 12 workers and 2.63 GB at 24; startup rose from 20.7 to 65.1 ms.
Production support needs a bounded reusable pool, explicit memory accounting, ordering,
cancellation, ownership, error propagation, and wiping. Per-call workers are inappropriate.

## Cleanup status

Successful calls and synchronous progress-callback throws wipe B, V, and tmp; output is distinct.
The `c = 1` helper destroys HMAC templates/clones and cleans `u` on normal completion.

Existing cleanup is not exception-complete: later allocation failure can strand B, and final-HMAC
or unexpected ROMix/scheduler/built-in errors can bypass cleanup. The speed patch preserves these
error points and does not claim arbitrary-exception erasure. A staged outer `try/finally` around a
try-free ROMix helper remains separate hardening work. JavaScript wiping is best effort; scalar
locals, VM copies, caller buffers, swap, and dumps remain outside guarantees.

## Security and parameter recalibration

The implementation computes the same RFC 7914 function with unchanged `N`, `r`, `p`, Salsa rounds,
and PBKDF2 work. Applications may benchmark and raise parameters only in a versioned format;
changing them changes the derived key. Package speedup is not a direct security-loss ratio because
attackers use native, GPU, FPGA, or custom implementations.

`maxmem` guards persistent workspace, not peak RSS or CPU time. Memory is roughly
`r*(N+p+1)` while work is `r*N*p`; attacker-controlled parameters can create extreme CPU cost even
within the memory sum. Use fixed/versioned parameters and rate limits. `scryptAsync` is cooperative
microtask scheduling without cancellation and is not a DoS boundary.

[RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) and the
[scrypt paper](https://www.tarsnap.com/scrypt/scrypt.pdf) describe its sequential memory-hard goal.
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) gives CFRG guidance for Argon2id; new
password-storage designs should evaluate modern memory-hard choices while retaining scrypt for
interoperability where required.

## Remaining directions

- Harden staged allocation and final-HMAC cleanup separately, then benchmark the lifecycle cost.
- Reconsider `c = 1` helper placement if reducing combined ESKDF size becomes a goal.
- Re-run the `r = 4` threshold and Salsa loop shape as engines change.
- Add workers or parallel `p` lanes only behind an explicit API with a different memory,
  cancellation, progress, and wiping contract.

## Priority

1. Keep scalar-carry BlockMix for `r >= 4` and the compact small-`r` fallback.
2. Keep copyless first-pair BlockMix and the x8 phase-2 xor loop.
3. Keep the canonical local PBKDF2(`c = 1`) orchestrator, measuring combined consumers separately.
4. Preserve one-V accounting, exact progress, HMAC identity, input timing, endian conversion, and
   call-local state.
5. Treat exception-complete cleanup and workers as separate lifecycle/API projects.

## Validation

The predecessor suite passed 708/708. Scalar differential testing added 738 assertions covering
RFC vectors, 500 random sync cases, 90 async cases, Node comparisons, exact progress/errors, and 48
concurrent calls. Another Node harness added 2,085 systematic/random offset, UTF-8, mutation,
maxmem, lifecycle, and concurrency assertions.

Cross-engine predecessor tests passed 141/141 cases on each engine; independent scalar review
repeated all 738 cases and confirmed the long-`N` gains and neutral small-`r` dispatch. Dedicated
checks preserved canonical HMAC identity, allocation/cleanup order, callback reentry, mutable input
timing, maxmem errors, and known exception-cleanup gaps. Generator `--check`, types, and formatting
pass; no WASM code was copied into Noble.
