# PBKDF2 JS optimization audit

Tested 2026-08-13/14 on Ryzen 9 9900X, Linux 6.12. Main benchmark: synchronous
one-output-block PBKDF2-HMAC-SHA-256/SHA-512 at `c = 32768`, in millions of complete PRF rounds/s.
Engines: Node 26.6.0 (V8 14.6), JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%.
All implementations were pure JavaScript; no WASM was loaded.

## Result

| Engine       | SHA-256 before | SHA-256 current |    Gain | SHA-512 before | SHA-512 current |   Gain |
| ------------ | -------------: | --------------: | ------: | -------------: | --------------: | -----: |
| V8           |        1.708 M |         2.782 M |  +62.9% |        0.519 M |         0.619 M | +19.2% |
| JSC          |        1.112 M |         1.931 M |  +73.6% |        0.363 M |         0.591 M | +62.9% |
| SpiderMonkey |        0.491 M |         1.313 M | +167.3% |        0.202 M |         0.363 M | +79.9% |

After `U1`, every PBKDF2 feedback input is exactly one digest. From keyed HMAC midstates, each
SHA-256 inner/outer leg is one fixed padded block at total length 96 bytes; SHA-512 is one block at
192 bytes. The optimized loop keeps `U` and XOR accumulator `T` in words, runs those fixed
compressions, and serializes only at output or generic fallback.

The fast path is deliberately narrow:

- exact canonical SHA-256/SHA-512 wrappers only;
- synchronous calls require `c >= 1000`;
- asynchronous calls also require `asyncTick > 0`;
- `c = 1`, lower counts, zero-tick async, custom hashes, and lookalikes remain generic.

At `c = 1000`, paired gains were `+63-71% / +21-22%` on V8,
`+64-72% / +61%` on JSC, and `+161-162% / +83%` on SpiderMonkey for SHA-256 / SHA-512. Lower
cutoffs caused setup losses and engine-tier cliffs. Keeping `c = 1` generic avoids regressing both
PBKDF2 stages used by scrypt.

## Shipped wins

| Change                                                   |                                      Result |
| -------------------------------------------------------- | ------------------------------------------: |
| Cache actual HMAC inner/outer numeric midstates          |              preserves mutable IV/key setup |
| Use fixed one-block SHA-256 feedback compressions        |     removes generic machinery from `U2..Uc` |
| Use fixed one-block split-u32 SHA-512 compressions       | smaller gain; u64 emulation still dominates |
| Keep `U` and `T` in words across rounds                  |            serializes once per output block |
| Reuse call-local state/schedule arrays                   |         reentrant and concurrent-async safe |
| Wipe schedules at async boundaries and all state on exit |        no retained key-equivalent midstates |
| Dispatch through a private exact-wrapper WeakMap         |        generic hash API stays hash-agnostic |
| Guard all hash prototype descriptors after SHA-2 import  |                  mutations safely fall back |
| Snapshot word state on async invalidation                |      generic loop resumes at the next round |
| Skip specialization below the measured crossover         |           no low-count or scrypt regression |

`U1` remains generic, preserving arbitrary password/salt lengths and existing configuration,
padding, and tree semantics. Dispatch uses exact exported function identity; aliases may
specialize, while proxies, copied/bound wrappers, configured hashes, or another package copy do
not. Post-import replacement, deletion, shadowing, or prototype-chain changes trigger fallback.

Positive-tick async performs one PRF per scheduler callback and revalidates descriptors after each
actual Promise resume. On invalidation it serializes `U/T`, wipes fast arrays, and continues with
generic clones. Zero-tick async stays wholly generic because validating after every yield costs
more than the accelerator saves.

Bundle cost against 2.3.0:

| Entry                | Before min / gzip | Current min / gzip |          Growth |
| -------------------- | ----------------: | -----------------: | --------------: |
| PBKDF2 + SHA-256     |     9001 / 3914 B |     14558 / 6310 B | +61.7% / +61.2% |
| PBKDF2 + SHA-512     |    11918 / 5226 B |     15154 / 6767 B | +27.2% / +29.5% |
| PBKDF2 + both hashes |    14042 / 6187 B |     21310 / 8860 B | +51.8% / +43.2% |
| Generic `pbkdf2.js`  |     5105 / 2071 B |      5585 / 2303 B |  +9.4% / +11.2% |
| Complete `sha2.js`   |    11762 / 5533 B |     18598 / 8000 B | +58.1% / +44.6% |

All remain below 2x. Canonical standalone SHA wrappers retain factory/guard code because they may
be passed to PBKDF2; this also grows current scrypt gzip by 17.9% despite its generic `c = 1` path.

## Rejected single-thread changes

| Change                                          |                                            Result |
| ----------------------------------------------- | ------------------------------------------------: |
| Rehash ipad/opad or use `hash.chunks([pad, U])` |             repeats work HMAC already precomputes |
| Reset generic HMAC states only                  |    still finalizes and serializes twice per round |
| Apply SHA-256's one-shot wrapper                |                  PBKDF2 uses stateful `.create()` |
| Specialize hashes by shape/name                 |                forgeable; breaks custom semantics |
| Expose a public marker/factory on hash wrappers |              observable API and tree-shaking cost |
| Import SHA-2 directly from generic PBKDF2       |           dependency cycle and forced bundle cost |
| Accelerate `c = 1` or low counts                |      no feedback work or setup/tiering regression |
| Accelerate `asyncTick = 0`                      |                   descriptor scans erase the gain |
| Add SHA-224/384/512-t or other hash cores       |                   poor size and compatibility ROI |
| Interleave two output blocks by default         | helps only `dkLen > hLen`; nearly duplicates core |
| Automatically lower or raise caller `c`         |         changes derived keys and interoperability |
| Share keyed scratch or remove wiping            |             secret retention and concurrency bugs |
| Use native crypto, WebCrypto, or WASM           |                    different API/deployment model |

SHA-224/384 and SHA-512/224/256 have different digest lengths, IVs, padding, and truncation.
Parameterization is possible, but each registered wrapper adds bundle and guard/threshold/fallback
coverage. They remain correct through the generic RFC 8018 path.

## Independent output blocks and workers

One PBKDF2 chain is serial: `U_j = PRF(P, U_(j-1))`. Different output blocks `T_i` and independent
derivations can run in parallel, but ordinary 256/512-bit derived keys use one block.

A real two-lane core would duplicate state and interleave schedules. The analogous SHA-2
independent-message experiment gained about 9% on V8/JSC and 18% on SpiderMonkey, insufficient for
the source/register cost here. A baseline persistent Node worker pool reached about 3.8x with four
workers at `c = 10000`; remeasure against the optimized core before proceeding.

Production batching would need a bounded pool, ordering, errors/cancellation, password/salt copy
policy, worker state wiping, browser fallback, and transfer/shared-memory rules. Per-call worker
creation is inappropriate.

## Security and iteration recalibration

The optimization computes the same RFC 8018 function and does not reduce `c`, but it lowers local
wall time. Applications that chose `c` for a latency budget should benchmark the final version and
may raise it when their stored format permits. The library must never adjust it automatically.

Attackers already use native, GPU, or custom implementations, so this package's speed ratio is not
a direct security-loss ratio. PBKDF2 remains CPU-hard and parallel across guesses; scrypt and
Argon2id address a different, memory-hard cost dimension. Avoid presenting one timeless iteration
number or PBKDF2 as a universal replacement for memory-hard password hashing.

The fixed-block proof follows [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html),
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html), and
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final). HMAC midstates, `U`, and `T` are
treated as secrets and explicitly wiped, subject to JavaScript VM/JIT best-effort limits.

## Remaining directions

- Base the cutoff on total feedback work if multi-block workloads justify more complexity.
- Revisit two-lane sync only with real `dkLen > hLen` usage and all-engine evidence.
- Explore reducing SHA-only/scrypt bundle externality without public markers or generic-PBKDF2
  imports.
- Re-run thresholds and compressor shapes as engine tiering changes.
- Consider a separate persistent-worker API only for independent derivations or unusually long
  multi-block outputs.

## Priority

1. Keep exact SHA-256/SHA-512 specialization above the measured cutoff.
2. Keep `c = 1`, low counts, zero-tick async, and every other hash generic.
3. Preserve exact identity dispatch, descriptor fallback, call-local state, and complete wiping.
4. Recalibrate application iteration policies and async timing tests after the speedup.
5. Revisit more hashes, lanes, workers, and bundle architecture only with usage evidence.

## Validation

The final suite passed 708/708 plus build, checks, and the fixed-geometry checker. Existing tests
cover RFC 7914, ACVP, Node differentials, password/salt mutation timing, generic hashes and XOFs,
`c = 1` yielding, scrypt, cutoff boundaries, output lengths, UTF-8, and concurrent async calls.

Independent review added 3,656 Node assertions and 408 JSC/SpiderMonkey exact-versus-generic
comparisons. Dedicated gate/lifecycle tests proved the cutoff and zero-tick paths allocate no fast
arrays, accelerated paths wipe every observed private array, descriptor/prototype invalidation
falls back after actual awaits, and `U1`/later failures clean up. The checker independently derives
fixed digest/padding/length positions; no WASM module was imported, initialized, or measured.
