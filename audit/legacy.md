# Legacy hashes JS optimization audit

Tested 2026-08-13 on Ryzen 9 9900X, Linux 6.12. Main benchmarks: one-shot SHA-1,
MD5, and RIPEMD-160 at `32 B / 1 MiB`. Engines: Node 26.6.0 (V8 14.6),
JavaScriptCore 2.52.5, and SpiderMonkey 128. Variance: ±3-5%. All implementations were pure
JavaScript; no WASM was loaded. A 2026-08-14 follow-up compared the new bounded RIPEMD-160
one-shot path with `@awasm/noble` on Node/V8; JSC and SpiderMonkey were not available for that
follow-up.

These are compatibility primitives. Speed does not improve their cryptographic strength: do not
use SHA-1 or MD5 where collision resistance is required, and do not choose any legacy hash for a
new protocol merely because it is fast.

## Result

SHA-1:

| Engine       |                   Before |                  Current |        Gain |
| ------------ | -----------------------: | -----------------------: | ----------: |
| V8           | 2.158 Mops / 436.9 MiB/s | 2.284 Mops / 509.4 MiB/s |  +6% / +17% |
| JSC          | 1.757 Mops / 262.5 MiB/s | 1.894 Mops / 357.3 MiB/s |  +8% / +36% |
| SpiderMonkey | 0.681 Mops / 105.6 MiB/s | 0.805 Mops / 134.2 MiB/s | +18% / +27% |

MD5:

| Engine       |                   Before |                  Current |         Gain |
| ------------ | -----------------------: | -----------------------: | -----------: |
| V8           | 1.814 Mops / 308.4 MiB/s | 2.211 Mops / 623.3 MiB/s | +22% / +102% |
| JSC          | 1.225 Mops / 111.8 MiB/s | 1.792 Mops / 370.7 MiB/s | +46% / +232% |
| SpiderMonkey |  0.709 Mops / 95.5 MiB/s | 0.895 Mops / 155.2 MiB/s |  +26% / +63% |

RIPEMD-160:

| Engine       |                   Before |                  Current |    Gain |
| ------------ | -----------------------: | -----------------------: | ------: |
| V8           | 1.417 Mops / 167.9 MiB/s | 1.419 Mops / 168.4 MiB/s | 0% / 0% |
| JSC          | 1.364 Mops / 159.0 MiB/s | 1.363 Mops / 158.7 MiB/s | 0% / 0% |
| SpiderMonkey |  0.419 Mops / 37.8 MiB/s |  0.420 Mops / 37.9 MiB/s | 0% / 0% |

Those rows describe the stateful compressor, which remains unchanged. For the reported
`FILTER=ripemd160 node benchmark/thirdparty/hashes.ts` case, the bounded one-shot path changed the
median 32-byte call from `748 ns` to `281 ns` (`2.66x` throughput). `awasm-js` measured `307 ns`,
so Noble moved from 2.4x slower to about 8% faster. At 10 MiB Noble remained `175 MiB/s` and
awasm-js measured `648 MiB/s`; long inputs deliberately retain the portable stateful compressor.

The gap had two causes. Noble spent about `235 ns` constructing a fresh class, buffer, and view,
then ran the table/group-dispatched stateful compressor. The awasm JS target reuses module memory
and spells all 160 left/right operations into generated code. Its RIPEMD target is `71,017` raw
bytes, lazily reserves about `10.49 MiB`, and its consumer-facing selected export was previously
measured at `12,782` bytes gzip. It is a useful throughput ceiling, not a size-equivalent design.

At 10 MiB, SHA-1 gained `+21.0% / +36.0% / +27.5%`, MD5 gained
`+102.9% / +230.6% / +62.2%`, and unchanged RIPEMD-160 remained within noise on V8 / JSC /
SpiderMonkey.

The algorithms expose different optimization surfaces:

- SHA-1 uses RFC 3174's 16-word circular schedule and four fixed boolean/constant phases;
- MD5 emits four fixed operations per phase-loop iteration, resolving rotations and lane movement;
- RIPEMD-160 keeps its stateful compressor because faster V8/SpiderMonkey forms caused a severe
  JSC tier cliff, while ordinary one-shot inputs through 55 bytes use a bounded fixed-group core;
- buffering, endian conversion, length encoding, finalization, cloning, HMAC, and PBKDF2 remain on
  the shared stateful path.

Profiles attributed 95.4% of SHA-1 and 98.3% of RIPEMD-160 V8 ticks to `process()`. A diagnostic
MD5 profile attributed about 94% to compression and round helpers. Traversal was under 1% where
separately visible.

## Shipped wins

| Change                                                       |                                 Result |
| ------------------------------------------------------------ | -------------------------------------: |
| Replace SHA-1's 80-word schedule with a 16-word rolling ring |          `+17% / +36% / +27%` at 1 MiB |
| Split SHA-1 into four fixed phases                           |     removes round branches and helpers |
| Execute four straight MD5 operations per phase iteration     |        `+102% / +232% / +63%` at 1 MiB |
| Resolve MD5 rotations and lane movement at each call site    | removes table and destination dispatch |
| Add a bounded RIPEMD-160 one-block one-shot core             |     `748 ns -> 281 ns`; beats awasm-js |
| Retain RIPEMD-160's existing compressor                      |    avoids the JSC giant-function cliff |
| Preserve stateful padding, counters, output, and cloning     |   lifecycle and consumer compatibility |
| Keep typed schedule scratch and wipe it                      |   no retained message-derived schedule |
| Generate and byte-check selected SHA-1/MD5/RIPEMD regions    |      auditability without runtime cost |

The SHA-1 recurrence is RFC 3174 method 2:
`W[t & 15] = rotl1(W[(t-3)&15] ^ W[(t-8)&15] ^ W[(t-14)&15] ^ W[t&15])`. MD5 retains its typed
16-word block and runtime K table; the generator fixes phase/lane wiring and asserts the RFC K,
rotation, and message-index tables. This bounded form keeps most fully static throughput without
its 33-36% tree-shaken gzip cost.

Bundle cost against 2.3.0:

| Export               | Before min / gzip | Current min / gzip |          Growth |
| -------------------- | ----------------: | -----------------: | --------------: |
| Complete `legacy.js` |     7340 / 3201 B |     10774 / 4126 B | +46.8% / +28.9% |
| `sha1`               |     4525 / 2136 B |      5031 / 2176 B |  +11.2% / +1.9% |
| `md5`                |     4601 / 2176 B |      5310 / 2378 B |  +15.4% / +9.3% |
| `ripemd160`          |     5280 / 2505 B |      7658 / 3253 B | +45.0% / +29.9% |

The RIPEMD follow-up alone changes the post-SHA-1/MD5 whole module from `8532 / 3444` to
`10774 / 4126` bytes minified/gzip (`+25.8% / +19.8%`) and the tree-shaken RIPEMD export from
`5417 / 2552` to `7658 / 3253` (`+41.4% / +27.5%`). SHA-1 and MD5 tree-shaken gzip changes by
only 2 bytes because the RIPEMD wrapper guards are scoped inside its pure factory.

## Rejected single-thread changes

| Change                                                     |                                           Result |
| ---------------------------------------------------------- | -----------------------------------------------: |
| SHA-1 phase split with the 80-word schedule                |                           only `+6% / +5% / +1%` |
| Fully generate SHA-1's recursive 80 rounds                 |                        excessive source/JIT cost |
| Ordinary-array or scalar-local SHA-1 schedule              | weaker wipe/type shape or register-pressure risk |
| Repeated direct MD5 message reads                          |                   each word is reused four times |
| Fully static/preloaded MD5                                 |       663 / 434 / 237 MiB/s; +33-36% export gzip |
| Giant typed-message RIPEMD-160                             |      448 / 7 / 180 MiB/s; catastrophic JSC cliff |
| Giant scalar-preload RIPEMD-160                            |   554 / 8 / 213 MiB/s; same cliff, larger source |
| Interleaved fixed RIPEMD-160                               |                  426 / 7 / 199 MiB/s; same cliff |
| Reuse or capture an exported class compressor for one-shot |                  demonstrated reentry corruption |
| Change shared `HashMD.update` traversal                    |        compressor dominates; broad consumer risk |
| Remove schedule wiping or input/output validation          |          security, lifecycle, and API regression |
| Split one digest across workers                            |            chaining makes standard hashes serial |

A compact one-shot prototype improved typical 32-byte throughput by 43-102%, but grew final whole
gzip by about 18% and was incorrect. Its captured compressors still used shared `SHA1_W`, `MD5_W`,
and `BUF_160`; a crafted length getter could patch `DataView.prototype.getUint32`, reenter while
scratch was live, and return a wrong digest for all three algorithms. It could also turn a
supported-path `RangeError` into a digest.

The rejected prototype would have needed a lexical compressor accepting explicit disjoint
scratch, a strict callback-free plain-`Uint8Array` gate, captured decode/copy/output intrinsics,
fresh output, and cleanup in `finally`. It must explicitly define compatibility with
exported-prototype mutations.

The new RIPEMD-only path implements that requirement without capturing the exported class. It
uses a separate 16-word schedule, fixed boolean expressions in ten bounded loops, indexed
callback-free little-endian decoding, fresh output, and indexed cleanup in `finally`. Buffers,
subclasses, cross-realm views, proxies, forged typed-array brands, own metadata, and inputs longer
than 55 bytes fall back before scratch is leased. Stateful streaming, cloning, HMAC, and PBKDF2
continue to use `_RIPEMD160`. Eligible ordinary one-shot calls no longer observe mutations to
`_RIPEMD160.prototype`; callers needing the exported stateful behavior can use `.create()`.

The common eligibility/fallback policy is documented in the
[shared short one-shot wrapper audit](./one-shot.md); RIPEMD retains its own schedule and cleanup.

Small, unshipped candidates:

| Change                                         |                                  Result |
| ---------------------------------------------- | --------------------------------------: |
| Extend the RIPEMD direct path through 119 B    | second padded block; size/tiering proof |
| SHA-1 x2/x4 ring and expression sweep          |    compact; needs all-engine tier proof |
| Further factor MD5's four fixed operations     |   may reduce gzip while retaining speed |
| Bounded RIPEMD groups, lanes, or split callees |   may remove dispatch without JSC cliff |
| Packed `hashMany` API                          | ownership amortization and possible ILP |

## Independent-message batching and workers

All three compressors are serial within one standard digest. Workers or independently hashing
slices change the result; scatter/gather chunks remain one logical serial message.

A persistent Node `worker_threads` prototype, measured with the pre-optimization core, produced:

| Algorithm / batch             |     1 worker |    2 workers |    4 workers |
| ----------------------------- | -----------: | -----------: | -----------: |
| SHA-1, independent 32 B       | 1.978 Mmsg/s | 3.831 Mmsg/s | 6.831 Mmsg/s |
| SHA-1, independent 1 MiB      |  447.0 MiB/s |  878.2 MiB/s | 1324.5 MiB/s |
| MD5, independent 32 B         | 1.745 Mmsg/s | 3.515 Mmsg/s | 6.288 Mmsg/s |
| MD5, independent 1 MiB        |  309.2 MiB/s |  605.7 MiB/s | 1200.6 MiB/s |
| RIPEMD-160, independent 32 B  | 1.295 Mmsg/s | 2.591 Mmsg/s | 4.688 Mmsg/s |
| RIPEMD-160, independent 1 MiB |  167.8 MiB/s |  318.2 MiB/s |  634.8 MiB/s |

Two workers scaled nearly linearly and four reached 2.9-3.9x. Production support would need a
bounded reusable pool, transfer/copy policy, output ordering, errors, cancellation, and sequential
fallback. Remeasure against the current compressors before proceeding.

## Remaining directions

- Keep SHA-1's phase-split ring; revisit wider unrolling only when engines materially change.
- Search smaller MD5 factoring only if it preserves speed and reduces tree-shaken size.
- Remeasure the bounded RIPEMD-160 one-shot core on JSC and SpiderMonkey; reject any tier cliff.
- Extend the RIPEMD one-shot path past 55 bytes only if the second-block path earns its size.
- Revisit SHA-1/MD5 one-shot hashing only after the same disjoint-scratch, reentry, callback,
  cleanup, and compatibility requirements are met.
- Start independent-message work with synchronous packed `hashMany`; use workers only for large
  batches.
- Keep security guidance independent of performance. RFC 6151 and RFC 6194 restrict MD5 and SHA-1
  use in new protocols and collision-resistant applications.

## Priority

1. Keep SHA-1's phase-split ring, MD5's four-operation loops, and RIPEMD-160's stateful compressor.
2. Preserve `HashMD` padding, counters/output, lifecycle, cloning, HMAC/PBKDF2, and schedule wiping.
3. Keep the RIPEMD direct path bounded, disjoint from stateful scratch, and strict about inputs.
4. Consider packed independent-message batching before workers; neither accelerates one digest.

## Validation

SHA-1, MD5, and the RIPEMD one-shot core passed generator `--check`. The stateful compressors also
passed arbitrary-state differentials, random and adversarial blocks, unaligned views,
modulo-`2^32` edges, and schedule/round assertions. The unchanged stateful RIPEMD compressor was
checked against the baseline and awasm JavaScript.

Public tests covered dense lengths and padding boundaries, offsets, split streaming, cloning,
lifecycle, output guards/tails, one-shot ownership, strict-gate fallbacks, forged metadata/brands,
and reentry after the stateful RIPEMD schedule was populated. Official vectors, Node, the old
implementation, and 7,803 awasm differentials supplied independent oracles. The final tree passed
build, all 709 tests, all 12 checks, focused formatting, generator `--check`, and `git diff --check`.
Timings used isolated CPU-pinned processes, extensive work-count warmup, digest verification,
alternating launch order, and medians.
