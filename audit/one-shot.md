# Shared short one-shot wrapper audit

Tested 2026-08-14 on Ryzen 9 9900X, Linux 6.12, Node 26.6.0 / V8 14.6. JSC and
SpiderMonkey were not available for this follow-up. All implementations were pure JavaScript.

## Result

The hardened wrapper policy used by SHA-224/256, RIPEMD-160, fixed-output SHA3/Keccak, and default
BLAKE2s now lives in `src/utils.ts` as `_wrapShortHash`. Algorithm-specific padding, compression,
scratch leasing, reentry allocation, serialization, and cleanup remain in their original modules.

| 32-byte one-shot |   Before | Shared wrapper | Change |
| ---------------- | -------: | -------------: | -----: |
| SHA-256          | 249.3 ns |       248.6 ns |  -0.3% |
| RIPEMD-160       | 252.8 ns |       251.8 ns |  -0.4% |
| SHA3-256         | 767.4 ns |       768.7 ns |  +0.2% |
| BLAKE2s          | 118.5 ns |       118.8 ns |  +0.3% |

The changes are within measurement noise. Measurements used warmed processes and medians of nine
baseline or eleven final samples. The shared wrapper performs the same intrinsic same-realm plain
`Uint8Array` gate, validates bytes, applies an inclusive length cutoff, optionally requires
`opts === undefined`, calls the original stateful fallback, and copies/freezes its public metadata.

## Size

`bismar -bsm ./sha2.js ./legacy.js ./sha3.js ./blake2.js` changed the four-family selection from
`54883 / 17154` to `53890 / 16907` bytes minified/gzip: `-993 / -247` bytes (`-1.8% / -1.4%`).

| Tree-shaken export | Before min / gzip | Shared min / gzip |      Delta |
| ------------------ | ----------------: | ----------------: | ---------: |
| `sha256`           |      10834 / 5032 |      10894 / 5055 |  +60 / +23 |
| `ripemd160`        |       7658 / 3253 |       7719 / 3270 |  +61 / +17 |
| `sha3_256`         |       9700 / 3814 |       9761 / 3835 |  +61 / +21 |
| `blake2s`          |      17181 / 3999 |      17242 / 4014 |  +61 / +15 |
| `sha512`           |      11427 / 5474 |      11269 / 5416 | -158 / -58 |

Single direct-hash entries pay roughly 15-23 gzip bytes for the shared helper, while combined
consumers deduplicate the policy. SHA-512 shrinks because the old SHA-256 module-level guard
constants no longer leak into SHA-512-only bundles. SHAKE, raw `keccakP`, BLAKE2b, SHA-1, and MD5
remain unchanged within bismar's 1-2 byte variance.

## Boundary

The shared layer intentionally does not lease scratch or accept cleanup callbacks. A generic
`withScratch` helper would add hot callbacks and obscure ownership across incompatible state shapes:
a 16-word SHA schedule, a 200-byte sponge, and BLAKE2s's word buffer plus scalar state record. Each
direct implementation therefore keeps its arithmetic outside the lexical `try/finally`, leases
private storage on reentry, and wipes its own exact state.

Centralizing only policy also gives one place to audit constructor-before-input-access fallback.
Proxies fail `ArrayBuffer.isView` before `getPrototypeOf`; Buffer, subclasses, cross-realm or forged
views, and own metadata use the original stateful wrapper. BLAKE2s additionally sends every supplied
options object, including `{}`, to its configured stateful constructor.

## Validation

The complete 711-test suite and 12 repository checks passed. Coverage includes all direct-path
boundaries, unaligned input, output ownership, options, exotic and forged views, prototype mutation,
forced reentry and exceptions, and scratch restoration. Type checking, build, formatting, and the
SHA3, BLAKE2, and legacy generators passed. The only check warnings are two pre-existing long
comments in `src/argon2.ts`.
