# Changelog for noble-hashes

## 2.4.0 (2026-08-27)

### Security and correctness

- Protect passed options against mutation / pollution
- keccakprg: fail until entropy is added
- webcrypto: reject output sizes which crashed engine
- blake3: fix tree merging for multi-terabyte streams
- Improve zeroization

### Misc

- Speed-up Argon2 by 20%
- Argon2 cost options are now optional. The defaults are `t: 3`, `m: 1024 ** 2` KiB (1 GiB), `p: 1`, `dkLen: 32`, and a 1 GiB `maxmem` limit; larger-memory calls must set `maxmem` explicitly.
- Corrected scrypt's default `maxmem` to work for `N: 2 ** 20`, `r: 8`, and `p: 1`
- `nextTick` and `asyncLoop` now yield through `scheduler.yield()` when available or `setTimeout` otherwise, allowing timers, I/O, and rendering to progress. They also accept optional rejection cleanup; async Argon2, PBKDF2, and scrypt use it to wipe work state if scheduling is aborted.

## 2.3.0 (2026-08-06)

### Performance

- Improved 32-byte input performance across all hashes by 10–45%.
- Improved SHA-3 and SHAKE by 40%, one-megabyte KangarooTwelve, MarsupilamiFourteen, and TurboSHAKE by 50%, and KMAC by 20%.
- Improved Argon2 performance by 2.2×.
- Improved PBKDF2 and HKDF performance by 20%.

### Other changes

- Added better error messages and stricter type checks throughout the package.
- Fixed `HMAC._cloneInto` so it preserves `canXOF` in issue #134, reported by [@ChALkeR](https://github.com/ChALkeR), and corrected an Argon2d typo in issue #135.
- Renamed `blake2.compress` to the internal `_compress` method.
- Reduced unpacked on-disk size from 869 KB to 665 KB by disabling less-relevant source maps.

## 2.2.0 (2026-04-11)

- **March 2026 self-audit** (all files): no major issues found.
  - Audited for specification compliance and security.
  - Fixed `dkLen=0` handling in `pbkdf2`, `blake2`, `turboshake`, and `kt`.
  - Fixed `parallelHash` with `blockLen=0`.
  - Made the `argon2` progress callback reach 100%.
  - Changed `digestInto` to return no value for better performance.
  - Added support for non-four-divisible `dkLen` values in `argon2` and `blake2`.
- Fixed all byte-array types for compatibility with both TypeScript 5.6 and TypeScript 5.9+.
  - TypeScript 5.6 uses `Uint8Array`, while TypeScript 5.9+ made it generic as `Uint8Array<ArrayBuffer>`.
  - This previously caused incompatibilities and errors such as `TS2345`.
  - See [TypeScript issue #62240](https://github.com/microsoft/TypeScript/issues/62240) for more context.
- Sped up SHA-3 by as much as 50%, contributed by [@ChALkeR](https://github.com/ChALkeR) in [pull request #126](https://github.com/paulmillr/noble-hashes/pull/126).
- Fixed compilation issues on TypeScript 6.
- Added big-endian support; all tests pass on s390x.
- Improved tree-shaking and reduced bundle sizes.
- Added extensive documentation throughout the package.
- Skipped version 2.1 to align with the other noble packages.

## 2.0.1 (2025-09-22)

- Required the `.js` extension for all module imports.
  - Old: `@noble/hashes/sha3`.
  - New: `@noble/hashes/sha3.js`.
  - This simplifies native browser use without transpilers.
  - The change was planned for 2.0.0 but accidentally omitted.
- Declared exported submodules in `package.json` to support TypeScript autocompletion.
- Fixed the scrypt `maxmem` error message, contributed by [@ChALkeR](https://github.com/ChALkeR) in [pull request #121](https://github.com/paulmillr/noble-hashes/pull/121).
- Sped up scrypt by 4%, contributed by [@ChALkeR](https://github.com/ChALkeR) in [pull request #122](https://github.com/paulmillr/noble-hashes/pull/122).

## 2.0.0 (2025-08-25)

### High-level changes

- Made the package ESM-only. ESM can be loaded from CommonJS on Node.js 20.19 and later.
  - Node.js 20.19 is now the minimum required version.
  - Package imports now work correctly in bundler-free environments such as browsers.
  - Reduced npm package download size from 152 KB to 136 KB.
  - Reduced unpacked on-disk size from 1.1 MB to 669 KB.
- Reduced bundle sizes compared with version 1.
- Required the `.js` extension for all module imports.
  - Old: `@noble/hashes/sha3`.
  - New: `@noble/hashes/sha3.js`.
  - This simplifies native browser use without transpilers.

### API changes

- Restricted hash inputs to `Uint8Array` and prohibited `string` inputs.
  - Strict validation improves security.
  - Use `utils.utf8ToBytes` to reproduce the previous behavior.
- Renamed or removed modules for consistency.
  - `sha256` and `sha512` → `sha2.js`.
  - `blake2b` and `blake2s` → `blake2.js`.
  - `ripemd160`, `sha1`, and `md5` → `legacy.js`.
  - `_assert` → `utils.js`.
  - Removed the internal `crypto` module in favor of built-in WebCrypto.
- Improved TypeScript types and option autocompletion.
- Upgraded the TypeScript compilation environment to TypeScript 5.9 and ES2022.
- Made error messages substantially more descriptive.

## 1.8.0 (2025-04-21)

### Preparation for version 2

This release contains fixes and improvements that pave the way for version 2.

- Made modules available with a `.js` extension.
  - Old: `@noble/hashes/sha2`.
  - New: `@noble/hashes/sha2.js`.
  - The old path remains available.
  - This simplifies native browser use without transpilers.
- Refactored core functionality and removed duplicate code.
- Reduced package size.

### Deprecations

Several modules were renamed for clearer grouping. The old names remain available but deprecated to ease migration:

- `sha256` and `sha512` → `sha2`.
- `_assert` → `utils`.
- `blake2b` and `blake2s` → `blake2`.
- `ripemd160` and `sha1` → `legacy`.

## 1.7.2 (2025-04-14)

- Added an MD5 implementation to the new `legacy` module.
- Moved SHA-1 to `legacy`, retaining the old alias until the next major release.
- Made `randomBytes` ensure a `Uint8Array` result on older Node.js versions.
- Used built-in `Uint8Array.toHex` and `Uint8Array.fromHex` [when available](https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex), giving a 13× speedup for 256-byte arrays and a 20× speedup for 32 KB arrays.
- Made the TypeScript source runnable without compilation on Node.js 24 through [`erasableSyntaxOnly`](https://devblogs.microsoft.com/typescript/announcing-typescript-5-8/#the---erasablesyntaxonly-option).

## 1.7.1 (2025-01-18)

- Implemented BLAKE1, an SHA-3 proposal.
- Enabled TypeScript `verbatimModuleSyntax` in preparation for native Node.js type stripping.
- Improved documentation.

## 1.7.0 (2025-01-03)

- Published the package on [JSR](https://jsr.io/@noble/hashes).
- Enabled TypeScript [`isolatedDeclarations`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-5.html#isolated-declarations), simplifying generated documentation and related tooling.
- Added extensive comments to improve autocompletion, code generation, and general code comprehension.
- Removed some exports from the internal `_assert` module.

### New contributors

- [@quentinadam](https://github.com/quentinadam) made their first contribution in [pull request #103](https://github.com/paulmillr/noble-hashes/pull/103).

## 1.6.1 (2024-11-24)

- Fixed Argon2 initialization.
- Included `d.ts.map` files in the package.

## 1.6.0 (2024-11-22)

- Added support for arrays larger than 4 GB on supported platforms.
- Hardened and stabilized Argon2.
- Improved `isBytes` performance.
- Improved compatibility with parsers and minifiers.

### New contributors

- [@mahnunchik](https://github.com/mahnunchik) made their first contribution in [pull request #102](https://github.com/paulmillr/noble-hashes/pull/102).

## 1.5.0 (2024-09-01)

- Relaxed scrypt parameter validation to allow `{ r: 1, p: 8 }`.
- Exported additional TypeScript types.
- Added support for Node.js 14.21.3 alongside Node.js 16 and later.
- Exported SHA-224, SHA-384, SHA-512/224, and SHA-512/256 in the single-file build.

### New contributors

- [@quixoten](https://github.com/quixoten) made their first contribution in [pull request #89](https://github.com/paulmillr/noble-hashes/pull/89).
- [@legobeat](https://github.com/legobeat) made their first contribution in [pull request #94](https://github.com/paulmillr/noble-hashes/pull/94).
- [@iAchilles](https://github.com/iAchilles) made their first contribution in [pull request #92](https://github.com/paulmillr/noble-hashes/pull/92).
- [@sreyemnayr](https://github.com/sreyemnayr) made their first contribution in [pull request #99](https://github.com/paulmillr/noble-hashes/pull/99).

## 1.4.0 (2024-03-14)

- Added support for big-endian platforms, contributed by [@jonathan-albrecht-ibm](https://github.com/jonathan-albrecht-ibm) in [pull request #81](https://github.com/paulmillr/noble-hashes/pull/81).
- Added an XOF constructor wrapper for cSHAKE, contributed by [@stknob](https://github.com/stknob) in [pull request #82](https://github.com/paulmillr/noble-hashes/pull/82).
- Renamed `_sha2` to `_md`.
- Reduced duplicate code in `utils` and `_assert`.
- Changed the TypeScript module target to `Node16`.

## 1.3.3 (2023-12-11)

- Added the `sha2` module as an alias for the existing `sha256` and `sha512` modules.
- Implemented [TurboSHAKE](https://eprint.iacr.org/2023/342) in `sha3-addons`.
- Improved utilities:
  - Sped up `hexToBytes` sixfold and improved its error formatting.
  - Made `isBytes` more reliable in environments such as jsdom.
  - Made `concatBytes` validate input types earlier.
- Upgraded the build to TypeScript 5.3.2.

## 1.3.2 (2023-08-23)

- Improved tree-shaking:
  - Annotated top-level invocations as pure.
  - Used constant enums.
  - Reduced wildcard imports from `_assert` and `_u64`.
  - Declared the package side-effect-free.
- Fixed Argon2 validation for the parallelism and iterations parameters.
- Fixed `isPlainObject` in serverless environments, as used by scrypt and PBKDF2.
- Disabled the viral TypeScript `moduleResolution` setting.

### New contributors

- [@jeetiss](https://github.com/jeetiss) made their first contribution in [pull request #65](https://github.com/paulmillr/noble-hashes/pull/65).
- [@Systemcluster](https://github.com/Systemcluster) made their first contribution in [pull request #69](https://github.com/paulmillr/noble-hashes/pull/69).

## 1.3.1 (2023-06-03)

### Changes

- Fixed `utf8ToBytes` in Firefox extension contexts ([Firefox issue 1681809](https://bugzil.la/1681809)).
- Made BLAKE3 inputs immutable, contributed by [@libitx](https://github.com/libitx) in [pull request #51](https://github.com/paulmillr/noble-hashes/pull/51).
- Added pure annotations to `sha3-addons` to reduce bundle size.
- Harmonized `utils` with noble-curves.
- Fixed types:
  - Fixed the XOF type in SHA-3 and BLAKE3, closing issue #55.
  - Exported the HMAC type, fixing issue #52.
  - Removed the `cryptoNode` dependency on `@types/node`.

### New contributors

- [@pkieltyka](https://github.com/pkieltyka) made their first contribution in [pull request #47](https://github.com/paulmillr/noble-hashes/pull/47).
- [@libitx](https://github.com/libitx) made their first contribution in [pull request #51](https://github.com/paulmillr/noble-hashes/pull/51).
- [@janek26](https://github.com/janek26) made their first contribution.

## 1.3.0 (2023-03-16)

- Changed native cryptography imports so built-in WebCrypto is used on all platforms, including Node.js.

## 1.2.0 (2023-02-02)

- Added an [experimental Argon2 implementation from RFC 9106](https://github.com/paulmillr/noble-hashes/commit/7988e5134e519c96805e6ceeba5bb10c96023941).
- Included source maps in the package.
- Fixed an `import "_assert"` issue.

## 1.1.5 (2022-12-15)

- Added SHA-224 and SHA-512/224.

## 1.1.4 (2022-12-15)

- Fixed an SHA-2 bug.

## 1.1.3 (2022-09-30)

### Changes

- Improved HMAC type checking in worker contexts.
- Added TypeScript `types` fields to the exports map, contributed by [@jacogr](https://github.com/jacogr) in [pull request #36](https://github.com/paulmillr/noble-hashes/pull/36).

### New contributors

- [@neil-yoga-crypto](https://github.com/neil-yoga-crypto) made their first contribution in [pull request #35](https://github.com/paulmillr/noble-hashes/pull/35).

## 1.1.2 (2022-06-20)

- Added SHA-1 support.

## 1.1.1 (2022-06-11)

- Removed the viral TypeScript `esModuleInterop` option.
- Improved key-derivation functions.
- Improved performance.

## 1.0.0 (2022-01-19)

- First stable post-audit release.

## 0.1.0 (2021-10-06)

- Initial release
