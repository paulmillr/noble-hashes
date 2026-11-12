# misc

Miscellaneous items that can be useful when developing or testing.

`unrolled-` files generate optimized hash permutations and compression functions from compact,
spec-derived schedules.

`unrolled-argon2.js` generates the current Argon2 permutation: one four-chain interleaved half-round
run twice (columns, then diagonals via rotated locals), with the block XORs fused into its loads
and stores. Run it with `--check` to ensure the generator and the generated region of
`src/argon2.ts` stay in sync.

`unrolled-blake3.js` generates the current two-round loop BLAKE3 compression (two spelled-out
rounds run three times plus one tail round, message words permuted in locals). It verifies that
every round reads the official message schedule; run it with `--check` to ensure the generator and
`src/blake3.ts` stay in sync.

`unrolled-blake1.js` generates the fixed BLAKE-384/512 schedule and the loop-form BLAKE-224/256
compression, which reads message words through `BSIGMA` and companion constants through `B256_T`.
It verifies the BLAKE submission's SIGMA rows and constants; run it with `--check` to ensure the
generator, both tables, and `src/blake1.ts` stay in sync.

`unrolled-blake2.js` generates the fixed BLAKE2b round schedule and the loop-form BLAKE2s
compression, whose single round body reads message words through `BSIGMA`. It verifies the RFC 7693
SIGMA rows; run it with `--check` to ensure the generator, `BSIGMA`, and `src/blake2.ts` stay in sync.

`unrolled-sha3.js` generates the current plane-by-plane Keccak-p[1600] permutation (two rounds
per loop iteration as two textually identical bodies, early parity) and the load-time Iota loop. It
derives and verifies the FIPS 202 Iota, Rho, and Pi schedules; run it with `--check` to ensure the
generator and `src/sha3.ts` stay in sync.

`unrolled-legacy.js` generates the grouped SHA-1 and MD5 compression loops and the fixed-group
RIPEMD-160 compressor shared by its class and one-shot path. It independently checks the SHA-1
rolling schedule and the RFC 1321 constants, shifts, and message indices; run it with `--check` to
ensure the generator and `src/legacy.ts` stay in sync.

`unrolled-sha2.js` generates the SHA-256 two-round ring from one template for both
`SHA2_32B.process()` and the standalone `sha256Compress()` used by the short one-shot path. It also
checks the emitted `SHA256_K` table against cube roots of the first 64 primes; run it with `--check`
to ensure the generator and `src/sha2.ts` stay in sync.

`sha2-constants.js` checks the SHA-512 round constants, which `src/sha2.ts` derives at import
instead of shipping a table. Run it with `--check` to ensure all 80 words agree between the
FIPS 180-4 table, an independent cube-root derivation, and the derivation block in `src/sha2.ts`.

`pbkdf2-sha2.js` derives and checks the fixed SHA-512 PBKDF2 feedback geometry used by the numeric
feedback-round accelerator in `src/sha2.ts`. SHA-256 has no accelerator and uses the generic engine.

`unrolled-scrypt.js` generates the scalar-carry Salsa20/8 BlockMix used for every `r`: one Salsa
body per 64-byte half-block, alternating between the even and odd output halves. Run it with
`--check` to ensure the generated core in `src/scrypt.ts` stays in sync.
