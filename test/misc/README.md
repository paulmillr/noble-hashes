# misc

Miscellaneous items that can be useful when developing or testing.

`unrolled-` files generate optimized hash permutations and compression functions from compact,
spec-derived schedules.

`unrolled-argon2.js` generates the current interleaved Argon2 permutation. Run it with `--check`
to ensure the generator and `src/argon2.ts` stay in sync.

`unrolled-blake3.js` generates the current fully unrolled BLAKE3 compression. Run it with
`--check` to ensure the generator and `src/blake3.ts` stay in sync.

`unrolled-blake1.js` generates the fixed BLAKE-384/512 schedule and the fully unrolled
BLAKE-224/256 compression. It verifies the BLAKE submission's SIGMA rows and constants; run it
with `--check` to ensure the generator and `src/blake1.ts` stay in sync.

`unrolled-blake2.js` generates the fixed BLAKE2b round schedule and the statically scheduled
BLAKE2s compression. It verifies the RFC 7693 SIGMA rows; run it with `--check` to ensure the
generator and `src/blake2.ts` stay in sync.

`unrolled-sha3.js` generates the current statically scheduled Keccak-p[1600] permutation. It
derives and verifies the FIPS 202 Iota, Rho, and Pi schedules; run it with `--check` to ensure the
generator and `src/sha3.ts` stay in sync.

`unrolled-legacy.js` generates the grouped SHA-1 and MD5 compression loops. It independently
checks the SHA-1 rolling schedule and the RFC 1321 constants, shifts, and message indices; run it
with `--check` to ensure the generator and `src/legacy.ts` stay in sync.

`sha2-constants.js` derives the split SHA-512 round constants from the FIPS 180-4 cube-root
definition. Run it with `--check` to ensure the generated constants in `src/sha2.ts` stay in sync.

`pbkdf2-sha2.js` derives and checks the fixed SHA-256 / SHA-512 PBKDF2 feedback geometry used by
the numeric feedback-round accelerators in `src/sha2.ts`.

`unrolled-scrypt.js` generates the scalar-carry Salsa20/8 BlockMix used for common `r >= 4`
parameters. Run it with `--check` to ensure the generated core in `src/scrypt.ts` stays in sync.
