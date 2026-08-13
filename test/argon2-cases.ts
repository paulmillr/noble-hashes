export type Argon2Case = {
  passwordLen: number;
  saltLen: number;
  secretLen?: number;
  dkLen: number;
  t: number;
  p: number;
  m: number;
};

const BASE: Argon2Case = {
  passwordLen: 32,
  saltLen: 16,
  dkLen: 32,
  t: 1,
  p: 1,
  m: 8,
};

// A compact boundary/pairwise matrix. Every entry is unique and each expensive axis is varied
// independently, so the scheduled cross-test does not multiply unrelated costs together.
export const ARGON2_CASES: Argon2Case[] = [
  { ...BASE },
  { ...BASE, passwordLen: 0, saltLen: 8, dkLen: 4 },
  { ...BASE, passwordLen: 1, saltLen: 9, secretLen: 0, dkLen: 16 },
  { ...BASE, passwordLen: 64, saltLen: 32, secretLen: 1, dkLen: 33 },
  { ...BASE, passwordLen: 256, saltLen: 64, secretLen: 8, dkLen: 64 },
  { ...BASE, passwordLen: 1024, saltLen: 256, secretLen: 257, dkLen: 128 },
  { ...BASE, passwordLen: 64 * 1024, saltLen: 1024, secretLen: 1024, dkLen: 512 },
  { ...BASE, passwordLen: 256 * 1024, saltLen: 64 * 1024, secretLen: 64 * 1024 },
  { ...BASE, t: 2, p: 2, m: 16 },
  { ...BASE, t: 4, p: 3, m: 24 },
  { ...BASE, t: 8, p: 4, m: 32 },
  { ...BASE, t: 32, p: 1, m: 64 },
  { ...BASE, p: 16, m: 128 },
  { ...BASE, m: 1024 },
  { ...BASE, m: 4096, dkLen: 1024 },
];

export function patternedBytes(bytes: Uint8Array, len: number): Uint8Array {
  return Uint8Array.from({ length: len }, (_, i) => bytes[i % bytes.length]);
}

export function argon2Inputs(c: Argon2Case) {
  const password = patternedBytes(Uint8Array.of(1, 2, 3, 4, 5), c.passwordLen);
  const salt = patternedBytes(Uint8Array.of(6, 7, 8, 9, 10), c.saltLen);
  const secret =
    c.secretLen === undefined
      ? undefined
      : patternedBytes(Uint8Array.of(11, 12, 13, 14, 15), c.secretLen);
  return { password, salt, secret };
}
