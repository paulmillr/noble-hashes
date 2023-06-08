// prettier-ignore
module.exports = [
  ['blake2b', 'blake2b'], ['blake2s', 'blake2s'], ['blake3', 'blake3'], ['hmac', 'hmac'],
  ['hkdf', 'hkdf'], ['pbkdf2', 'pbkdf2'], ['pbkdf2', 'pbkdf2Async'], ['ripemd160', 'ripemd160'],
  ['scrypt', 'scrypt'], ['scrypt', 'scryptAsync'], ['sha256', 'sha256'], ['sha512', 'sha512'],
  ['sha1', 'sha1'], ['sha3', 'sha3_224'], ['sha3', 'sha3_256'], ['sha3', 'sha3_384'],
  ['sha3', 'sha3_512'], ['sha3', 'keccakP'], ['sha3', 'keccak_256'], ['sha3', 'keccak_384'],
  ['sha3', 'keccak_512'], ['sha3-addons', 'cshake128'], ['sha3-addons', 'cshake256'],
  ['sha3-addons', 'kmac128'], ['sha3-addons', 'kmac256'], ['sha3-addons', 'k12'],
  ['sha3-addons', 'm14'], ['argon2', 'argon2id'], ['eskdf', 'eskdf'],
].map(([filename, imports]) => ({
  name: `${imports} from ${filename}`,
  path: `../esm/${filename}.js`,
  import: `{ ${imports} }`,
  running: false,
  ignore: ['@noble/hashes/crypto'],
}));

