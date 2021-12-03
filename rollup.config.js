import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'rollup.js',
  output: {
    file: 'build/noble-hashes.js',
    format: 'umd',
    name: 'nobleHashes',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve({ browser: true })],
};
