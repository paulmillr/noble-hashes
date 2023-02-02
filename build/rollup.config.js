import resolve from '@rollup/plugin-node-resolve';

export default {
  input: './rollup-spec.js',
  output: {
    file: './noble-hashes.js',
    format: 'umd',
    name: 'nobleHashes',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve({ browser: true })],
};
