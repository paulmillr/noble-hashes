import resolve from '@rollup/plugin-node-resolve';

export default {
  input: './rollup-spec.js',
  output: {
    file: './noble-hashes.js',
    format: 'umd',
    name: 'nobleHashes',
    exports: 'named',
    generatedCode: {
      preset: 'es2015'
    }
  },
  plugins: [resolve({ browser: true })],
};
