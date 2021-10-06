import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'rollup.js',
  output: {
    file: 'build/noble-hashes.js',
    format: 'umd',
    name: 'nobleHashes',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve(), commonjs()],
};
