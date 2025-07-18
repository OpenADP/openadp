import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import nodePolyfills from 'rollup-plugin-polyfill-node';

export default {
  input: 'src/ocrypt.browser.js',
  output: {
    file: 'dist/ocrypt.browser.js',
    format: 'es',
    sourcemap: true
  },
  plugins: [
    nodePolyfills({
      include: ['crypto', 'buffer', 'util', 'stream', 'process', 'os', 'path']
    }),
    resolve({
      browser: true,
      exportConditions: ['browser'],
      preferBuiltins: false,
      alias: {
        'crypto': 'crypto-browserify',
        'buffer': 'buffer',
        'os': 'os-browserify/browser',
        'path': 'path-browserify'
      }
    }),
    commonjs(),
    json()
  ],
  external: ['@noble/hashes/sha256', '@noble/hashes/hkdf']
}; 