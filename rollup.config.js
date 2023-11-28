import typescript from '@rollup/plugin-typescript';
import nodeResolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import terser from '@rollup/plugin-terser';

export default {
	input: 'index.ts',
	output: {
		dir: './dist',
		format: 'cjs'
	},
	external: ['virgil-crypto'],
	plugins: [typescript(), nodeResolve(), commonjs(), json(), terser()],
};
