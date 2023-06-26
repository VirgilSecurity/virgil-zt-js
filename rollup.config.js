import typescript from '@rollup/plugin-typescript';

export default {
	input: 'index.ts',
	output: {
		dir: './example/backend/node_modules/build',
		format:  'cjs'
	},
	plugins: [typescript()]
}
