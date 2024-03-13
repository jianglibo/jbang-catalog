// rollup.config.mjs
// import json from '@rollup/plugin-json';
import terser from '@rollup/plugin-terser';
import typescript from '@rollup/plugin-typescript';
import nodePolyfills from 'rollup-plugin-polyfill-node';
// import buble from 'rollup-plugin-buble';
// import sizes from 'rollup-plugin-sizes';
// import html from '@rollup/plugin-html';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
	input: 'src/index.ts',
	external: [],
	// (addonAttach, addonFit, addonWebLinks, xterm);
	output:
		[
			{
				file: 'public/dist/bundle.js',
				format: 'iife',
				name: 'MyBundle',
				globals: id => {
					console.log(id);
					if (id.endsWith('.cfg'))
						return "cfg";
				}
			}
			// {
			// 	file: 'dist/bundle.min.js',
			// 	format: 'iife',
			// 	name: 'version'
			// 	,
			// 	globals: {
			// 		addonAttach: 'AttachAddon.AttachAddon'
			// 	},
			// 	plugins: [terser()]
			// }
		],
	plugins: [typescript()]
};
// , html(), buble(), sizes(), json(),, nodeResolve(),nodePolyfills(),