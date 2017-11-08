import rpi_babel from 'rollup-plugin-babel'

const sourcemap = 'inline'

const external = []

const plugins = [jsy_plugin()]

export default [
	{ input: 'code/index.cjs.js',
		output: [{ file: `dist/index.js`, format: 'cjs' }],
    sourcemap, external, plugins },

	{ input: 'code/index.mjs',
		output: [{ file: `dist/index.mjs`, format: 'es' }],
    sourcemap, external, plugins },

	{ input: 'code/dataview.js',
    name: 'msg-fabric-packet-stream',
		output: [{ file: `dist/dataview.umd.js`, format: 'umd' }],
    sourcemap, external, plugins },
]




function jsy_plugin() {
  const jsy_preset = [ 'jsy/lean', { no_stage_3: true, modules: false } ]
  return rpi_babel({
    exclude: 'node_modules/**',
    presets: [ jsy_preset ],
    plugins: [],
    babelrc: false }) }
