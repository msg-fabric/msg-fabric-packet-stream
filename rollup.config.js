import babel from 'rollup-plugin-babel'

const externals = []

const plugins = [jsy_plugin()]

export default [
	{ input: 'code/index.cjs.js',
		output: [{ file: `dist/index.js`, format: 'cjs' }],
    externals, plugins },

	{ input: 'code/index.mjs',
		output: [{ file: `dist/index.mjs`, format: 'es' }],
    externals, plugins },

	{ input: 'code/dataview.js',
    name: 'msg-fabric-packet-stream/dataview',
		output: [{ file: `dist/dataview.umd.js`, format: 'umd' }],
    externals, plugins },
]




function jsy_plugin() {
  const jsy_preset = [ 'jsy/lean', { no_stage_3: true, modules: false } ]
  return babel({
    exclude: 'node_modules/**',
    presets: [ jsy_preset ],
    plugins: [],
    babelrc: false }) }
