import babel from 'rollup-plugin-babel'

const sourcemap = 'inline'

const externals = []

const plugins = [jsy_plugin()]

export default [
	{ input: 'code/index.cjs.js',
		output: [{ file: `dist/index.js`, format: 'cjs' }],
    sourcemap, externals, plugins },

	{ input: 'code/index.mjs',
		output: [{ file: `dist/index.mjs`, format: 'es' }],
    sourcemap, externals, plugins },

	{ input: 'code/dataview.js',
    name: 'msg-fabric-packet-stream/dataview',
		output: [{ file: `dist/dataview.umd.js`, format: 'umd' }],
    sourcemap, externals, plugins },
]




function jsy_plugin() {
  const jsy_preset = [ 'jsy/lean', { no_stage_3: true, modules: false } ]
  return babel({
    exclude: 'node_modules/**',
    presets: [ jsy_preset ],
    plugins: [],
    babelrc: false }) }
