import babel from 'rollup-plugin-babel'

const jsy_preset =  [ "jsy/lean", { no_stage_3: true, modules: false } ]
const babel_plugin = babel({
  babelrc: false,
  presets: [ jsy_preset ],
  plugins: [],
  exclude: 'node_modules/**',
})

const node_plugins = [babel_plugin]
const browser_plugins = [babel_plugin]

export default [
	{
		input: 'code/index.cjs.js',
		output: [
			{ file: `dist/index.js`, format: 'cjs' },
		],
    plugins: node_plugins,
	},
	{
		input: 'code/index.mjs',
		output: [
			{ file: `dist/index.mjs`, format: 'es' },
		],
    plugins: node_plugins,
	},
	{
		input: 'code/dataview.js',
    name: 'msg-fabric-packet-stream/dataview',
		output: [
			{ file: `dist/dataview.umd.js`, format: 'umd' },
		],
    plugins: browser_plugins,
	},
]
