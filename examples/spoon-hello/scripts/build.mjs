#!/usr/bin/env node
import * as esbuild from 'esbuild'
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill'
import { mkdirSync, copyFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const clientPath = join(root, '../../web/net/lib/browser-net-client.js')

mkdirSync(join(root, 'dist'), { recursive: true })

await esbuild.build({
  entryPoints: [join(root, 'web/main.jsx')],
  bundle: true,
  outfile: join(root, 'dist/main.js'),
  format: 'esm',
  platform: 'browser',
  jsx: 'automatic',
  sourcemap: true,
  plugins: [
    nodeModulesPolyfillPlugin({
      globals: { process: true, Buffer: true }
    })
  ],
  alias: {
    'browser-net-shim': clientPath
  }
})

copyFileSync(join(root, 'web/index.html'), join(root, 'dist/index.html'))

console.log('spoon-hello: wrote dist/main.js and dist/index.html')
