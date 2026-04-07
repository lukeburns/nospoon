#!/usr/bin/env node
/**
 * Esbuild dev server for the spoon-hello React shell.
 * Usage: npm run dev -- --port 5173 --host 127.0.0.1
 */
import * as esbuild from 'esbuild'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function parseArgs (argv) {
  let port = 5173
  let host = '127.0.0.1'
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--port' || a === '-p') {
      const v = parseInt(argv[++i], 10)
      if (!Number.isFinite(v) || v < 1 || v > 65535) {
        console.error('dev: --port must be 1–65535')
        process.exit(1)
      }
      port = v
    } else if (a.startsWith('--port=')) {
      const v = parseInt(a.slice('--port='.length), 10)
      if (!Number.isFinite(v) || v < 1 || v > 65535) {
        console.error('dev: --port must be 1–65535')
        process.exit(1)
      }
      port = v
    } else if (a === '--host' || a === '--address') {
      const v = argv[++i]
      if (v == null || v === '' || v.startsWith('-')) {
        console.error('dev: --host / --address requires a value')
        process.exit(1)
      }
      host = v
    } else if (a.startsWith('--host=')) {
      host = a.slice('--host='.length)
    } else if (a.startsWith('--address=')) {
      host = a.slice('--address='.length)
    }
  }
  host = String(host).trim()
  if (!host) {
    console.error('dev: empty --host')
    process.exit(1)
  }
  return { port, host }
}

const { port, host } = parseArgs(process.argv)

process.chdir(root)

const ctx = await esbuild.context({
  entryPoints: ['web/main.jsx'],
  bundle: true,
  outfile: 'web/main.js',
  format: 'esm',
  platform: 'browser',
  jsx: 'automatic',
  sourcemap: true
})

await ctx.watch()

const result = await ctx.serve({
  port,
  host,
  servedir: 'web'
})

const browseHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host
const displayHost = host === '0.0.0.0' ? '0.0.0.0 (browse via 127.0.0.1)' : host
console.log('')
console.log(`spoon-hello dev  http://${browseHost}:${result.port}/`)
console.log(`  (serving from ${displayHost}:${result.port})`)
console.log('')
