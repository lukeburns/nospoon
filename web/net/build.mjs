#!/usr/bin/env node
'use strict'

import * as esbuild from 'esbuild'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = __dirname
const shimNet = path.resolve(root, 'shims/net.js')

const once = process.argv.includes('--once')
const port = Number(process.env.NET_DEV_PORT || 3456)

/** @type {import('esbuild').BuildOptions} */
const entry = path.resolve(root, 'test/test-echo.js')

/**
 * Resolve `net` to our shim in the **main** bundle.
 * Do not use `overrides.net` on the polyfill plugin: it rebuilds the shim in a nested esbuild
 * without polyfills, so imports like `stream` / `events` fail.
 */
function netShimResolvePlugin () {
  return {
    name: 'net-shim-resolve',
    setup (/** @type {import('esbuild').PluginBuild} */ build) {
      build.onResolve({ filter: /^net$/ }, () => ({ path: shimNet }))
    }
  }
}

const config = {
  entryPoints: [entry],
  bundle: true,
  platform: 'browser',
  outfile: path.resolve(root, 'dev-harness/bundle.js'),
  sourcemap: true,
  format: 'iife',
  target: ['es2022'],
  define: {
    'process.env.NODE_ENV': JSON.stringify(
      process.env.NODE_ENV || 'development'
    )
  },
  plugins: [
    netShimResolvePlugin(),
    nodeModulesPolyfillPlugin({
      globals: {
        Buffer: true,
        process: true
      },
      modules: {
        process: true,
        stream: true,
        buffer: true,
        events: true,
        crypto: true,
        path: true,
        util: true,
        assert: true,
        string_decoder: true,
        fs: 'empty',
        child_process: 'empty',
        os: true
      }
    })
  ]
}

if (once) {
  await esbuild.build(config)
  console.log('wrote', config.outfile)
} else {
  const ctx = await esbuild.context(config)
  await ctx.watch()
  await ctx.serve({
    servedir: path.resolve(root, 'dev-harness'),
    port,
    host: '127.0.0.1',
    /** SPA-style: unknown paths still serve the harness (optional) */
    fallback: path.resolve(root, 'dev-harness', 'index.html')
  })
  console.log(`net shim dev: http://127.0.0.1:${port}/ (esbuild watch + serve)`)
}
