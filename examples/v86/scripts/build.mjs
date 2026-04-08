#!/usr/bin/env node
/**
 * Bundle {@link ../web/main.js} with the browser {@code net} shim (unused here but kept for parity
 * with examples/simple) and {@code browser-net-shim} → {@code web/net/lib/browser-net-client.js}.
 */
import * as esbuild from 'esbuild'
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill'
import {
  mkdirSync,
  copyFileSync,
  cpSync,
  readFileSync,
  writeFileSync,
  existsSync
} from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoWebNet = join(root, '../../web/net')
const shimNet = join(repoWebNet, 'shims/net.js')
const clientPath = join(repoWebNet, 'lib/browser-net-client.js')

const inline = process.argv.includes('--inline')

const assetsV86 = join(root, 'assets', 'v86')
const distV86 = join(root, 'dist', 'v86')
const debugScript = join(root, '../../web/debug/nospoon-debug.js')

mkdirSync(join(root, 'dist'), { recursive: true })

function copyV86AssetsToDist () {
  if (!existsSync(join(assetsV86, 'libv86.mjs'))) {
    console.warn(
      'examples/v86: assets/v86/libv86.mjs missing — run: npm run vendor'
    )
    return
  }
  mkdirSync(distV86, { recursive: true })
  cpSync(assetsV86, distV86, { recursive: true })
  console.log('examples/v86: copied assets/v86 → dist/v86')
}

function netShimResolvePlugin () {
  return {
    name: 'net-shim-resolve',
    setup (build) {
      build.onResolve({ filter: /^net$/ }, () => ({ path: shimNet }))
    }
  }
}

function browserNetShimResolvePlugin () {
  return {
    name: 'browser-net-shim-resolve',
    setup (build) {
      build.onResolve({ filter: /^browser-net-shim$/ }, () => ({ path: clientPath }))
    }
  }
}

const esbuildOpts = {
  entryPoints: [join(root, 'web/main.js')],
  bundle: true,
  platform: 'browser',
  format: 'iife',
  target: ['es2022'],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  minify: true,
  plugins: [
    netShimResolvePlugin(),
    browserNetShimResolvePlugin(),
    nodeModulesPolyfillPlugin({
      globals: { process: true, Buffer: true },
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

if (inline) {
  const result = await esbuild.build({
    ...esbuildOpts,
    write: false
  })
  const out = result.outputFiles[0]
  const js = out.text.replace(/<\/script/gi, '<\\/script')
  const indexSrc = readFileSync(join(root, 'web/index.html'), 'utf8')
  const htmlNoScript = indexSrc.replace(
    /\s*<script[^>]*src="bundle\.js"[^>]*><\/script>\s*/i,
    '\n'
  )
  const html = htmlNoScript.replace(
    '</body>',
    `  <script>\n${js}\n  </script>\n</body>`
  )
  const outfile = join(root, 'dist/index.html')
  writeFileSync(outfile, html, 'utf8')
  copyFileSync(debugScript, join(root, 'dist/nospoon-debug.js'))
  copyV86AssetsToDist()
  console.log('examples/v86: wrote (inline)', outfile)
} else {
  await esbuild.build({
    ...esbuildOpts,
    outfile: join(root, 'dist/bundle.js')
  })
  copyFileSync(join(root, 'web/index.html'), join(root, 'dist/index.html'))
  copyFileSync(join(root, 'web/styles.css'), join(root, 'dist/styles.css'))
  copyFileSync(debugScript, join(root, 'dist/nospoon-debug.js'))
  copyV86AssetsToDist()
  console.log('examples/v86: wrote dist/index.html, dist/bundle.js, dist/styles.css, dist/nospoon-debug.js')
}
