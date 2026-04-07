#!/usr/bin/env node
/**
 * Bundle {@link ../web/main.js} with the browser {@code net} shim.
 *
 * Default: {@link ../dist/index.html}, {@link ../dist/bundle.js}, {@link ../dist/styles.css} — normal static site layout.
 * {@code --inline}: one self-contained {@link ../dist/index.html} (inline script) for single-file deploy (e.g. IPFS).
 */
import * as esbuild from 'esbuild'
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill'
import { mkdirSync, copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoWebNet = join(root, '../../web/net')
const shimNet = join(repoWebNet, 'shims/net.js')

const inline = process.argv.includes('--inline')

mkdirSync(join(root, 'dist'), { recursive: true })

function netShimResolvePlugin () {
  return {
    name: 'net-shim-resolve',
    setup (build) {
      build.onResolve({ filter: /^net$/ }, () => ({ path: shimNet }))
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
  console.log('examples/simple: wrote (inline)', outfile)
} else {
  await esbuild.build({
    ...esbuildOpts,
    outfile: join(root, 'dist/bundle.js')
  })
  copyFileSync(join(root, 'web/index.html'), join(root, 'dist/index.html'))
  copyFileSync(join(root, 'web/styles.css'), join(root, 'dist/styles.css'))
  console.log('examples/simple: wrote dist/index.html, dist/bundle.js, dist/styles.css')
}
