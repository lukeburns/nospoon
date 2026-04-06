#!/usr/bin/env node
/**
 * Bundle {@link ../web/app.js} with the browser `net` shim and emit **one** self-contained
 * {@link ../dist/index.html} (inline script, no separate JS file). Auto-listen from port 23.
 */
import * as esbuild from 'esbuild'
import { nodeModulesPolyfillPlugin } from 'esbuild-plugins-node-modules-polyfill'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoWebNet = join(root, '../../web/net')
const shimNet = join(repoWebNet, 'shims/net.js')

mkdirSync(join(root, 'dist'), { recursive: true })

function netShimResolvePlugin () {
  return {
    name: 'net-shim-resolve',
    setup (build) {
      build.onResolve({ filter: /^net$/ }, () => ({ path: shimNet }))
    }
  }
}

const result = await esbuild.build({
  entryPoints: [join(root, 'web/app.js')],
  bundle: true,
  platform: 'browser',
  format: 'iife',
  target: ['es2022'],
  write: false,
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
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
})

const out = result.outputFiles[0]
const js = out.text.replace(/<\/script/gi, '<\\/script')

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>simple browser-net (nc-style)</title>
  <style>
    :root { font-family: system-ui, sans-serif; }
    body { margin: 1.25rem; max-width: 52rem; }
    code { background: #f0f0f0; padding: 0.1em 0.35em; border-radius: 4px; }
    .section-label { display: block; font-weight: 600; margin-top: 1.25rem; }
    .field-hint { margin: 0.25rem 0 0.5rem; font-size: 0.9rem; color: #444; }
    pre#log, #fromPeers {
      margin-top: 0.35rem;
      padding: 0.75rem 1rem;
      background: #111;
      color: #e8e8e8;
      border-radius: 8px;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-word;
      min-height: 4rem;
      font-family: ui-monospace, monospace;
    }
    pre#log { min-height: 6rem; }
    .peer-conn-line {
      color: #a8a8a8;
    }
    button.host-copy {
      all: unset;
      cursor: pointer;
      color: #8ec5ff;
      text-decoration: underline;
      text-decoration-style: dotted;
      text-underline-offset: 2px;
    }
    button.host-copy:hover { color: #b8dbff; }
    button.host-copy:focus-visible {
      outline: 2px solid #8ec5ff;
      outline-offset: 2px;
      border-radius: 2px;
    }
    textarea#toPeers {
      width: 100%;
      max-width: 52rem;
      box-sizing: border-box;
      font-family: ui-monospace, monospace;
      font-size: 0.85rem;
      line-height: 1.5;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      border: 1px solid #333;
      background: #111;
      color: #e8e8e8;
      margin-top: 0.35rem;
      caret-color: #b4f0a8;
    }
    @supports (caret-shape: block) {
      textarea#toPeers {
        caret-shape: block;
      }
    }
    textarea#toPeers::placeholder {
      color: #666;
    }
    textarea#toPeers:focus {
      outline: none;
      border-color: #8ec5ff;
      box-shadow: 0 0 0 2px rgba(142, 197, 255, 0.25);
    }
    label { margin-right: 0.5rem; }
  </style>
</head>
<body>
  <h1>TCP Server</h1>

  <p id="listenStatus" class="field-hint" aria-live="polite">Starting server...</p>

  <span class="section-label">Broadcast</span>
  <p class="field-hint">Broadcast keystrokes to all connected clients.</p>
  <textarea id="toPeers" rows="4" spellcheck="false" placeholder="Type to send."></textarea>

  <span class="section-label">Messages</span>
  <p class="field-hint">Messages from connected clients.</p>
  <div id="fromPeers" aria-label="From peers"></div>
  
  <span class="section-label">Log</span>
  <pre id="log"></pre>
  <script>
${js}
  </script>
</body>
</html>
`

const outfile = join(root, 'dist/index.html')
writeFileSync(outfile, html, 'utf8')
console.log('examples/simple: wrote', outfile)
