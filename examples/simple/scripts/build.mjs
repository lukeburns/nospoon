#!/usr/bin/env node
/**
 * Bundle {@link ../web/app.js} with the browser `net` shim and emit **one** self-contained
 * {@link ../dist/index.html} (inline script, no separate JS file). Netcat-style listen (port 23).
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
    pre#fromPeers, pre#log {
      margin-top: 0.35rem;
      padding: 0.75rem 1rem;
      background: #111;
      color: #e8e8e8;
      border-radius: 8px;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-word;
      min-height: 4rem;
    }
    pre#log { min-height: 6rem; }
    textarea#toPeers {
      width: 100%;
      max-width: 52rem;
      box-sizing: border-box;
      font-family: ui-monospace, monospace;
      font-size: 0.85rem;
      padding: 0.5rem 0.65rem;
      border-radius: 6px;
      border: 1px solid #ccc;
    }
    label { margin-right: 0.5rem; }
  </style>
</head>
<body>
  <h1>Browser-net (netcat-style)</h1>
  <p>
    Same behavior as <code>examples/spoon-hello</code> BrowserNet panel: default port <strong>23</strong>,
    bytes from mesh peers appear under &quot;From peers&quot; (tagged via <code>/api/whois/&lt;ip&gt;</code> when
    <code>controlOrigin</code> or <code>proxyHost</code> points at control HTTP). The &quot;To peers&quot; box
    broadcasts UTF-8 to every connected session; edits send DEL (0x7f) + inserts on the wire.
    WebSocket defaults match spoon-hello (<code>ws://middle:8766/api/browser-net</code> on CID pages, or
    <code>?proxyHost=127.0.0.1&amp;proxyPort=CONTROL_HTTP_PORT</code>).
  </p>
  <p>
    <label>Bind host <input id="bindHost" type="text" size="52" placeholder="empty = primary mesh"/></label>
  </p>
  <p>
    <label>Port <input id="listenPort" type="number" value="23" min="1" max="65535"/></label>
  </p>
  <p>
    <button id="btnListen" type="button">Listen</button>
    <button id="btnStop" type="button">Stop</button>
  </p>
  <span class="section-label">From peers</span>
  <pre id="fromPeers"></pre>
  <span class="section-label">To peers</span>
  <p class="field-hint">Broadcast to every connected session.</p>
  <textarea id="toPeers" rows="4" spellcheck="false" placeholder="Listening… type to send."></textarea>
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
