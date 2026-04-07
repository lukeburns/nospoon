#!/usr/bin/env node
/**
 * Serve {@link ../dist} on loopback for local smoke tests (same-origin as any dev proxy you add).
 */
import { createServer } from 'node:http'
import { readFileSync, existsSync } from 'node:fs'
import { join, extname, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(fileURLToPath(new URL('.', import.meta.url)), '../dist')
const PORT = Number(process.env.PORT || 4173)

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.bin': 'application/octet-stream',
  '.img': 'application/octet-stream',
  '.zst': 'application/octet-stream'
}

createServer(function (req, res) {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1')
    let rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
    rel = normalize(rel).replace(/^(\.\.(\/|\\|$))+/, '')
    const file = join(root, rel)
    if (!file.startsWith(root) || !existsSync(file)) {
      res.writeHead(404)
      res.end('Not found')
      return
    }
    const body = readFileSync(file)
    const type = MIME[extname(file)] || 'application/octet-stream'
    res.writeHead(200, { 'Content-Type': type })
    res.end(body)
  } catch (e) {
    res.writeHead(500)
    res.end(String(e && e.message ? e.message : e))
  }
}).listen(PORT, '127.0.0.1', function () {
  console.log('examples/v86 preview: http://127.0.0.1:' + PORT + '/')
})
