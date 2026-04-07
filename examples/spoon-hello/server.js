'use strict'

const http = require('http')
const fs = require('fs')
const path = require('path')
const hc = require('hypercore-crypto')

const DIST_DIR = path.join(__dirname, 'dist')

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
}

/**
 * @param {string} html
 * @param {{ signedPlainText: string }} payload
 */
function injectSpoonHelloConfig (html, payload) {
  const json = JSON.stringify(payload).replace(/</g, '\\u003c')
  return html.replace(
    /(<script type="application\/json" id="spoon-hello-config">)([\s\S]*?)(<\/script>)/,
    function (_, a, _b, c) {
      return a + json + c
    }
  )
}

/**
 * @param {string} reqPath
 * @returns {string | null} filesystem path or null
 */
function safeResolveStatic (reqPath) {
  let realDist
  try {
    realDist = fs.realpathSync(DIST_DIR)
  } catch {
    return null
  }
  const stripped = decodeURIComponent(reqPath).replace(/^\/+/, '')
  const rel = path.normalize(stripped).replace(/^(\.\.(\/|\\|$))+/, '')
  if (rel.includes('..')) return null
  const base = path.join(DIST_DIR, rel)
  let realBase
  try {
    realBase = fs.realpathSync(base)
  } catch {
    return null
  }
  if (!realBase.startsWith(realDist + path.sep) && realBase !== realDist) return null
  return realBase
}

/**
 * @param {string} signedPlainText
 */
function buildSpoonHelloHtmlPage (signedPlainText) {
  let htmlPath = path.join(DIST_DIR, 'index.html')
  let html
  try {
    html = fs.readFileSync(htmlPath, 'utf8')
  } catch (e) {
    throw new Error(
      'spoon-hello: dist/index.html missing — run `npm run build` in examples/spoon-hello (' +
        (e && e.message ? e.message : e) +
        ')'
    )
  }
  return injectSpoonHelloConfig(html, { signedPlainText })
}

/**
 * HTTP “hello” on one or more bind addresses (topic TUN + optional primary TUN): looks up the
 * visitor via whois (by IP) and returns a signed line with local and remote wire identities.
 * When {@code serveHtml} is true, browsers that send {@code Accept: text/html} get the React shell from {@code dist/} with the signed greeting injected as JSON.
 * @param {{ bindAddress?: string, bindAddresses?: string[], port?: number, myPublicKeyZ32: string, secretKey: Buffer, fetchVisitorKeyLine: (ip: string) => Promise<string>, onError?: (e: Error) => void, serveHtml?: boolean }} opts
 */
function createSpoonHelloServer (opts) {
  const raw =
    opts.bindAddresses != null && Array.isArray(opts.bindAddresses)
      ? opts.bindAddresses
      : [opts.bindAddress]
  const bindAddresses = [
    ...new Set(
      raw
        .map(function (a) {
          return String(a || '').trim()
        })
        .filter(Boolean)
    )
  ]
  const port = opts.port != null ? Number(opts.port) : 80
  const myPublicKeyZ32 = String(opts.myPublicKeyZ32 || '')
  const secretKey = opts.secretKey
  const fetchVisitorKeyLine = opts.fetchVisitorKeyLine
  const onError = typeof opts.onError === 'function' ? opts.onError : function () {}
  const serveHtml = opts.serveHtml === true

  if (bindAddresses.length === 0) {
    throw new Error('spoon hello: bindAddress or bindAddresses is required')
  }
  if (!secretKey || !Buffer.isBuffer(secretKey)) {
    throw new Error('spoon hello: secretKey is required')
  }
  if (typeof fetchVisitorKeyLine !== 'function') {
    throw new Error('spoon hello: fetchVisitorKeyLine is required')
  }

  /** @type {import('http').Server[]} */
  let servers = []

  function buildSignedPlain (visitorLine) {
    const yourKey = String(visitorLine || '').trim() || '(unknown)'
    const ts = new Date().toISOString()
    const bodyLine = `greetings ${yourKey}.\nsigned, ${myPublicKeyZ32} @ ${ts}\n`
    const msgBuf = Buffer.from(bodyLine, 'utf8')
    const sig = hc.sign(msgBuf, secretKey)
    const sigHex = sig.toString('hex')
    return bodyLine + '\n' + sigHex + '\n'
  }

  function sendStatic (res, fsPath) {
    const ext = path.extname(fsPath).toLowerCase()
    const type = MIME[ext] || 'application/octet-stream'
    let buf
    try {
      buf = fs.readFileSync(fsPath)
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('not found\n')
      return
    }
    res.writeHead(200, { 'Content-Type': type })
    res.end(buf)
  }

  function onRequest (req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' })
      res.end()
      return
    }

    let remote = req.socket.remoteAddress || ''
    if (remote.startsWith('::ffff:')) remote = remote.slice(7)

    const url = new URL(req.url || '/', 'http://x')
    const pathname = url.pathname

    const accept = String(req.headers.accept || '')
    const wantHtml = serveHtml && accept.indexOf('text/html') !== -1

    Promise.resolve()
      .then(function () {
        return fetchVisitorKeyLine(remote)
      })
      .then(function (visitorLine) {
        const plain = buildSignedPlain(visitorLine)

        if (pathname !== '/' && pathname !== '/index.html') {
          const fsPath = safeResolveStatic(pathname)
          if (!fsPath || !fs.statSync(fsPath).isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
            res.end('not found\n')
            return
          }
          if (req.method === 'HEAD') {
            const st = fs.statSync(fsPath)
            res.writeHead(200, {
              'Content-Type': MIME[path.extname(fsPath).toLowerCase()] || 'application/octet-stream',
              'Content-Length': st.size
            })
            res.end()
            return
          }
          sendStatic(res, fsPath)
          return
        }

        if (wantHtml) {
          const html = buildSpoonHelloHtmlPage(plain)
          const enc = 'utf8'
          if (req.method === 'HEAD') {
            res.writeHead(200, {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Length': Buffer.byteLength(html, enc)
            })
            res.end()
            return
          }
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
          res.end(html, enc)
          return
        }
        if (req.method === 'HEAD') {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': Buffer.byteLength(plain, 'utf8')
          })
          res.end()
          return
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end(plain)
      })
      .catch(function (err) {
        onError(err instanceof Error ? err : new Error(String(err)))
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
          res.end('error\n')
        }
      })
  }

  return {
    /**
     * @returns {Promise<{ port: number }>}
     */
    start () {
      servers = []
      const pending = bindAddresses.map(function (bindAddress) {
        return new Promise(function (resolve, reject) {
          const server = http.createServer(onRequest)
          function onListenErr (err) {
            server.removeListener('error', onListenErr)
            reject(err)
          }
          server.once('error', onListenErr)
          server.listen(port, bindAddress, function () {
            server.removeListener('error', onListenErr)
            server.on('error', function (err) {
              onError(err)
            })
            servers.push(server)
            const addr = server.address()
            const listenPort =
              addr && typeof addr === 'object' ? addr.port : port
            resolve(listenPort)
          })
        })
      })
      return Promise.all(pending)
        .then(function (ports) {
          return { port: ports[0] }
        })
        .catch(function (err) {
          const started = servers
          servers = []
          return Promise.all(
            started.map(function (s) {
              return new Promise(function (r) {
                s.close(r)
              })
            })
          ).then(function () {
            throw err
          })
        })
    },
    /**
     * @returns {Promise<void>}
     */
    stop () {
      const toClose = servers
      servers = []
      return Promise.all(
        toClose.map(function (s) {
          return new Promise(function (resolve) {
            s.close(function () {
              resolve()
            })
          })
        })
      ).then(function () {})
    }
  }
}

module.exports = { createSpoonHelloServer, injectSpoonHelloConfig, buildSpoonHelloHtmlPage }
