'use strict'

const http = require('http')
const hc = require('hypercore-crypto')

function escapeHtml (s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * @param {string} controlPanelOriginJson
 * @param {string} primaryMeshZ32Json
 */
function buildSpoonHelloHtmlPage (signedPlainText, controlPanelOriginJson, primaryMeshZ32Json) {
  const sig = escapeHtml(signedPlainText)
  const script = `(async function () {
  const CONTROL_PANEL_ORIGIN = ${controlPanelOriginJson}
  const enc = new TextEncoder()
  const NL = String.fromCharCode(10)
  const logEl = document.getElementById('log')
  const fromPeersEl = document.getElementById('fromPeers')
  const bindHostEl = document.getElementById('bindhost')
  const portEl = document.getElementById('port')
  const toPeersEl = document.getElementById('toPeers')
  const goBtn = document.getElementById('go')
  const stopBtn = document.getElementById('stop')

  function log (line) {
    logEl.textContent += line + NL
  }

  const activeSocks = new Set()
  /** @type {WeakMap<object, TextDecoder>} */
  const peerDec = new WeakMap()
  /** First-line label resolved (whois wire id or fallback). */
  const labeledPeers = new WeakSet()
  /** @type {WeakMap<object, Uint8Array[]>} */
  const awaitingWhois = new WeakMap()
  let server = null
  let lastFromSock = null
  let lastBrowserValue = ''

  function broadcastBytes (u8) {
    for (const sock of activeSocks) {
      try {
        sock.write(u8)
      } catch (_) {}
    }
  }

  /** One DEL (127) per UTF-8 byte removed — common TTY / nc expectation. */
  function delBytesForString (removedJs) {
    const n = enc.encode(removedJs).byteLength
    if (!n) return
    const u = new Uint8Array(n)
    u.fill(127)
    broadcastBytes(u)
  }

  function onBrowserInput () {
    const v = toPeersEl.value
    const prev = lastBrowserValue
    if (v === prev) return
    if (server && activeSocks.size > 0) {
      let p = 0
      const min = Math.min(v.length, prev.length)
      while (p < min && v.charCodeAt(p) === prev.charCodeAt(p)) p++
      const del = prev.slice(p)
      const ins = v.slice(p)
      if (del.length) delBytesForString(del)
      if (ins.length) broadcastBytes(enc.encode(ins))
    }
    lastBrowserValue = v
  }

  const cu = new URL(
    CONTROL_PANEL_ORIGIN.indexOf('://') !== -1
      ? CONTROL_PANEL_ORIGIN
      : 'http://' + CONTROL_PANEL_ORIGIN
  )
  const shimHref = new URL('browser-net-shim.js', cu).href
  const mod = await import(shimHref)
  mod.setBrowserNetProxy({
    hostname: cu.hostname,
    port: cu.port ? Number(cu.port) : undefined,
    pathname: '/api/browser-net'
  })
  const wsUrl = mod.defaultBrowserNetWsUrl(window.location.href)

  goBtn.onclick = async function () {
    if (server) {
      log('already listening — stop first')
      return
    }
    try {
      server = new mod.BrowserNetServer({ url: wsUrl })
      server.addEventListener('connection', function (ev) {
        const sock = ev.detail
        activeSocks.add(sock)
        peerDec.set(sock, new TextDecoder('utf-8', { fatal: false }))
        log('[session] open ' + sock.remoteAddress + ':' + sock.remotePort)
        sock.addEventListener('data', function (e) {
          const u8 = new Uint8Array(e.data)
          function flushPending (label) {
            const pending = awaitingWhois.get(sock)
            if (!pending) return
            awaitingWhois.delete(sock)
            labeledPeers.add(sock)
            fromPeersEl.textContent += '[' + label + '] '
            const dec = peerDec.get(sock)
            for (let i = 0; i < pending.length; i++) {
              fromPeersEl.textContent += dec.decode(pending[i], { stream: true })
            }
            fromPeersEl.scrollTop = fromPeersEl.scrollHeight
          }
          if (!labeledPeers.has(sock)) {
            if (!awaitingWhois.has(sock)) {
              awaitingWhois.set(sock, [])
              if (fromPeersEl.textContent.length) fromPeersEl.textContent += NL
              lastFromSock = sock
              const ip = sock.remoteAddress
              const whoisUrl = new URL(
                '/api/whois/' + encodeURIComponent(ip),
                CONTROL_PANEL_ORIGIN
              ).href
              fetch(whoisUrl)
                .then(function (r) {
                  return r.ok ? r.text() : ''
                })
                .then(function (raw) {
                  if (!activeSocks.has(sock)) return
                  const line = raw.trim()
                  const label = line || ip + ':' + sock.remotePort
                  flushPending(label)
                })
                .catch(function () {
                  if (!activeSocks.has(sock)) return
                  flushPending(ip + ':' + sock.remotePort)
                })
            }
            awaitingWhois.get(sock).push(u8)
            return
          }
          if (lastFromSock !== sock) {
            if (fromPeersEl.textContent.length) fromPeersEl.textContent += NL
            lastFromSock = sock
          }
          const dec = peerDec.get(sock)
          fromPeersEl.textContent += dec.decode(u8, { stream: true })
          fromPeersEl.scrollTop = fromPeersEl.scrollHeight
        })
        sock.addEventListener('close', function () {
          activeSocks.delete(sock)
          if (lastFromSock === sock) lastFromSock = null
          log('[session] close ' + sock.remoteAddress + ':' + sock.remotePort)
        })
      })
      const port = Number(portEl.value) || 23
      const bindhost = bindHostEl.value.trim()
      if (bindhost) await server.listen({ port, host: bindhost })
      else await server.listen(port)
      log('listening (nc-style) ' + (bindhost || 'primary') + ':' + port)
    } catch (err) {
      log('error: ' + (err && err.message ? err.message : err))
      server = null
    }
  }

  stopBtn.onclick = function () {
    if (server) {
      server.close()
      server = null
      activeSocks.clear()
      lastFromSock = null
      log('stopped')
    }
  }

  toPeersEl.addEventListener('input', onBrowserInput)
})()`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>spoon hello</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 1rem; max-width: 48rem; }
    pre#signature, pre#log, pre#fromPeers {
      font-family: ui-monospace, monospace;
      background: #1a1b1e;
      color: #e8e6e3;
      padding: 0.75rem;
      overflow: auto;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-all;
    }
    pre#signature { min-height: 4rem; }
    pre#log { min-height: 4rem; }
    pre#fromPeers { min-height: 10rem; max-height: 40vh; }
    textarea#toPeers {
      font-family: ui-monospace, monospace;
      width: 100%;
      max-width: 44rem;
      min-height: 5rem;
      box-sizing: border-box;
      background: #111216;
      color: #e8e6e3;
      border: 1px solid #333;
      padding: 0.5rem;
      font-size: 12px;
    }
    h2 { font-size: 1.1rem; margin-top: 1.25rem; }
    label { display: block; margin: 0.35rem 0; }
    button { margin-right: 0.5rem; margin-top: 0.5rem; }
    input[type="text"] { min-width: 18rem; }
  </style>
</head>
<body>
  <pre id="signature">${sig}</pre>
  <h2>Browser-net (netcat-style)</h2>
  <p>
    Loads the control panel <code>browser-net-shim.js</code> (cross-origin). From a mesh peer run
    <code>nc &lt;mesh-host&gt; &lt;port&gt;</code> (or similar). Bytes from clients show below as they arrive;
    what you type in the box is sent to <strong>all</strong> connected sessions immediately (UTF-8, edits
    become DEL + insert on the wire). Each peer line is tagged using
    <code>/api/whois/&lt;ip&gt;</code> on the control host — the same plain-text line as
    <code>http://whois/&lt;ip&gt;</code> when mesh DNS exposes <code>whois</code>. If lookup fails, the tag falls back to
    <code>ip:port</code>. Bind host defaults to your primary mesh DNS label (z32); override with a local mesh IPv4 or
    <code>z32.topic</code>.
  </p>
  <p>
    <label>Bind host <input id="bindhost" type="text" size="52"/></label>
  </p>
  <p>
    <label>Port <input id="port" type="number" value="23" min="1" max="65535"/></label>
  </p>
  <p>
    <button type="button" id="go">Listen</button>
    <button type="button" id="stop">Stop</button>
  </p>
  <p><strong>From peers</strong></p>
  <pre id="fromPeers"></pre>
  <p><strong>To peers</strong> (type here — broadcast to every session)</p>
  <textarea id="toPeers" rows="4" spellcheck="false" placeholder="Listening… type to send."></textarea>
  <p><strong>Log</strong></p>
  <pre id="log"></pre>
  <script type="module">${script}</script>
  <script>
    (function () {
      var el = document.getElementById('bindhost')
      var z = ${primaryMeshZ32Json}
      if (el && z) el.value = z
    })()
  </script>
</body>
</html>`
}

/**
 * HTTP “hello” on one or more bind addresses (topic TUN + optional primary TUN): looks up the
 * visitor via whois (by IP) and returns a signed line with local and remote wire identities.
 * Browsers (Accept: text/html) get HTML with the same signed block plus an embedded browser-net stream demo.
 * @param {{ bindAddress?: string, bindAddresses?: string[], port?: number, myPublicKeyZ32: string, secretKey: Buffer, fetchVisitorKeyLine: (ip: string) => Promise<string>, onError?: (e: Error) => void, getHtmlEmbedConfig?: () => { controlPanelOrigin: string, primaryMeshZ32: string } | null | undefined }} opts
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
  const getHtmlEmbedConfig =
    typeof opts.getHtmlEmbedConfig === 'function' ? opts.getHtmlEmbedConfig : null

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

  function onRequest (req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' })
      res.end()
      return
    }

    let remote = req.socket.remoteAddress || ''
    if (remote.startsWith('::ffff:')) remote = remote.slice(7)

    const accept = String(req.headers.accept || '')
    const wantHtml =
      getHtmlEmbedConfig != null && accept.indexOf('text/html') !== -1

    Promise.resolve()
      .then(function () {
        return fetchVisitorKeyLine(remote)
      })
      .then(function (visitorLine) {
        const plain = buildSignedPlain(visitorLine)
        if (wantHtml) {
          const cfg = getHtmlEmbedConfig && getHtmlEmbedConfig()
          const origin =
            cfg && cfg.controlPanelOrigin != null
              ? String(cfg.controlPanelOrigin).trim()
              : ''
          const z32 =
            cfg && cfg.primaryMeshZ32 != null
              ? String(cfg.primaryMeshZ32).trim()
              : myPublicKeyZ32
          if (!origin) {
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
            res.end('html embed: control panel origin not configured\n')
            return
          }
          const html = buildSpoonHelloHtmlPage(
            plain,
            JSON.stringify(origin),
            JSON.stringify(z32)
          )
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

module.exports = { createSpoonHelloServer }
