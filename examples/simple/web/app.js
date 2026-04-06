'use strict'

/**
 * Netcat-style browser TCP: listen on port 23 by default, broadcast "To peers" to every session,
 * show "From peers" with optional whois labels (same behavior as spoon-hello BrowserNetPanel).
 * Control plane: `?proxyHost=HOST&proxyPort=PORT` or `?wsHost=&wsPort=` or CID host → `middle:8766`.
 * Whois: `?controlOrigin=http://host:port` or inferred from proxyHost/proxyPort.
 */

const net = require('net')
const { setBrowserNetProxy } = net

/** Same as {@link BROWSER_NET_DWEB_WS_PORT} in control-http (browser-net on IPFS loopback). */
const MIDDLE_WS_PORT = 8766

const NL = '\n'

function isLikelyIpfsCidHostname (host) {
  const h = String(host || '').toLowerCase()
  if (!h || h.includes('.')) return false
  if (h.startsWith('qm') && h.length >= 46) return true
  if (h.startsWith('baf')) return true
  return /^[a-z0-9]{46,}$/.test(h)
}

/** Base URL for `/api/whois/<ip>` (control HTTP). */
let controlPanelOrigin = ''

function applyBrowserNetProxyFromLocation () {
  if (typeof window === 'undefined' || !window.location) return
  const u = new URL(window.location.href)
  const host =
    u.searchParams.get('proxyHost') ||
    u.searchParams.get('controlHost') ||
    ''
  const portStr =
    u.searchParams.get('proxyPort') || u.searchParams.get('controlPort') || ''
  if (host.trim()) {
    setBrowserNetProxy({
      hostname: host.trim(),
      port: portStr ? Number(portStr) : undefined,
      pathname: '/api/browser-net'
    })
  } else {
    const wsHost = u.searchParams.get('wsHost')
    if (wsHost && wsHost.trim()) {
      const wsPort = u.searchParams.get('wsPort')
      setBrowserNetProxy({
        hostname: wsHost.trim(),
        port: wsPort ? Number(wsPort) : MIDDLE_WS_PORT,
        pathname: '/api/browser-net'
      })
    } else if (isLikelyIpfsCidHostname(u.hostname)) {
      setBrowserNetProxy({
        hostname: 'middle',
        port: MIDDLE_WS_PORT,
        pathname: '/api/browser-net'
      })
    }
  }

  const explicit = u.searchParams.get('controlOrigin')
  if (explicit && explicit.trim()) {
    controlPanelOrigin = explicit.trim()
    return
  }
  if (host.trim()) {
    const p = portStr ? Number(portStr) : 80
    controlPanelOrigin = `http://${host.trim()}:${p}`
    return
  }
  if (u.protocol === 'http:' || u.protocol === 'https:') {
    controlPanelOrigin = u.origin
  }
}

function logLine (line) {
  const el = document.getElementById('log')
  if (el) el.textContent += String(line) + NL
  if (typeof console !== 'undefined' && console.log) console.log(line)
}

let fromPeersText = ''

function setFromPeers (updater) {
  if (typeof updater === 'function') fromPeersText = updater(fromPeersText)
  else fromPeersText = updater
  const el = document.getElementById('fromPeers')
  if (el) el.textContent = fromPeersText
}

applyBrowserNetProxyFromLocation()

/** @type {import('net').Server | null} */
let server = null
const activeSocks = new Set()
const peerDec = new WeakMap()
const labeledPeers = new WeakSet()
const awaitingWhois = new WeakMap()
let lastFromSock = null
let lastToPeersValue = ''

function broadcastBytes (u8) {
  for (const sock of activeSocks) {
    try {
      sock.write(u8)
    } catch (_) {}
  }
}

function delBytesForString (removedJs) {
  const enc = new TextEncoder()
  const n = enc.encode(removedJs).byteLength
  if (!n) return
  const u = new Uint8Array(n)
  u.fill(127)
  broadcastBytes(u)
}

function onToPeersInput (v) {
  const ta = document.getElementById('toPeers')
  if (ta) ta.value = v
  const prev = lastToPeersValue
  if (v === prev) return
  if (server && activeSocks.size > 0) {
    let p = 0
    const min = Math.min(v.length, prev.length)
    while (p < min && v.charCodeAt(p) === prev.charCodeAt(p)) p++
    const del = prev.slice(p)
    const ins = v.slice(p)
    if (del.length) delBytesForString(del)
    if (ins.length) broadcastBytes(new TextEncoder().encode(ins))
  }
  lastToPeersValue = v
}

async function startListen () {
  if (server) {
    logLine('already listening — stop first')
    return
  }
  const portEl = document.getElementById('listenPort')
  const bindEl = document.getElementById('bindHost')
  const port = Number(portEl && portEl.value) || 23
  const bindHost = bindEl && bindEl.value ? String(bindEl.value).trim() : ''

  const o =
    controlPanelOrigin.indexOf('://') !== -1
      ? controlPanelOrigin
      : controlPanelOrigin
        ? `http://${controlPanelOrigin}`
        : ''

  const srv = net.createServer(function (socket) {
    activeSocks.add(socket)
    peerDec.set(socket, new TextDecoder('utf-8', { fatal: false }))

    socket.on('data', function (chunk) {
      const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
      function flushPending (label) {
        const pending = awaitingWhois.get(socket)
        if (!pending) return
        awaitingWhois.delete(socket)
        labeledPeers.add(socket)
        setFromPeers(function (prev) {
          let next = prev + `[${label}] `
          const dec = peerDec.get(socket)
          for (let i = 0; i < pending.length; i++) {
            next += dec.decode(pending[i], { stream: true })
          }
          return next
        })
      }
      if (!labeledPeers.has(socket)) {
        if (!awaitingWhois.has(socket)) {
          awaitingWhois.set(socket, [])
          setFromPeers(function (prev) {
            return prev.length ? prev + NL : prev
          })
          lastFromSock = socket
          const ip = socket.remoteAddress
          if (o && ip) {
            const whoisUrl = new URL(
              `/api/whois/${encodeURIComponent(ip)}`,
              o
            ).href
            fetch(whoisUrl)
              .then(function (r) {
                return r.ok ? r.text() : ''
              })
              .then(function (raw) {
                if (!activeSocks.has(socket)) return
                const line = raw.trim()
                const label = line || `${ip}:${socket.remotePort}`
                flushPending(label)
              })
              .catch(function () {
                if (!activeSocks.has(socket)) return
                flushPending(`${ip}:${socket.remotePort}`)
              })
          }
        }
        awaitingWhois.get(socket).push(u8)
        if (!labeledPeers.has(socket) && !(o && socket.remoteAddress)) {
          flushPending(`${socket.remoteAddress}:${socket.remotePort}`)
        }
        return
      }
      if (lastFromSock !== socket) {
        setFromPeers(function (prev) {
          return prev.length ? prev + NL : prev
        })
        lastFromSock = socket
      }
      const dec = peerDec.get(socket)
      setFromPeers(function (prev) {
        return prev + dec.decode(u8, { stream: true })
      })
    })

    socket.on('close', function () {
      activeSocks.delete(socket)
      if (lastFromSock === socket) lastFromSock = null
      logLine(
        `[session] close ${socket.remoteAddress}:${socket.remotePort}`
      )
    })

    socket.on('error', function (err) {
      logLine('socket error: ' + (err && err.message ? err.message : String(err)))
    })

    logLine(`[session] open ${socket.remoteAddress}:${socket.remotePort}`)
  })

  srv.on('listening', function () {
    logLine('listening ' + JSON.stringify(srv.address()))
  })

  try {
    if (bindHost) await srv.listen({ port, host: bindHost })
    else await srv.listen(port)
    server = srv
    logLine(`listening (nc-style) ${bindHost || 'primary'}:${port}`)
  } catch (err) {
    logLine(
      'error: ' + (err && err.message ? err.message : String(err))
    )
  }
}

function stopListen () {
  if (server) {
    server.close()
    server = null
    activeSocks.clear()
    lastFromSock = null
    logLine('stopped')
  }
}

function wireUi () {
  const listenBtn = document.getElementById('btnListen')
  const stopBtn = document.getElementById('btnStop')
  const toPeers = document.getElementById('toPeers')
  if (listenBtn) listenBtn.addEventListener('click', function () { startListen() })
  if (stopBtn) stopBtn.addEventListener('click', function () { stopListen() })
  if (toPeers) {
    toPeers.addEventListener('input', function (e) {
      onToPeersInput(e.target.value)
    })
  }
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', wireUi)
} else {
  wireUi()
}
