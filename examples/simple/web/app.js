'use strict'

/**
 * Netcat-style browser TCP for CID (or mesh) pages: auto-listen on first free port from 23,
 * default virtual bind = topic TUN from Origin (no explicit bind host). WebSocket defaults match
 * spoon-hello: `ws://middle:8766/api/browser-net` unless overridden via query params.
 * Peer labels in &quot;From peers&quot; use `http://whois/&lt;ip&gt;` (manual DNS name `whois`).
 * Long mesh hostnames show truncated (e.g. {@code n7e⋯szo.baf⋯3qe}); click to copy the full string.
 */

const net = require('net')
const { setBrowserNetProxy } = net

/** Same as {@link BROWSER_NET_DWEB_WS_PORT} in control-http (browser-net on IPFS loopback). */
const MIDDLE_WS_PORT = 8766

const NL = '\n'
const LISTEN_PORT_START = 23
const LISTEN_PORT_TRIES = 500

/** Midline ellipsis between prefix/suffix of truncated labels (e.g. {@code n7e⋯szo}). */
const ELL = '\u22EF'
const TRUNC_PREFIX = 3
const TRUNC_SUFFIX = 3
const TRUNC_MIN = 12

function truncateLabel (seg) {
  if (seg.length <= TRUNC_MIN) return seg
  return seg.slice(0, TRUNC_PREFIX) + ELL + seg.slice(-TRUNC_SUFFIX)
}

function truncateMeshDisplay (full) {
  if (!full) return ''
  if (!full.includes('.')) return truncateLabel(full)
  return full.split('.').map(truncateLabel).join('.')
}

function shouldOfferCopyHost (full) {
  if (!full) return false
  if (!full.includes('.')) return full.length > TRUNC_MIN
  return full.split('.').some(function (p) {
    return p.length > TRUNC_MIN
  })
}

/**
 * {@link navigator.clipboard} is undefined on many non-secure pages ({@code http://}).
 * @param {string} text
 * @returns {Promise<void>}
 */
function copyTextToClipboard (text) {
  try {
    const clip =
      typeof navigator !== 'undefined' ? navigator.clipboard : undefined
    if (clip && typeof clip.writeText === 'function') {
      return clip.writeText(text).catch(function () {
        copyTextToClipboardExec(text)
      })
    }
  } catch (_) {}
  copyTextToClipboardExec(text)
  return Promise.resolve()
}

function copyTextToClipboardExec (text) {
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0'
    document.body.appendChild(ta)
    ta.focus()
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  } catch (_) {}
}

/**
 * @param {HTMLElement} parent
 * @param {string} full
 */
function appendCopyableHostTo (parent, full) {
  if (!parent || full == null) return
  const s = String(full)
  if (!shouldOfferCopyHost(s)) {
    parent.appendChild(document.createTextNode(s))
    return
  }
  const b = document.createElement('button')
  b.type = 'button'
  b.className = 'host-copy'
  b.textContent = truncateMeshDisplay(s)
  b.title = 'Click to copy — ' + s
  b.addEventListener('click', function (e) {
    e.preventDefault()
    void copyTextToClipboard(s)
  })
  parent.appendChild(b)
}

/** Base URL for whois (no trailing slash), e.g. `http://whois`. Override: `?whoisOrigin=`. */
let whoisBase = 'http://whois'

function applyBrowserNetProxyFromLocation () {
  if (typeof window === 'undefined' || !window.location) return
  const u = new URL(window.location.href)
  const whoisParam = u.searchParams.get('whoisOrigin')
  if (whoisParam && whoisParam.trim()) {
    whoisBase = whoisParam.trim().replace(/\/$/, '')
  }
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
    } else {
      setBrowserNetProxy({
        hostname: 'middle',
        port: MIDDLE_WS_PORT,
        pathname: '/api/browser-net'
      })
    }
  }
}

function whoisUrlForIp (ip) {
  const base = whoisBase.endsWith('/') ? whoisBase.slice(0, -1) : whoisBase
  return `${base}/${encodeURIComponent(ip)}`
}

/** Same as {@code GET /api/whois} — local public key z32, one line. */
function whoisUrlSelf () {
  const base = whoisBase.endsWith('/') ? whoisBase.slice(0, -1) : whoisBase
  return base + '/'
}

function pageHostname () {
  return typeof window !== 'undefined' && window.location && window.location.hostname
    ? String(window.location.hostname).trim()
    : ''
}

/**
 * Mesh-style host peers use: {@code z32.cid} when the page host is a single label (CID or key),
 * otherwise the full {@code hostname} (already {@code key.topic}).
 * @returns {Promise<string | null>}
 */
async function resolveVirtualListenHost () {
  const host = pageHostname()
  if (!host) return null
  if (host.includes('.')) return host
  try {
    const r = await fetch(whoisUrlSelf())
    if (!r.ok) return null
    const line = (await r.text()).trim()
    const z32 = line.split(/\r?\n/)[0].trim()
    if (!z32) return null
    return z32 + '.' + host
  } catch (_) {
    return null
  }
}

/** Set after successful listen; used for session log lines. */
let cachedVirtualListenHost = null

/**
 * @param {'open' | 'close'} kind
 * @param {object} socket — {@code net.Socket} from the browser shim
 */
function logAppendPlain (line) {
  const el = document.getElementById('log')
  if (el) el.appendChild(document.createTextNode(String(line) + NL))
  if (typeof console !== 'undefined' && console.log) console.log(line)
}

function logListeningLine (vh, port) {
  const el = document.getElementById('log')
  const line = 'listening on ' + vh + ':' + port
  if (el) {
    el.appendChild(document.createTextNode('listening on '))
    appendCopyableHostTo(el, vh)
    el.appendChild(document.createTextNode(':' + port + NL))
  }
  if (typeof console !== 'undefined' && console.log) console.log(line)
}

function setListenStatus (vh, port) {
  const status = document.getElementById('listenStatus')
  if (!status) return
  status.textContent = ''
  status.appendChild(document.createTextNode('Listening on '))
  appendCopyableHostTo(status, vh)
  status.appendChild(document.createTextNode(':' + port))
}

const socketPeerLabel = new WeakMap()
const peerConnectedLineDone = new WeakSet()

let fromPeersNonEmpty = false
/** @type {Text | null} */
let fromPeersTailText = null

function fromPeersBreakIfNeeded () {
  const el = document.getElementById('fromPeers')
  if (!el || !fromPeersNonEmpty) return
  el.appendChild(document.createElement('br'))
  fromPeersTailText = null
}

/**
 * @param {string} fullLabel
 * @returns {HTMLSpanElement}
 */
function createPeerHostBracketSpan (fullLabel) {
  const wrap = document.createElement('span')
  wrap.className = 'peer-tag'
  wrap.appendChild(document.createTextNode('['))
  if (shouldOfferCopyHost(fullLabel)) {
    const b = document.createElement('button')
    b.type = 'button'
    b.className = 'host-copy'
    b.textContent = truncateMeshDisplay(fullLabel)
    b.title = 'Click to copy — ' + fullLabel
    b.addEventListener('click', function (e) {
      e.preventDefault()
      void copyTextToClipboard(fullLabel)
    })
    wrap.appendChild(b)
  } else {
    wrap.appendChild(document.createTextNode(fullLabel))
  }
  wrap.appendChild(document.createTextNode('] '))
  return wrap
}

function fromPeersAppendConnectionStatus (fullLabel, status) {
  const el = document.getElementById('fromPeers')
  if (!el) return
  fromPeersBreakIfNeeded()
  const row = document.createElement('span')
  row.className = 'peer-conn-line'
  row.appendChild(createPeerHostBracketSpan(fullLabel))
  row.appendChild(
    document.createTextNode(status === 'connected' ? 'connected' : 'disconnected')
  )
  el.appendChild(row)
  el.appendChild(document.createElement('br'))
  fromPeersTailText = null
  fromPeersNonEmpty = true
}

function rememberPeerLabel (socket, label) {
  if (label != null && String(label) !== '') {
    socketPeerLabel.set(socket, String(label))
  }
}

function tryAppendPeerConnected (socket) {
  if (peerConnectedLineDone.has(socket)) return
  const label = socketPeerLabel.get(socket)
  if (label == null) return
  peerConnectedLineDone.add(socket)
  fromPeersAppendConnectionStatus(label, 'connected')
}

function announcePeerSessionOpen (socket) {
  const ip = socket.remoteAddress
  const rp = socket.remotePort
  if (!ip) {
    rememberPeerLabel(socket, '?')
    tryAppendPeerConnected(socket)
    if (typeof console !== 'undefined' && console.log) {
      console.log('[session] open ?')
    }
    return
  }
  fetch(whoisUrlForIp(ip))
    .then(function (r) {
      return r.ok ? r.text() : ''
    })
    .then(function (raw) {
      if (!activeSocks.has(socket)) return
      const label = (raw && raw.trim()) || `${ip}:${rp}`
      rememberPeerLabel(socket, label)
      tryAppendPeerConnected(socket)
      if (typeof console !== 'undefined' && console.log) {
        console.log('[session] open', label)
      }
    })
    .catch(function () {
      if (!activeSocks.has(socket)) return
      const label = `${ip}:${rp}`
      rememberPeerLabel(socket, label)
      tryAppendPeerConnected(socket)
      if (typeof console !== 'undefined' && console.log) {
        console.log('[session] open', label)
      }
    })
}

function announcePeerSessionClose (socket) {
  const ip = socket.remoteAddress
  const rp = socket.remotePort
  const label =
    socketPeerLabel.get(socket) ||
    (ip != null ? `${ip}:${rp != null ? rp : '?'}` : '?')
  fromPeersAppendConnectionStatus(label, 'disconnected')
  if (typeof console !== 'undefined' && console.log) {
    console.log('[session] close', label)
  }
}

function fromPeersAppendLabel (fullLabel) {
  const el = document.getElementById('fromPeers')
  if (!el) return
  el.appendChild(createPeerHostBracketSpan(fullLabel))
  fromPeersTailText = document.createTextNode('')
  el.appendChild(fromPeersTailText)
  fromPeersNonEmpty = true
}

function fromPeersAppendText (s) {
  if (s == null || s === '') return
  const el = document.getElementById('fromPeers')
  if (!el) return
  if (!fromPeersTailText) {
    fromPeersTailText = document.createTextNode('')
    el.appendChild(fromPeersTailText)
  }
  fromPeersTailText.nodeValue += s
  fromPeersNonEmpty = true
}

function resetFromPeersDom () {
  const el = document.getElementById('fromPeers')
  if (el) el.innerHTML = ''
  fromPeersNonEmpty = false
  fromPeersTailText = null
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

function toPeersIsAppendOnly (prev, next) {
  return next.length >= prev.length && next.slice(0, prev.length) === prev
}

function onToPeersBeforeInput (e) {
  const t = e.inputType
  if (
    t === 'deleteContentBackward' ||
    t === 'deleteContentForward' ||
    t === 'deleteByCut' ||
    t === 'deleteByDrag' ||
    t === 'historyUndo' ||
    t === 'historyRedo'
  ) {
    e.preventDefault()
  }
}

function onToPeersInput (v) {
  const ta = document.getElementById('toPeers')
  if (!ta) return
  const prev = lastToPeersValue
  if (!toPeersIsAppendOnly(prev, v)) {
    ta.value = prev
    const len = prev.length
    ta.setSelectionRange(len, len)
    return
  }
  if (v === prev) return
  if (server && activeSocks.size > 0) {
    const ins = v.slice(prev.length)
    if (ins.length) broadcastBytes(new TextEncoder().encode(ins))
  }
  lastToPeersValue = v
}

function createPeerServer () {
  return net.createServer(function (socket) {
    activeSocks.add(socket)
    peerDec.set(socket, new TextDecoder('utf-8', { fatal: false }))

    socket.on('data', function (chunk) {
      const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
      function flushPending (label) {
        const pending = awaitingWhois.get(socket)
        if (!pending) return
        awaitingWhois.delete(socket)
        labeledPeers.add(socket)
        rememberPeerLabel(socket, label)
        tryAppendPeerConnected(socket)
        fromPeersAppendLabel(label)
        const dec = peerDec.get(socket)
        let chunk = ''
        for (let i = 0; i < pending.length; i++) {
          chunk += dec.decode(pending[i], { stream: true })
        }
        fromPeersAppendText(chunk)
      }
      if (!labeledPeers.has(socket)) {
        if (!awaitingWhois.has(socket)) {
          awaitingWhois.set(socket, [])
          fromPeersBreakIfNeeded()
          lastFromSock = socket
          const ip = socket.remoteAddress
          if (ip) {
            const url = whoisUrlForIp(ip)
            fetch(url)
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
        if (!labeledPeers.has(socket) && !socket.remoteAddress) {
          flushPending(
            `${socket.remoteAddress || '?'}:${socket.remotePort || '?'}`
          )
        }
        return
      }
      if (lastFromSock !== socket) {
        fromPeersBreakIfNeeded()
        fromPeersTailText = null
        lastFromSock = socket
      }
      const dec = peerDec.get(socket)
      fromPeersAppendText(dec.decode(u8, { stream: true }))
    })

    socket.on('close', function () {
      activeSocks.delete(socket)
      if (lastFromSock === socket) lastFromSock = null
      announcePeerSessionClose(socket)
    })

    socket.on('error', function (err) {
      logAppendPlain(
        'socket error: ' + (err && err.message ? err.message : String(err))
      )
    })

    announcePeerSessionOpen(socket)
  })
}

/**
 * @param {number} port
 * @returns {Promise<void>}
 */
async function listenOnPort (port) {
  const srv = createPeerServer()
  try {
    await srv.listen(port)
  } catch (e) {
    try {
      srv.close()
    } catch (_) {}
    throw e
  }
  server = srv
  cachedVirtualListenHost = await resolveVirtualListenHost()
  const vh = cachedVirtualListenHost || pageHostname() || '?'
  logListeningLine(vh, port)
  setListenStatus(vh, port)
}

function listenErrorRetryable (err) {
  const msg = err && err.message ? err.message : String(err)
  return /already|in use|EADDR|bound|listen_err/i.test(msg)
}

async function autoListenFrom (startPort) {
  for (
    let port = startPort;
    port < startPort + LISTEN_PORT_TRIES && port <= 65535;
    port++
  ) {
    try {
      await listenOnPort(port)
      return
    } catch (err) {
      if (server) {
        try {
          server.close()
        } catch (_) {}
        server = null
      }
      if (listenErrorRetryable(err)) continue
      logAppendPlain('listen error: ' + (err && err.message ? err.message : String(err)))
      return
    }
  }
  logAppendPlain(
    'listen error: no free port in range ' +
      startPort +
      '–' +
      (startPort + LISTEN_PORT_TRIES - 1)
  )
}

const TO_PEERS_NAV_KEYS = new Set([
  'ArrowLeft',
  'ArrowRight',
  'ArrowUp',
  'ArrowDown',
  'Home',
  'End',
  'PageUp',
  'PageDown'
])

function snapToPeersCaretEnd () {
  const ta = document.getElementById('toPeers')
  if (!ta || document.activeElement !== ta) return
  const len = ta.value.length
  ta.setSelectionRange(len, len)
}

function onToPeersKeyUp (e) {
  if (e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return
  if (!TO_PEERS_NAV_KEYS.has(e.key)) return
  snapToPeersCaretEnd()
}

function wireUi () {
  const toPeers = document.getElementById('toPeers')
  if (toPeers) {
    toPeers.addEventListener('beforeinput', onToPeersBeforeInput)
    toPeers.addEventListener('input', function (e) {
      onToPeersInput(e.target.value)
    })
    toPeers.addEventListener('keyup', onToPeersKeyUp)
  }
}

function boot () {
  wireUi()
  cachedVirtualListenHost = null
  resetFromPeersDom()
  logAppendPlain('starting listener')
  void autoListenFrom(LISTEN_PORT_START)
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
