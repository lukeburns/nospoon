'use strict'

/**
 * Entry: configure the browser-net bridge ({@link ./env.js}), start the TCP broadcast service
 * ({@link ./server/tcp-broadcast-server.js}), and attach a minimal console UI. The static document
 * is the shell; this file is the “client” that also runs the “server”.
 */

const net = require('net')
const {
  applyBrowserNetProxyFromLocation,
  pageHostname,
  resolveVirtualListenHost,
  resolvePeerLabelFromWhois
} = require('./env.js')
const {
  createTcpBroadcastServer,
  LISTEN_PORT_START
} = require('./server/tcp-broadcast-server.js')

applyBrowserNetProxyFromLocation()

const NL = '\n'

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

/** @type {import('net').Socket | null} */
let lastFromSock = null

const tcpService = createTcpBroadcastServer(net, {
  resolvePeerLabel: resolvePeerLabelFromWhois,
  ui: {
    appendLog: logAppendPlain,
    appendPeerConnectionStatus: fromPeersAppendConnectionStatus,
    beginPeerDataStream: fromPeersAppendLabel,
    onUnlabeledPeerDataStart: function (socket) {
      fromPeersBreakIfNeeded()
      lastFromSock = socket
    },
    appendPeerData: function (socket, text) {
      if (lastFromSock !== socket) {
        fromPeersBreakIfNeeded()
        fromPeersTailText = null
        lastFromSock = socket
      }
      fromPeersAppendText(text)
    }
  }
})

let lastToPeersValue = ''

function broadcastBytes (u8) {
  tcpService.broadcastBytes(u8)
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
  if (tcpService.getServer() && tcpService.hasConnectedPeers()) {
    const ins = v.slice(prev.length)
    if (ins.length) broadcastBytes(new TextEncoder().encode(ins))
  }
  lastToPeersValue = v
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

async function boot () {
  wireUi()
  lastFromSock = null
  resetFromPeersDom()
  lastToPeersValue = ''
  const ta = document.getElementById('toPeers')
  if (ta) ta.value = ''
  logAppendPlain('starting listener')
  await tcpService.listenFrom(LISTEN_PORT_START, async function (port) {
    const vh =
      (await resolveVirtualListenHost()) || pageHostname() || '?'
    logListeningLine(vh, port)
    setListenStatus(vh, port)
  })
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function () {
    void boot()
  })
} else {
  void boot()
}
