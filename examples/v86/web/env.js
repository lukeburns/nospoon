'use strict'

/**
 * Browser page environment: WebSocket proxy to the mesh control plane, optional whois base URL,
 * and HTTP origin for v86 assets (`/v86/*`, `/browser-net-shim.js` on the control host).
 * Mirrors {@link ../../simple/web/env.js} with {@link resolveControlPanelOrigin} for the emulator.
 */

const net = require('net')
const { setBrowserNetProxy } = net

/** Same as {@code BROWSER_NET_DWEB_WS_PORT} in control-http (browser-net on IPFS loopback). */
const MIDDLE_WS_PORT = 8766

/** Base URL for whois (no trailing slash), e.g. {@code http://whois}. Override: {@code ?whoisOrigin=}. */
let whoisBase = 'http://whois'

/** Topic override from {@code ?topic=} query param — used for localhost dev testing. */
let topicOverride = ''

function _isLoopback (h) {
  return h === 'localhost' || h === '127.0.0.1' || h === '::1'
}

function applyBrowserNetProxyFromLocation () {
  if (typeof window === 'undefined' || !window.location) return
  const u = new URL(window.location.href)

  const topicParam = u.searchParams.get('topic')
  if (topicParam && topicParam.trim()) {
    topicOverride = topicParam.trim()
  }

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
      const h = u.hostname
      const looksLikeCid = !h.includes('.') && h.length >= 46
      setBrowserNetProxy({
        hostname: looksLikeCid ? h : 'middle',
        port: MIDDLE_WS_PORT,
        pathname: '/api/browser-net'
      })
    }
  }
}

/**
 * HTTP origin for v86 static assets ({@code /v86/libv86.mjs}, {@code guest/…}).
 * Default: {@code window.location.origin} so {@code npm run build} + {@code preview} serves everything same-origin.
 * Override with {@code ?controlOrigin=https://host:port} when assets live on the nospoon control plane only.
 * If {@code proxyHost} / {@code controlHost} is set (same as simple), uses {@code http://host:port} (port 80 if omitted).
 * @returns {string}
 */
function resolveControlPanelOrigin () {
  if (typeof window === 'undefined' || !window.location) {
    return 'http://127.0.0.1:80'
  }
  const u = new URL(window.location.href)
  const explicit = u.searchParams.get('controlOrigin')
  if (explicit && explicit.trim()) {
    return explicit.trim().replace(/\/$/, '')
  }
  const host =
    u.searchParams.get('proxyHost') ||
    u.searchParams.get('controlHost') ||
    ''
  const portStr =
    u.searchParams.get('proxyPort') ||
    u.searchParams.get('controlPort') ||
    ''
  if (host.trim()) {
    const h = host.trim()
    const port = portStr ? Number(portStr) : 80
    const p =
      port && Number.isFinite(port) && port !== 80 ? ':' + String(port) : ''
    return 'http://' + h + p
  }
  return u.origin
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
 * Mesh-style virtual bind host: {@code z32.topic} where topic comes from
 * {@code ?topic=} param, page hostname (CID or key), or the full hostname
 * if it already contains a dot (i.e. already {@code key.topic}).
 * @returns {Promise<string | null>}
 */
async function resolveVirtualListenHost () {
  const topic = topicOverride
  const host = topic || pageHostname()
  if (!host) return null
  if (!topic && host.includes('.')) return host
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

/**
 * Resolve a display label for a peer IP using whois (falls back to {@code ip:port}).
 * @param {string} ip
 * @param {number} [port]
 * @returns {Promise<string>}
 */
async function resolvePeerLabelFromWhois (ip, port) {
  const rp = port
  try {
    const r = await fetch(whoisUrlForIp(ip))
    const raw = r.ok ? await r.text() : ''
    const line = raw && raw.trim()
    return line || `${ip}:${rp}`
  } catch (_) {
    return `${ip}:${rp}`
  }
}

function getTopicOverride () {
  return topicOverride
}

module.exports = {
  applyBrowserNetProxyFromLocation,
  resolveControlPanelOrigin,
  whoisUrlForIp,
  whoisUrlSelf,
  pageHostname,
  resolveVirtualListenHost,
  resolvePeerLabelFromWhois,
  getTopicOverride,
  MIDDLE_WS_PORT
}
