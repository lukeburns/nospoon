'use strict'

/**
 * Tiny echo server using the browser `net` shim ({@link ../../../web/net/shims/net.js}).
 * Control plane override: `?proxyHost=HOST&proxyPort=PORT`.
 * IPFS CID pages: optional `?wsHost=&wsPort=` or default `middle:8766` when the host looks like a CID.
 */

const net = require('net')
const { setBrowserNetProxy } = net

/** Same as {@link BROWSER_NET_DWEB_WS_PORT} in control-http (browser-net on IPFS loopback). */
const MIDDLE_WS_PORT = 8766

function isLikelyIpfsCidHostname (host) {
  const h = String(host || '').toLowerCase()
  if (!h || h.includes('.')) return false
  if (h.startsWith('qm') && h.length >= 46) return true
  if (h.startsWith('baf')) return true
  return /^[a-z0-9]{46,}$/.test(h)
}

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
    return
  }
  const wsHost = u.searchParams.get('wsHost')
  if (wsHost && wsHost.trim()) {
    const wsPort = u.searchParams.get('wsPort')
    setBrowserNetProxy({
      hostname: wsHost.trim(),
      port: wsPort ? Number(wsPort) : MIDDLE_WS_PORT,
      pathname: '/api/browser-net'
    })
    return
  }
  if (isLikelyIpfsCidHostname(u.hostname)) {
    setBrowserNetProxy({
      hostname: 'middle',
      port: MIDDLE_WS_PORT,
      pathname: '/api/browser-net'
    })
  }
}

function log (line) {
  const el = document.getElementById('log')
  if (el) el.textContent += String(line) + '\n'
  if (typeof console !== 'undefined' && console.log) console.log(line)
}

applyBrowserNetProxyFromLocation()

const server = net.createServer(function (socket) {
  log('connection from ' + socket.remoteAddress + ':' + socket.remotePort)

  socket.on('data', function (chunk) {
    const s = chunk.toString()
    log('echo: ' + JSON.stringify(s))
    socket.write(chunk)
  })

  socket.on('end', function () {
    log('client ended readable side')
  })

  socket.on('close', function () {
    log('socket closed')
  })

  socket.on('error', function (err) {
    log('socket error: ' + (err && err.message ? err.message : String(err)))
  })
})

server.on('listening', function () {
  log('listening ' + JSON.stringify(server.address()))
})

server.listen(7777, function () {
  log('listen callback fired (port 7777)')
})
