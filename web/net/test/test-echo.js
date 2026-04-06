'use strict'

/**
 * Echo server smoke test — bundled with {@link ../shims/net.js} replacing `net`.
 *
 * Open the dev harness with optional query params:
 *   ?proxyHost=127.0.0.1&proxyPort=CONTROL_HTTP_PORT
 * so `setBrowserNetProxy` targets your nospoon control plane (WebSocket `/api/browser-net`).
 */

const net = require('net')

const { setBrowserNetProxy } = net

function applyProxyFromQuery () {
  if (typeof window === 'undefined' || !window.location) return
  const u = new URL(window.location.href)
  const host =
    u.searchParams.get('proxyHost') ||
    u.searchParams.get('controlHost') ||
    ''
  const portStr =
    u.searchParams.get('proxyPort') || u.searchParams.get('controlPort') || ''
  if (!host.trim()) return
  setBrowserNetProxy({
    hostname: host.trim(),
    port: portStr ? Number(portStr) : undefined,
    pathname: '/api/browser-net'
  })
}

applyProxyFromQuery()

const server = net.createServer((socket) => {
  console.log('connection from', socket.remoteAddress, socket.remotePort)

  socket.on('data', (chunk) => {
    console.log('echo:', chunk.toString())
    socket.write(chunk)
  })

  socket.on('end', () => {
    console.log('client disconnected (readable end)')
  })

  socket.on('close', () => {
    console.log('socket closed')
  })

  socket.on('error', (err) => {
    console.error('socket error', err)
  })
})

server.on('listening', () => {
  console.log('listening', server.address())
})

server.listen(7777, () => {
  console.log('listen callback fired')
})
