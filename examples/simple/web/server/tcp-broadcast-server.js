'use strict'

/**
 * TCP broadcast service using the browser {@code net} shim — same shape as a tiny Node
 * {@code net.createServer} program, with no knowledge of the DOM.
 *
 * The page is the host: this listens on a virtual port and broadcasts outbound bytes to
 * every connected peer. UI and DNS/whois resolution are injected via {@code options}.
 */

const LISTEN_PORT_START = 23
const LISTEN_PORT_TRIES = 500

module.exports = {
  createTcpBroadcastServer,
  LISTEN_PORT_START,
  LISTEN_PORT_TRIES
}

/**
 * @param {import('net')} net
 * @param {object} options
 * @param {(ip: string, port: number) => Promise<string>} options.resolvePeerLabel
 * @param {object} options.ui
 * @param {(line: string) => void} options.ui.appendLog
 * @param {(label: string, status: 'connected'|'disconnected') => void} options.ui.appendPeerConnectionStatus
 * @param {(label: string) => void} options.ui.beginPeerDataStream
 * @param {(socket: import('net').Socket, text: string) => void} options.ui.appendPeerData
 * @param {(socket: import('net').Socket) => void} [options.ui.onUnlabeledPeerDataStart] — first bytes while whois pending
 */
function createTcpBroadcastServer (net, options) {
  const { resolvePeerLabel, ui } = options
  const appendLog = ui.appendLog
  const appendPeerConnectionStatus = ui.appendPeerConnectionStatus
  const beginPeerDataStream = ui.beginPeerDataStream
  const appendPeerData = ui.appendPeerData
  const onUnlabeledPeerDataStart = ui.onUnlabeledPeerDataStart || function () {}

  const activeSocks = new Set()
  const socketPeerLabel = new WeakMap()
  const peerDec = new WeakMap()
  const labeledPeers = new WeakSet()
  const awaitingWhois = new WeakMap()
  const peerConnectedLineDone = new WeakSet()

  /** @type {import('net').Server | null} */
  let server = null

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
    appendPeerConnectionStatus(label, 'connected')
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
    void resolvePeerLabel(ip, rp)
      .then(function (label) {
        if (!activeSocks.has(socket)) return
        rememberPeerLabel(socket, label)
        tryAppendPeerConnected(socket)
        if (typeof console !== 'undefined' && console.log) {
          console.log('[session] open', label)
        }
      })
      .catch(function () {
        if (!activeSocks.has(socket)) return
        const fallback = `${ip}:${rp}`
        rememberPeerLabel(socket, fallback)
        tryAppendPeerConnected(socket)
        if (typeof console !== 'undefined' && console.log) {
          console.log('[session] open', fallback)
        }
      })
  }

  function announcePeerSessionClose (socket) {
    const ip = socket.remoteAddress
    const rp = socket.remotePort
    const label =
      socketPeerLabel.get(socket) ||
      (ip != null ? `${ip}:${rp != null ? rp : '?'}` : '?')
    appendPeerConnectionStatus(label, 'disconnected')
    if (typeof console !== 'undefined' && console.log) {
      console.log('[session] close', label)
    }
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
          beginPeerDataStream(label)
          const dec = peerDec.get(socket)
          let text = ''
          for (let i = 0; i < pending.length; i++) {
            text += dec.decode(pending[i], { stream: true })
          }
          appendPeerData(socket, text)
        }
        if (!labeledPeers.has(socket)) {
          if (!awaitingWhois.has(socket)) {
            awaitingWhois.set(socket, [])
            onUnlabeledPeerDataStart(socket)
            const ip = socket.remoteAddress
            if (ip) {
              void resolvePeerLabel(ip, socket.remotePort)
                .then(function (resolved) {
                  if (!activeSocks.has(socket)) return
                  const line = resolved && String(resolved).trim()
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
        const dec = peerDec.get(socket)
        appendPeerData(socket, dec.decode(u8, { stream: true }))
      })

      socket.on('close', function () {
        activeSocks.delete(socket)
        announcePeerSessionClose(socket)
      })

      socket.on('error', function (err) {
        appendLog(
          'socket error: ' + (err && err.message ? err.message : String(err))
        )
      })

      announcePeerSessionOpen(socket)
    })
  }

  function broadcastBytes (u8) {
    for (const sock of activeSocks) {
      try {
        sock.write(u8)
      } catch (_) {}
    }
  }

  function listenErrorRetryable (err) {
    const msg = err && err.message ? err.message : String(err)
    return /already|in use|EADDR|bound|listen_err/i.test(msg)
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
  }

  /**
   * @param {number} startPort
   * @param {(port: number) => Promise<void>} onListening — e.g. resolve virtual host and update chrome
   * @returns {Promise<void>}
   */
  async function listenFrom (startPort, onListening) {
    for (
      let port = startPort;
      port < startPort + LISTEN_PORT_TRIES && port <= 65535;
      port++
    ) {
      try {
        await listenOnPort(port)
        await onListening(port)
        return
      } catch (err) {
        if (server) {
          try {
            server.close()
          } catch (_) {}
          server = null
        }
        if (listenErrorRetryable(err)) continue
        appendLog(
          'listen error: ' + (err && err.message ? err.message : String(err))
        )
        return
      }
    }
    appendLog(
      'listen error: no free port in range ' +
        startPort +
        '–' +
        (startPort + LISTEN_PORT_TRIES - 1)
    )
  }

  function close () {
    if (!server) return
    try {
      server.close()
    } catch (_) {}
    server = null
    activeSocks.clear()
  }

  return {
    listenFrom,
    broadcastBytes,
    close,
    /** @returns {import('net').Server | null} */
    getServer: function () {
      return server
    },
    hasConnectedPeers: function () {
      return activeSocks.size > 0
    }
  }
}
