'use strict'

/**
 * TCP middleman: WebSocket multiplexer + IPv4 TCP termination for browser `net` shims.
 *
 * Inbound: decoded inner IPv4 TCP datagrams — {@link #tryConsumeInboundPacket}.
 * Outbound connect: browser sends `connect`; {@link BrowserNetMiddlewareOptions#getOutboundRoute}
 * supplies `writeFramed` + peer identity for SYN on the correct mesh stream.
 */

const crypto = require('crypto')
const { WebSocketServer } = require('ws')
const {
  parseIpv4Tcp,
  buildIpv4TcpPacket,
  FLAG_FIN,
  FLAG_SYN,
  FLAG_RST,
  FLAG_PSH,
  FLAG_ACK
} = require('./tcp-ipv4')

const BIN_TAG = 0x01

/**
 * @typedef {object} InboundPacketCtx
 * @property {string} peerKeyHex
 * @property {string} peerAliasIp
 * @property {function(Buffer): void} writeFramed
 */

/**
 * @typedef {object} OutboundRoute
 * @property {string} peerKeyHex
 * @property {string} peerAliasIp
 * @property {function(Buffer): void} writeFramed
 */

/**
 * @typedef {object} BrowserNetMiddlewareOptions
 * @property {function(Buffer): Buffer} frameIpv4ForPeerStream
 * @property {function(Buffer, InboundPacketCtx): boolean} [shouldAcceptInboundPacket]
 * @property {function(import('ws')|undefined): string | null | undefined} getDefaultListenIpv4 — per-socket default bind (`ws` omitted in status snapshots)
 * @property {function(string, import('ws')|undefined): string | null | undefined} [resolveListenHost]
 * @property {function(string, import('ws')|undefined): string | null | undefined} [resolveConnectHost] — non-IPv4 `connect` host
 * @property {function(string, import('ws')|undefined): OutboundRoute | null | undefined} [getOutboundRoute] — required for `connect` op
 * @property {function(import('ws'), import('http').IncomingMessage): (void|Promise<void>)} [prepareWebSocket] — runs before JSON/binary handlers (e.g. Origin policy + topic join)
 * @property {string} [webSocketPath]
 * @property {{ defaultListenNotReady?: string, unknownListenHost?: string }} [messages]
 */

/**
 * @param {BrowserNetMiddlewareOptions} opts
 */
function createBrowserNetMiddleware (opts) {
  if (typeof opts.frameIpv4ForPeerStream !== 'function') {
    throw new Error('createBrowserNetMiddleware: frameIpv4ForPeerStream is required')
  }
  if (typeof opts.getDefaultListenIpv4 !== 'function') {
    throw new Error('createBrowserNetMiddleware: getDefaultListenIpv4 is required')
  }

  const frameIpv4ForPeerStream = opts.frameIpv4ForPeerStream
  const getDefaultListenIpv4 = opts.getDefaultListenIpv4
  const resolveListenHost =
    typeof opts.resolveListenHost === 'function' ? opts.resolveListenHost : null
  const prepareWebSocket =
    typeof opts.prepareWebSocket === 'function' ? opts.prepareWebSocket : null
  const resolveConnectHost =
    typeof opts.resolveConnectHost === 'function' ? opts.resolveConnectHost : null
  const getOutboundRoute =
    typeof opts.getOutboundRoute === 'function' ? opts.getOutboundRoute : null
  const shouldAcceptInboundPacket =
    typeof opts.shouldAcceptInboundPacket === 'function'
      ? opts.shouldAcceptInboundPacket
      : function () {
        return true
      }
  const webSocketPath =
    opts.webSocketPath != null && String(opts.webSocketPath).trim() !== ''
      ? String(opts.webSocketPath).trim()
      : '/api/browser-net'

  const msg = opts.messages || {}
  const MSG_DEFAULT_LISTEN = msg.defaultListenNotReady ||
    'default listen address not ready; set host explicitly'
  const MSG_UNKNOWN_HOST = msg.unknownListenHost ||
    'invalid listen host; set host explicitly or configure resolveListenHost'

  /** @type {Map<string, { ws: import('ws'), clientId: string }>} */
  const listeners = new Map()
  /** @type {Map<string, TcpSession>} */
  const sessions = new Map()

  function listenKey (host, port) {
    return `${host}:${port}`
  }

  function sessionKey (peerKeyHex, remoteIp, remotePort, localIp, localPort) {
    return `${peerKeyHex}:${remoteIp}:${remotePort}:${localIp}:${localPort}`
  }

  function sendFramedIpv4 (writeFramed, innerIpv4) {
    try {
      writeFramed(frameIpv4ForPeerStream(innerIpv4))
    } catch (_) {}
  }

  /**
   * @typedef {object} TcpSession
   * @property {string} peerKeyHex
   * @property {string} peerAliasIp
   * @property {string} remoteIp
   * @property {string} localIp
   * @property {number} remotePort
   * @property {number} localPort
   * @property {number} peerIsn
   * @property {number} synOurIsn
   * @property {number} sendNext
   * @property {number} recvNext
   * @property {'syn_sent'|'syn_rcvd'|'established'|'closed'} state
   * @property {import('ws')} ws
   * @property {number} streamId
   * @property {function(Buffer): void} writeFramed
   * @property {boolean} [outbound]
   * @property {string} [connectRid]
   */

  /**
   * Merge TCP flags; bare SYN (client handshake) must not set ACK.
   * @param {number} flags
   */
  function tcpFlagsWithAck (flags) {
    if (flags & FLAG_RST) return flags
    if ((flags & FLAG_SYN) && !(flags & FLAG_ACK)) return flags
    return flags | FLAG_ACK
  }

  /**
   * @param {TcpSession} s
   * @param {number} flags
   * @param {Buffer} [payload]
   */
  function sendTcp (s, flags, payload) {
    const pay = payload && payload.length ? payload : Buffer.alloc(0)
    const f = tcpFlagsWithAck(flags)
    const pkt = buildIpv4TcpPacket({
      srcIp: s.localIp,
      dstIp: s.remoteIp,
      srcPort: s.localPort,
      dstPort: s.remotePort,
      seq: s.sendNext,
      ack: s.recvNext,
      flags: f,
      payload: pay
    })
    let adv = pay.length
    if (flags & FLAG_SYN) adv = (adv + 1) >>> 0
    if (flags & FLAG_FIN) adv = (adv + 1) >>> 0
    if (adv) s.sendNext = (s.sendNext + adv) >>> 0
    sendFramedIpv4(s.writeFramed, pkt)
  }

  function sendRst (s) {
    const pkt = buildIpv4TcpPacket({
      srcIp: s.localIp,
      dstIp: s.remoteIp,
      srcPort: s.localPort,
      dstPort: s.remotePort,
      seq: s.sendNext,
      ack: s.recvNext,
      flags: FLAG_RST | FLAG_ACK
    })
    sendFramedIpv4(s.writeFramed, pkt)
  }

  /** @type {WeakMap<import('ws'), Map<number, string>>} */
  const wsStreamToSession = new WeakMap()

  function detachStreamFromWs (ws, streamId) {
    const m = wsStreamToSession.get(ws)
    if (!m) return
    m.delete(streamId)
    if (m.size === 0) wsStreamToSession.delete(ws)
  }

  function closeSession (sk, why) {
    const s = sessions.get(sk)
    if (!s || s.state === 'closed') return
    const pendingOutbound = s.outbound === true && s.state === 'syn_sent' && s.connectRid
    const rid = s.connectRid
    const streamId = s.streamId
    const ws = s.ws
    s.state = 'closed'
    sessions.delete(sk)
    detachStreamFromWs(ws, streamId)
    if (ws.readyState === 1) {
      try {
        if (pendingOutbound && rid) {
          ws.send(
            JSON.stringify({
              op: 'connect_err',
              rid,
              error: String(why || 'closed')
            })
          )
        } else {
          ws.send(JSON.stringify({ op: 'end', stream: streamId, reason: why || 'closed' }))
        }
      } catch (_) {}
    }
  }

  function isPortFree (localIp, port) {
    const k = listenKey(localIp, port)
    if (listeners.has(k)) return false
    for (const s of sessions.values()) {
      if (s.state === 'closed') continue
      if (s.localIp === localIp && s.localPort === port) return false
    }
    return true
  }

  function allocateEphemeralPort (localIp) {
    const lo = 49152
    const hi = 65535
    const span = hi - lo + 1
    const start = lo + (crypto.randomBytes(2).readUInt16BE(0) % span)
    for (let i = 0; i < span; i++) {
      const p = lo + ((start - lo + i) % span)
      if (isPortFree(localIp, p)) return p
    }
    return null
  }

  function ipv4Literal (s) {
    const t = String(s || '').trim()
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return null
    const p = t.split('.').map((x) => Number(x))
    if (p.some((n) => n > 255)) return null
    return t
  }

  /**
   * @param {Buffer} packet
   * @param {InboundPacketCtx} ctx
   * @returns {boolean}
   */
  function tryConsumeInboundPacket (packet, ctx) {
    const parsed = parseIpv4Tcp(packet)
    if (!parsed) return false

    const { srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload } = parsed
    const sk = sessionKey(ctx.peerKeyHex, srcIp, srcPort, dstIp, dstPort)
    let s = sessions.get(sk)

    if (s) {
      if (!shouldAcceptInboundPacket(packet, ctx)) return false

      if (flags & FLAG_RST) {
        closeSession(sk, 'rst')
        return true
      }

      if (s.state === 'syn_sent' && s.outbound) {
        if ((flags & FLAG_SYN) && (flags & FLAG_ACK)) {
          if (ack !== ((s.synOurIsn + 1) >>> 0)) return true
          s.peerIsn = seq >>> 0
          s.recvNext = (s.peerIsn + 1) >>> 0
          sendTcp(s, FLAG_ACK, Buffer.alloc(0))
          s.state = 'established'
          if (s.ws.readyState === 1 && s.connectRid) {
            try {
              s.ws.send(
                JSON.stringify({
                  op: 'connected',
                  rid: s.connectRid,
                  stream: s.streamId,
                  local: { ip: s.localIp, port: s.localPort },
                  remote: { ip: s.remoteIp, port: s.remotePort }
                })
              )
            } catch (_) {}
            s.connectRid = undefined
          }
          return true
        }
        return true
      }

      if (s.state === 'syn_rcvd') {
        if (flags & FLAG_ACK && !(flags & FLAG_SYN)) {
          const expectAck = (s.synOurIsn + 1) >>> 0
          if (ack === expectAck) {
            s.state = 'established'
            try {
              s.ws.send(
                JSON.stringify({
                  op: 'accept',
                  stream: s.streamId,
                  local: { ip: s.localIp, port: s.localPort },
                  remote: { ip: s.remoteIp, port: s.remotePort }
                })
              )
            } catch (_) {}
          }
          return true
        }
        if (flags & FLAG_SYN && !(flags & FLAG_ACK)) {
          const pkt = buildIpv4TcpPacket({
            srcIp: s.localIp,
            dstIp: s.remoteIp,
            srcPort: s.localPort,
            dstPort: s.remotePort,
            seq: s.synOurIsn,
            ack: (s.peerIsn + 1) >>> 0,
            flags: tcpFlagsWithAck(FLAG_SYN | FLAG_ACK)
          })
          sendFramedIpv4(s.writeFramed, pkt)
          return true
        }
      }

      if (s.state === 'established') {
        if (flags & FLAG_FIN) {
          if (seq !== s.recvNext) return true
          s.recvNext = (s.recvNext + 1) >>> 0
          sendTcp(s, FLAG_FIN, Buffer.alloc(0))
          closeSession(sk, 'fin')
          return true
        }
        if (payload.length > 0) {
          if (seq !== s.recvNext) return true
          s.recvNext = (s.recvNext + payload.length) >>> 0
          sendTcp(s, FLAG_ACK, Buffer.alloc(0))
          if (s.ws.readyState === 1) {
            const hdr = Buffer.allocUnsafe(5)
            hdr[0] = BIN_TAG
            hdr.writeUInt32BE(s.streamId >>> 0, 1)
            try {
              s.ws.send(Buffer.concat([hdr, payload]), { binary: true })
            } catch (_) {}
          }
          return true
        }
        return true
      }

      return true
    }

    if (flags & FLAG_RST) return false

    if (!shouldAcceptInboundPacket(packet, ctx)) return false

    if (flags & FLAG_SYN && !(flags & FLAG_ACK)) {
      const lk = listenKey(dstIp, dstPort)
      if (!listeners.has(lk)) return false

      const rec = listeners.get(lk)
      if (!rec || rec.ws.readyState !== 1) return true

      const peerIsn = seq
      const synOurIsn = crypto.randomBytes(4).readUInt32BE(0) >>> 0
      const streamId = nextStreamIdFor(rec.ws)
      const inbound = {
        peerKeyHex: ctx.peerKeyHex,
        peerAliasIp: ctx.peerAliasIp,
        remoteIp: srcIp,
        localIp: dstIp,
        remotePort: srcPort,
        localPort: dstPort,
        peerIsn,
        synOurIsn,
        sendNext: (synOurIsn + 1) >>> 0,
        recvNext: (peerIsn + 1) >>> 0,
        state: 'syn_rcvd',
        ws: rec.ws,
        streamId,
        writeFramed: ctx.writeFramed,
        outbound: false
      }
      sessions.set(sk, inbound)
      attachStreamToWs(rec.ws, sk, inbound)

      const synAck = buildIpv4TcpPacket({
        srcIp: dstIp,
        dstIp: srcIp,
        srcPort: dstPort,
        dstPort: srcPort,
        seq: synOurIsn,
        ack: (peerIsn + 1) >>> 0,
        flags: tcpFlagsWithAck(FLAG_SYN | FLAG_ACK)
      })
      sendFramedIpv4(ctx.writeFramed, synAck)
      return true
    }

    return false
  }

  function nextStreamIdFor (ws) {
    ws._browserNetNextId = (ws._browserNetNextId || 1) >>> 0
    return ws._browserNetNextId++ >>> 0
  }

  function attachStreamToWs (ws, sk, s) {
    let m = wsStreamToSession.get(ws)
    if (!m) {
      m = new Map()
      wsStreamToSession.set(ws, m)
    }
    m.set(s.streamId, sk)
  }

  function browserData (ws, streamId, payload) {
    const m = wsStreamToSession.get(ws)
    if (!m) return
    const sk = m.get(streamId)
    const s = sk ? sessions.get(sk) : null
    if (!s || s.state !== 'established') return
    sendTcp(s, FLAG_PSH | FLAG_ACK, payload)
  }

  function browserEnd (ws, streamId) {
    const m = wsStreamToSession.get(ws)
    if (!m) return
    const sk = m.get(streamId)
    const s = sk ? sessions.get(sk) : null
    if (!s || s.state !== 'established') return
    sendTcp(s, FLAG_FIN, Buffer.alloc(0))
    closeSession(sk, 'local_end')
  }

  function cleanupWs (ws) {
    const m = wsStreamToSession.get(ws)
    if (m) {
      for (const sk of new Set(m.values())) {
        const s = sessions.get(sk)
        if (s && s.state !== 'closed') sendRst(s)
        closeSession(sk, 'ws_close')
      }
      wsStreamToSession.delete(ws)
    }
    for (const [k, rec] of listeners.entries()) {
      if (rec.ws === ws) listeners.delete(k)
    }
  }

  /**
   * @param {import('ws')} ws
   * @param {import('http').IncomingMessage} [_req]
   */
  function attachWebSocketConnection (ws, _req) {
    ws._browserNetClientId = crypto.randomBytes(4).toString('hex')
    ws.on('message', function (data, isBinary) {
      if (isBinary && Buffer.isBuffer(data)) {
        if (data.length < 5 || data[0] !== BIN_TAG) return
        const sid = data.readUInt32BE(1) >>> 0
        browserData(ws, sid, data.subarray(5))
        return
      }
      let msg
      try {
        msg = JSON.parse(String(data))
      } catch {
        return
      }
      if (!msg || typeof msg !== 'object') return
      const op = msg.op
      if (op === 'hello') {
        try {
          ws.send(JSON.stringify({ op: 'hello_ok', v: 1 }))
        } catch (_) {}
        return
      }
      if (op === 'connect') {
        const rid = msg.rid
        if (!getOutboundRoute) {
          try {
            ws.send(
              JSON.stringify({
                op: 'connect_err',
                rid,
                error: 'connect not configured (getOutboundRoute missing)'
              })
            )
          } catch (_) {}
          return
        }
        const port = Number(msg.port)
        if (!Number.isFinite(port) || port < 1 || port > 65535) {
          try {
            ws.send(
              JSON.stringify({ op: 'connect_err', rid, error: 'bad port' })
            )
          } catch (_) {}
          return
        }
        const hostRaw =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : ''
        if (!hostRaw) {
          try {
            ws.send(
              JSON.stringify({ op: 'connect_err', rid, error: 'host required' })
            )
          } catch (_) {}
          return
        }
        let remoteIp = ipv4Literal(hostRaw)
        if (!remoteIp && resolveConnectHost) {
          remoteIp = resolveConnectHost(hostRaw, ws) || null
        }
        if (!remoteIp) {
          try {
            ws.send(
              JSON.stringify({
                op: 'connect_err',
                rid,
                error: 'unknown remote host (use IPv4 or configure resolveConnectHost)'
              })
            )
          } catch (_) {}
          return
        }
        const route = getOutboundRoute(remoteIp, ws)
        if (!route || typeof route.writeFramed !== 'function') {
          try {
            ws.send(
              JSON.stringify({
                op: 'connect_err',
                rid,
                error: 'no route to host (offline or unroutable)'
              })
            )
          } catch (_) {}
          return
        }
        const primary = getDefaultListenIpv4(ws)
        const rawLocal =
          msg.localHost != null && String(msg.localHost).trim() !== ''
            ? String(msg.localHost).trim()
            : null
        let localIp = null
        if (rawLocal == null) {
          localIp = primary || null
        } else if (resolveListenHost) {
          localIp = resolveListenHost(rawLocal, ws) || ipv4Literal(rawLocal)
        } else {
          localIp = ipv4Literal(rawLocal)
          if (localIp && primary && localIp !== primary) localIp = null
        }
        if (!localIp) {
          try {
            ws.send(
              JSON.stringify({
                op: 'connect_err',
                rid,
                error: MSG_DEFAULT_LISTEN
              })
            )
          } catch (_) {}
          return
        }
        const localPort = allocateEphemeralPort(localIp)
        if (localPort == null) {
          try {
            ws.send(
              JSON.stringify({
                op: 'connect_err',
                rid,
                error: 'no ephemeral port available'
              })
            )
          } catch (_) {}
          return
        }
        const synOurIsn = crypto.randomBytes(4).readUInt32BE(0) >>> 0
        const streamId = nextStreamIdFor(ws)
        const sk = sessionKey(
          route.peerKeyHex,
          remoteIp,
          port,
          localIp,
          localPort
        )
        const out = {
          peerKeyHex: route.peerKeyHex,
          peerAliasIp: route.peerAliasIp,
          remoteIp,
          localIp,
          remotePort: port,
          localPort,
          peerIsn: 0,
          synOurIsn,
          sendNext: synOurIsn >>> 0,
          recvNext: 0,
          state: 'syn_sent',
          ws,
          streamId,
          writeFramed: route.writeFramed,
          outbound: true,
          connectRid: rid
        }
        sessions.set(sk, out)
        attachStreamToWs(ws, sk, out)
        sendTcp(out, FLAG_SYN, Buffer.alloc(0))
        return
      }
      if (op === 'listen') {
        const port = Number(msg.port)
        const rid = msg.rid
        const primary = getDefaultListenIpv4(ws)
        if (!Number.isFinite(port) || port < 1 || port > 65535) {
          try {
            ws.send(
              JSON.stringify({
                op: 'listen_err',
                rid,
                error: 'bad port'
              })
            )
          } catch (_) {}
          return
        }
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = null
        if (rawHost == null) {
          bindIp = primary || null
          if (!bindIp) {
            try {
              ws.send(
                JSON.stringify({
                  op: 'listen_err',
                  rid,
                  error: MSG_DEFAULT_LISTEN
                })
              )
            } catch (_) {}
            return
          }
        } else if (resolveListenHost) {
          bindIp = resolveListenHost(rawHost, ws) || null
        } else {
          bindIp = primary && rawHost === primary ? primary : null
        }
        if (!bindIp) {
          try {
            ws.send(
              JSON.stringify({
                op: 'listen_err',
                rid,
                error: MSG_UNKNOWN_HOST
              })
            )
          } catch (_) {}
          return
        }
        const host = bindIp
        const k = listenKey(host, port)
        const prev = listeners.get(k)
        if (prev && prev.ws !== ws) {
          try {
            ws.send(
              JSON.stringify({
                op: 'listen_err',
                rid,
                error: 'port already bound by another session'
              })
            )
          } catch (_) {}
          return
        }
        listeners.set(k, { ws, clientId: ws._browserNetClientId })
        try {
          ws.send(JSON.stringify({ op: 'listen_ok', rid, bind: { ip: host, port } }))
        } catch (_) {}
        return
      }
      if (op === 'unlisten') {
        const port = Number(msg.port)
        const primary = getDefaultListenIpv4(ws)
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = ''
        if (rawHost == null) {
          bindIp = primary || ''
        } else if (resolveListenHost) {
          bindIp = resolveListenHost(rawHost, ws) || ''
        } else {
          bindIp = primary && rawHost === primary ? primary : ''
        }
        const host = bindIp
        const rid = msg.rid
        const k = listenKey(host, port)
        const cur = listeners.get(k)
        if (cur && cur.ws === ws) listeners.delete(k)
        try {
          ws.send(JSON.stringify({ op: 'unlisten_ok', rid }))
        } catch (_) {}
        return
      }
      if (op === 'end') {
        browserEnd(ws, Number(msg.stream) >>> 0)
        return
      }
    })

    ws.on('close', function () {
      cleanupWs(ws)
    })
  }

  function attachToHttpServer (server) {
    const wss = new WebSocketServer({ noServer: true })
    const pathNorm = webSocketPath.startsWith('/') ? webSocketPath : `/${webSocketPath}`
    server.on('upgrade', function (req, socket, head) {
      const host = req.headers.host || 'localhost'
      let path
      try {
        path = new URL(req.url || '/', `http://${host}`).pathname
      } catch {
        return
      }
      if (path !== pathNorm) return
      wss.handleUpgrade(req, socket, head, function (ws) {
        function attach () {
          attachWebSocketConnection(ws, req)
        }
        if (prepareWebSocket) {
          Promise.resolve(prepareWebSocket(ws, req))
            .then(attach)
            .catch(function () {
              try {
                ws.close()
              } catch (_) {}
            })
        } else {
          attach()
        }
      })
    })
    return wss
  }

  function getStatus () {
    const def = getDefaultListenIpv4()
    const listenerList = []
    for (const [k, rec] of listeners.entries()) {
      const d = k.lastIndexOf(':')
      listenerList.push({
        bind: k.slice(0, d),
        port: Number(k.slice(d + 1)),
        clientId: rec.clientId
      })
    }
    const streamList = []
    for (const s of sessions.values()) {
      streamList.push({
        stream: s.streamId,
        state: s.state,
        outbound: !!s.outbound,
        peerKeyHex: s.peerKeyHex,
        local: { ip: s.localIp, port: s.localPort },
        remote: { ip: s.remoteIp, port: s.remotePort }
      })
    }
    return {
      defaultListenIpv4: def || null,
      primaryTunIp: def || null,
      listeners: listenerList,
      streams: streamList
    }
  }

  return {
    tryConsumeInboundPacket,
    attachToHttpServer,
    getStatus
  }
}

module.exports = {
  createBrowserNetMiddleware,
  BIN_TAG
}
