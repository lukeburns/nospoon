'use strict'

/**
 * TCP middleman: WebSocket multiplexer + IPv4 TCP termination for browser `net` shims.
 *
 * Inbound: decoded inner IPv4 TCP datagrams on the mesh path — {@link #tryConsumeInboundPacket}
 * returns whether this module handled the packet (caller should not pass-through) or declined.
 *
 * Outbound replies: {@link BrowserNetMiddlewareOptions#frameIpv4ForPeerStream} turns an inner IPv4
 * datagram into bytes for `ctx.writeFramed` (length prefix, key-address encoding, etc.).
 *
 * Protocol matches {@link ./browser-net-client.js} (hello, listen, unlisten, end, BIN_TAG binary).
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
 * @typedef {object} BrowserNetMiddlewareOptions
 * @property {function(Buffer): Buffer} frameIpv4ForPeerStream — inner IPv4 datagram → wire bytes for `writeFramed`
 * @property {function(Buffer, InboundPacketCtx): boolean} [shouldAcceptInboundPacket] — if false, decline packet (pass-through). Default accepts all when a listener matches.
 * @property {function(): string | null | undefined} getDefaultListenIpv4 — default bind when `listen` omits `host`
 * @property {function(string): string | null | undefined} [resolveListenHost] — map `host` string to local IPv4
 * @property {string} [webSocketPath] — HTTP upgrade path (default `/api/browser-net`)
 * @property {{ defaultListenNotReady?: string, unknownListenHost?: string }} [messages] — `listen_err` text
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

  /**
   * @param {function(Buffer): void} writeFramed
   * @param {Buffer} innerIpv4
   */
  function sendFramedIpv4 (writeFramed, innerIpv4) {
    try {
      writeFramed(frameIpv4ForPeerStream(innerIpv4))
    } catch (_) {}
  }

  /**
   * @typedef {object} TcpSession
   * @property {string} peerKeyHex
   * @property {string} remoteIp
   * @property {string} localIp
   * @property {number} remotePort
   * @property {number} localPort
   * @property {number} peerIsn
   * @property {number} synOurIsn
   * @property {number} sendNext
   * @property {number} recvNext
   * @property {'syn_rcvd'|'established'|'closed'} state
   * @property {import('ws')} ws
   * @property {number} streamId
   * @property {function(Buffer): void} writeFramed
   */

  /**
   * @param {TcpSession} s
   * @param {number} flags
   * @param {Buffer} [payload]
   */
  function sendTcp (s, flags, payload) {
    const pay = payload && payload.length ? payload : Buffer.alloc(0)
    const f = flags | FLAG_ACK
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

  function closeSession (sk, why) {
    const s = sessions.get(sk)
    if (!s || s.state === 'closed') return
    s.state = 'closed'
    sessions.delete(sk)
    if (s.ws.readyState === 1) {
      try {
        s.ws.send(JSON.stringify({ op: 'end', stream: s.streamId, reason: why || 'closed' }))
      } catch (_) {}
    }
  }

  /**
   * @param {Buffer} packet
   * @param {InboundPacketCtx} ctx
   * @returns {boolean} true if handled here (do not pass-through)
   */
  function tryConsumeInboundPacket (packet, ctx) {
    const parsed = parseIpv4Tcp(packet)
    if (!parsed) return false

    const { srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload } = parsed

    const lk = listenKey(dstIp, dstPort)
    if (!listeners.has(lk)) return false

    if (!shouldAcceptInboundPacket(packet, ctx)) {
      return false
    }

    const sk = sessionKey(ctx.peerKeyHex, srcIp, srcPort, dstIp, dstPort)
    let s = sessions.get(sk)

    if (flags & FLAG_RST) {
      if (s) closeSession(sk, 'rst')
      return true
    }

    if (s && s.state === 'syn_rcvd') {
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
          flags: FLAG_SYN | FLAG_ACK
        })
        sendFramedIpv4(s.writeFramed, pkt)
        return true
      }
    }

    if (s && s.state === 'established') {
      if (flags & FLAG_FIN) {
        if (seq !== s.recvNext) return true
        s.recvNext = (s.recvNext + 1) >>> 0
        sendTcp(s, FLAG_FIN, Buffer.alloc(0))
        closeSession(sk, 'fin')
        return true
      }
      if (payload.length > 0) {
        if (seq !== s.recvNext) {
          return true
        }
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

    if (!s && flags & FLAG_SYN && !(flags & FLAG_ACK)) {
      const rec = listeners.get(lk)
      if (!rec || rec.ws.readyState !== 1) return true

      const peerIsn = seq
      const synOurIsn = crypto.randomBytes(4).readUInt32BE(0) >>> 0
      const streamId = nextStreamIdFor(rec.ws)
      s = {
        peerKeyHex: ctx.peerKeyHex,
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
        writeFramed: ctx.writeFramed
      }
      sessions.set(sk, s)
      attachStreamToWs(rec.ws, sk, s)

      const synAck = buildIpv4TcpPacket({
        srcIp: dstIp,
        dstIp: srcIp,
        srcPort: dstPort,
        dstPort: srcPort,
        seq: synOurIsn,
        ack: (peerIsn + 1) >>> 0,
        flags: FLAG_SYN | FLAG_ACK
      })
      sendFramedIpv4(ctx.writeFramed, synAck)
      return true
    }

    return true
  }

  /** @type {WeakMap<import('ws'), Map<number, string>>} */
  const wsStreamToSession = new WeakMap()

  function nextStreamIdFor (ws) {
    ws._browserNetNextId = (ws._browserNetNextId || 1) >>> 0
    return ws._browserNetNextId++ >>> 0
  }

  /**
   * @param {import('ws')} ws
   * @param {string} sk
   * @param {TcpSession} s
   */
  function attachStreamToWs (ws, sk, s) {
    let m = wsStreamToSession.get(ws)
    if (!m) {
      m = new Map()
      wsStreamToSession.set(ws, m)
    }
    m.set(s.streamId, sk)
  }

  /**
   * @param {import('ws')} ws
   * @param {number} streamId
   * @param {Buffer} payload
   */
  function browserData (ws, streamId, payload) {
    const m = wsStreamToSession.get(ws)
    if (!m) return
    const sk = m.get(streamId)
    const s = sk ? sessions.get(sk) : null
    if (!s || s.state !== 'established') return
    sendTcp(s, FLAG_PSH | FLAG_ACK, payload)
  }

  /**
   * @param {import('ws')} ws
   * @param {number} streamId
   */
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
      for (const sk of m.values()) {
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

  function attachWebSocketConnection (ws) {
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
      if (op === 'listen') {
        const port = Number(msg.port)
        const rid = msg.rid
        const primary = getDefaultListenIpv4()
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
          bindIp = resolveListenHost(rawHost) || null
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
        const primary = getDefaultListenIpv4()
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = ''
        if (rawHost == null) {
          bindIp = primary || ''
        } else if (resolveListenHost) {
          bindIp = resolveListenHost(rawHost) || ''
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

  /**
   * @param {import('http').Server} server
   */
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
        wss.emit('connection', ws, req)
      })
    })
    wss.on('connection', attachWebSocketConnection)
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
