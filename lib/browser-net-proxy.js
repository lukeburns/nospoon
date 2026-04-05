'use strict'

/**
 * Browser `net` shim — control-plane WebSocket multiplexer + mesh-side TCP termination (phases 0–2).
 *
 * ## Protocol (v1, insecure)
 *
 * WebSocket URL: same HTTP origin as the control panel, path `/api/browser-net` (no subprotocol).
 *
 * **Framing**
 * - Text messages: JSON objects with an `op` field.
 * - Binary messages: tag `0x01` + 4-byte big-endian `streamId` + raw payload bytes (browser → mesh TCP payload).
 *
 * **Client → server (JSON)**
 * - `{ "op": "hello", "v": 1 }` — optional; server may reply `{ "op": "hello_ok", "v": 1 }`.
 * - `{ "op": "listen", "port": <number>, "host": "<optional>", "rid": <any> }` — bind on `(resolvedIPv4, port)`. Omit `host` → primary direct-pool TUN IP. Otherwise `host` is either a literal IPv4 for any **local** mesh interface (primary or topic TUN) or mesh DNS for **this** key (`z32` or `z32.topic`, e.g. `z32.spoon`). One registration per `(ip,port)` globally.
 * - `{ "op": "unlisten", "port": <number>, "host": "<optional>", "rid": <any> }`
 * - `{ "op": "end", "stream": <number> }` — half-close / tear down logical stream (sends FIN to peer).
 *
 * **Server → client (JSON)**
 * - `{ "op": "listen_ok", "rid": ... }` / `{ "op": "listen_err", "rid": ..., "error": "..." }`
 * - `{ "op": "accept", "stream": <n>, "local": { "ip", "port" }, "remote": { "ip", "port" } }`
 * - `{ "op": "end", "stream": <n> }`
 * - `{ "op": "error", "message": "..." }`
 *
 * **Server → client (binary)** — same as client binary: `0x01` + stream BE + payload (mesh → browser).
 *
 * ## Dispatch (phase 2)
 * Inbound tunnel IPv4 packets for the **primary** direct-pool mesh address are normally written to TUN.
 * If a browser client has registered `listen` for `(dstIp, dstTcpPort)`, packets for that 5-tuple are handled
 * here instead (proxy wins over TUN). Other ports still use TUN. IPv6 and non-TCP are unchanged.
 *
 * Limitation: only packets arriving on the **Hyperswarm shared inbound** path are intercepted; local
 * hairpin-only flows that never hit that decoder are not multiplexed to the browser.
 */

const crypto = require('crypto')
const { WebSocketServer } = require('ws')
const { encode } = require('./framing')
const { wrapTunnelPayload } = require('./key-address')
const { tunnelSourceAllowedForPeerStream } = require('./routing')
const {
  parseIpv4Tcp,
  buildIpv4TcpPacket,
  FLAG_FIN,
  FLAG_SYN,
  FLAG_RST,
  FLAG_PSH,
  FLAG_ACK
} = require('./browser-net-tcp')

const BIN_TAG = 0x01

/**
 * @param {object} opts
 * @param {function(): import('./key-address').KeyAddressTable} opts.getKa
 * @param {function(): string | null | undefined} opts.getPrimaryTunIp
 * @param {function(string): string | null | undefined} [opts.resolveListenBind] — map `host` string to local mesh IPv4
 */
function createBrowserNetProxy (opts) {
  const getKa = opts.getKa
  const getPrimaryTunIp = opts.getPrimaryTunIp
  const resolveListenBind =
    typeof opts.resolveListenBind === 'function' ? opts.resolveListenBind : null

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

  function replyOnStream (ka, writeFramed, innerIp) {
    try {
      writeFramed(encode(wrapTunnelPayload(ka, innerIp)))
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
   * @property {number} synOurIsn — seq used in SYN-ACK
   * @property {number} sendNext — next outgoing TCP seq
   * @property {number} recvNext — next seq expected from peer
   * @property {'syn_rcvd'|'established'|'closed'} state
   * @property {import('ws')} ws
   * @property {number} streamId
   * @property {function(Buffer): void} writeFramed
   */

  /**
   * @param {TcpSession} s
   * @param {number} flags — TCP flags (FLAG_ACK merged in unless RST-only)
   * @param {Buffer} [payload]
   */
  function sendTcp (s, flags, payload) {
    const pay = payload && payload.length ? payload : Buffer.alloc(0)
    const f = flags | FLAG_ACK
    const ka = getKa()
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
    replyOnStream(ka, s.writeFramed, pkt)
  }

  function sendRst (s) {
    const ka = getKa()
    const pkt = buildIpv4TcpPacket({
      srcIp: s.localIp,
      dstIp: s.remoteIp,
      srcPort: s.localPort,
      dstPort: s.remotePort,
      seq: s.sendNext,
      ack: s.recvNext,
      flags: FLAG_RST | FLAG_ACK
    })
    replyOnStream(ka, s.writeFramed, pkt)
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
   * @param {{ peerKeyHex: string, peerAliasIp: string, writeFramed: function(Buffer): void }} ctx
   * @returns {boolean} true if consumed (do not pass to TUN)
   */
  function tryConsumeInboundPacket (packet, ctx) {
    const ka = getKa()
    const parsed = parseIpv4Tcp(packet)
    if (!parsed) return false

    const { srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload } = parsed

    const lk = listenKey(dstIp, dstPort)
    if (!listeners.has(lk)) return false

    if (
      !tunnelSourceAllowedForPeerStream(packet, ctx.peerAliasIp, ctx.peerKeyHex, ka)
    ) {
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
        const ka = getKa()
        const pkt = buildIpv4TcpPacket({
          srcIp: s.localIp,
          dstIp: s.remoteIp,
          srcPort: s.localPort,
          dstPort: s.remotePort,
          seq: s.synOurIsn,
          ack: (s.peerIsn + 1) >>> 0,
          flags: FLAG_SYN | FLAG_ACK
        })
        replyOnStream(ka, s.writeFramed, pkt)
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
      replyOnStream(ka, ctx.writeFramed, synAck)
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
        const primary = getPrimaryTunIp()
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
                  error: 'primary mesh not ready; set host explicitly'
                })
              )
            } catch (_) {}
            return
          }
        } else if (resolveListenBind) {
          bindIp = resolveListenBind(rawHost) || null
        } else {
          bindIp = primary && rawHost === primary ? primary : null
        }
        if (!bindIp) {
          try {
            ws.send(
              JSON.stringify({
                op: 'listen_err',
                rid,
                error:
                  'host must be a local mesh IPv4 or mesh DNS for this key (z32 or z32.topic e.g. z32.spoon)'
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
        const primary = getPrimaryTunIp()
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = ''
        if (rawHost == null) {
          bindIp = primary || ''
        } else if (resolveListenBind) {
          bindIp = resolveListenBind(rawHost) || ''
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
    server.on('upgrade', function (req, socket, head) {
      const host = req.headers.host || 'localhost'
      let path
      try {
        path = new URL(req.url || '/', `http://${host}`).pathname
      } catch {
        return
      }
      if (path !== '/api/browser-net') return
      wss.handleUpgrade(req, socket, head, function (ws) {
        wss.emit('connection', ws, req)
      })
    })
    wss.on('connection', attachWebSocketConnection)
    return wss
  }

  function getStatus () {
    const primary = getPrimaryTunIp()
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
      primaryTunIp: primary || null,
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
  createBrowserNetProxy,
  BIN_TAG
}
