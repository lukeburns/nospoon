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
const RAW_IP_TAG = 0x02
const IP_PROTO_UDP = 17
const DNS_PORT = 53

// ---------------------------------------------------------------------------
// Minimal DNS wire-format helpers (A-record queries only)
// ---------------------------------------------------------------------------

/**
 * Parse the QNAME from a DNS query payload starting at offset 12.
 * Returns { name, endOffset } or null.
 */
function parseDnsQname (buf, off) {
  const labels = []
  let i = off
  while (i < buf.length) {
    const len = buf[i]
    if (len === 0) { i++; break }
    if ((len & 0xc0) !== 0) return null // compressed — not expected in queries from stub resolvers
    i++
    if (i + len > buf.length) return null
    labels.push(buf.subarray(i, i + len).toString('ascii'))
    i += len
  }
  return labels.length ? { name: labels.join('.'), endOffset: i } : null
}

/**
 * Build a minimal DNS A-record response.
 * @param {Buffer} queryPkt  — full DNS query payload (header + question)
 * @param {string} name      — QNAME (dotted, for logging only)
 * @param {string|null} ipv4 — resolved IPv4 or null for NODATA (empty answer)
 * @returns {Buffer}
 */
function buildDnsResponse (queryPkt, name, ipv4) {
  const id = queryPkt.readUInt16BE(0)
  const qnameEnd = parseDnsQname(queryPkt, 12)
  if (!qnameEnd) return null
  const questionEnd = qnameEnd.endOffset + 4 // QTYPE(2) + QCLASS(2)
  const questionSection = queryPkt.subarray(12, questionEnd)

  if (!ipv4) {
    // NODATA — name may exist but no A record yet (avoids negative caching)
    const resp = Buffer.alloc(12 + questionSection.length)
    resp.writeUInt16BE(id, 0)
    resp.writeUInt16BE(0x8180, 2) // QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
    resp.writeUInt16BE(1, 4)      // QDCOUNT
    questionSection.copy(resp, 12)
    return resp
  }

  const parts = ipv4.split('.').map(Number)
  // Header(12) + question + answer(16: ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4))
  const resp = Buffer.alloc(12 + questionSection.length + 16)
  resp.writeUInt16BE(id, 0)
  resp.writeUInt16BE(0x8180, 2) // QR=1, RD=1, RA=1, RCODE=0
  resp.writeUInt16BE(1, 4)      // QDCOUNT
  resp.writeUInt16BE(1, 6)      // ANCOUNT
  questionSection.copy(resp, 12)
  let off = 12 + questionSection.length
  resp.writeUInt16BE(0xc00c, off); off += 2       // NAME pointer to QNAME
  resp.writeUInt16BE(1, off); off += 2             // TYPE A
  resp.writeUInt16BE(1, off); off += 2             // CLASS IN
  resp.writeUInt32BE(60, off); off += 4            // TTL 60s
  resp.writeUInt16BE(4, off); off += 2             // RDLENGTH
  resp[off++] = parts[0]; resp[off++] = parts[1]
  resp[off++] = parts[2]; resp[off++] = parts[3]
  return resp
}

/**
 * Build a UDP/IPv4 packet wrapping a DNS response payload.
 * @param {string} srcIp
 * @param {string} dstIp
 * @param {number} srcPort
 * @param {number} dstPort
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function buildUdpIpv4 (srcIp, dstIp, srcPort, dstPort, payload) {
  const ipLen = 20 + 8 + payload.length
  const buf = Buffer.alloc(ipLen)
  // IPv4 header
  buf[0] = 0x45             // ver=4, ihl=5
  buf.writeUInt16BE(ipLen, 2)
  buf.writeUInt16BE(0x4000, 6) // DF
  buf[8] = 64               // TTL
  buf[9] = IP_PROTO_UDP
  const srcParts = srcIp.split('.').map(Number)
  const dstParts = dstIp.split('.').map(Number)
  buf[12] = srcParts[0]; buf[13] = srcParts[1]; buf[14] = srcParts[2]; buf[15] = srcParts[3]
  buf[16] = dstParts[0]; buf[17] = dstParts[1]; buf[18] = dstParts[2]; buf[19] = dstParts[3]
  // IP checksum
  let cksum = 0
  for (let j = 0; j < 20; j += 2) cksum += buf.readUInt16BE(j)
  while (cksum > 0xffff) cksum = (cksum & 0xffff) + (cksum >> 16)
  buf.writeUInt16BE((~cksum) & 0xffff, 10)
  // UDP header
  const udpOff = 20
  buf.writeUInt16BE(srcPort, udpOff)
  buf.writeUInt16BE(dstPort, udpOff + 2)
  buf.writeUInt16BE(8 + payload.length, udpOff + 4)
  // UDP checksum = 0 (optional in IPv4)
  payload.copy(buf, udpOff + 8)
  return buf
}

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
 * @property {function(string, import('ws')): string | null} [resolveDns] — resolve hostname → IPv4 for bridge-scoped DNS; return null for NXDOMAIN
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
  const resolveDns =
    typeof opts.resolveDns === 'function' ? opts.resolveDns : null
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
  /** @type {Map<string, { ws: import('ws'), clientId: string }>} ip → owner */
  const interfaces = new Map()
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
    // Interface mode: if the dest IP is bound to a WebSocket, forward the
    // entire raw IP packet without parsing TCP or managing sessions.
    if (packet.length >= 20) {
      const dstIpRaw = `${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}`
      const iface = interfaces.get(dstIpRaw)
      if (iface && iface.ws.readyState === 1) {
        const hdr = Buffer.allocUnsafe(1)
        hdr[0] = RAW_IP_TAG
        try {
          iface.ws.send(Buffer.concat([hdr, packet]), { binary: true })
        } catch (_) {}
        return true
      }
    }

    const parsed = parseIpv4Tcp(packet)
    if (!parsed) return false

    const { srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload } = parsed
    const sk = sessionKey(ctx.peerKeyHex, srcIp, srcPort, dstIp, dstPort)
    let s = sessions.get(sk)

    if (s) {
      // Source was validated when this session started (inbound bare SYN at open, or outbound
      // connect’s first peer reply). Re-running shouldAccept on later segments (especially the
      // client’s final ACK after our SYN-ACK) can spuriously fail and leave inbound sessions stuck
      // in syn_rcvd with no `accept` to the browser.

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
    for (const [k, rec] of interfaces.entries()) {
      if (rec.ws === ws) interfaces.delete(k)
    }
  }

  /**
   * @param {import('ws')} ws
   * @param {import('http').IncomingMessage} [_req]
   * @returns {function(import('ws').RawData, boolean): void}
   */
  function attachWebSocketConnection (ws, _req) {
    ws._browserNetClientId = crypto.randomBytes(4).toString('hex')
    const _cid = ws._browserNetClientId
    console.error('[ws-lifecycle] open cid=' + _cid)
    ws.on('close', function (code, reason) { console.error('[ws-lifecycle] close cid=' + _cid + ' code=' + code + ' reason=' + reason) })
    ws.on('error', function (err) { console.error('[ws-lifecycle] error cid=' + _cid + ' ' + (err && err.message)) })
    const _origSend = ws.send.bind(ws)
    ws.send = function (data, opts, cb) {
      if (Buffer.isBuffer(data) && data.length > 0 && data[0] === RAW_IP_TAG) {
        const p = data.subarray ? data.subarray(1) : data.slice(1)
        const src = p.length >= 16 ? (p[12] + '.' + p[13] + '.' + p[14] + '.' + p[15]) : '?'
        const dst = p.length >= 20 ? (p[16] + '.' + p[17] + '.' + p[18] + '.' + p[19]) : '?'
        console.error('[ws-tx→browser] cid=' + _cid + ' RAW_IP src=' + src + ' dst=' + dst + ' len=' + p.length)
      }
      return _origSend(data, opts, cb)
    }
    function browserNetWsMessage (data, isBinary) {
      if (isBinary && Buffer.isBuffer(data)) {
        console.error('[ws-rx←browser] cid=' + _cid + ' binary len=' + data.length + ' tag=0x' + data[0].toString(16))
        if (data.length < 2) return
        if (data[0] === RAW_IP_TAG) {
          const pkt = data.subarray(1)
          if (pkt.length < 20) return
          const srcIp = `${pkt[12]}.${pkt[13]}.${pkt[14]}.${pkt[15]}`
          const dstIp = `${pkt[16]}.${pkt[17]}.${pkt[18]}.${pkt[19]}`

          // Intercept DNS queries (UDP dst port 53) and resolve in-process.
          const proto = pkt[9]
          if (resolveDns && proto === IP_PROTO_UDP && pkt.length >= 28) {
            const ihl = (pkt[0] & 0x0f) * 4
            const udpDstPort = pkt.readUInt16BE(ihl + 2)
            if (udpDstPort === DNS_PORT) {
              const udpSrcPort = pkt.readUInt16BE(ihl)
              const dnsPayload = pkt.subarray(ihl + 8)
              if (dnsPayload.length >= 12) {
                const qr = parseDnsQname(dnsPayload, 12)
                if (qr) {
                  const qtype = qr.endOffset + 1 < dnsPayload.length
                    ? dnsPayload.readUInt16BE(qr.endOffset)
                    : 0
                  if (qtype === 1) { // A record
                    const resolvedIp = resolveDns(qr.name, ws)
                    const dnsResp = buildDnsResponse(dnsPayload, qr.name, resolvedIp)
                    if (dnsResp) {
                      const ipResp = buildUdpIpv4(dstIp, srcIp, DNS_PORT, udpSrcPort, dnsResp)
                      const hdr = Buffer.allocUnsafe(1)
                      hdr[0] = RAW_IP_TAG
                      try { ws.send(Buffer.concat([hdr, ipResp])) } catch (_) {}
                      console.error('[dns] ' + qr.name + ' → ' + (resolvedIp || 'NXDOMAIN'))
                    }
                    return
                  }
                }
              }
            }
          }

          // Interface mode: raw IP packet from the browser, route to mesh.
          if (!getOutboundRoute) return
          const route = getOutboundRoute(dstIp, ws)
          if (route && typeof route.writeFramed === 'function') {
            console.error('[iface-tx] dst=' + dstIp + ' len=' + pkt.length + ' → route OK peer=' + route.peerKeyHex.slice(0, 8))
            sendFramedIpv4(route.writeFramed, pkt)
          } else {
            console.error('[iface-tx] dst=' + dstIp + ' len=' + pkt.length + ' → NO ROUTE')
          }
          return
        }
        if (data[0] === BIN_TAG) {
          if (data.length < 5) return
          const sid = data.readUInt32BE(1) >>> 0
          browserData(ws, sid, data.subarray(5))
          return
        }
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
      console.error('[ws-rx←browser] cid=' + _cid + ' json op=' + op)
      if (op === 'hello') {
        try {
          ws.send(JSON.stringify({ op: 'hello_ok', v: 1 }))
        } catch (_) {}
        return
      }
      if (op === 'bind_interface') {
        const rid = msg.rid
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = null
        if (rawHost == null) {
          bindIp = getDefaultListenIpv4(ws) || null
        } else if (resolveListenHost) {
          bindIp = resolveListenHost(rawHost, ws) || ipv4Literal(rawHost)
        } else {
          bindIp = ipv4Literal(rawHost)
        }
        if (!bindIp) {
          try {
            ws.send(JSON.stringify({ op: 'bind_interface_err', rid, error: MSG_UNKNOWN_HOST }))
          } catch (_) {}
          return
        }
        const prev = interfaces.get(bindIp)
        if (prev && prev.ws !== ws) {
          try {
            ws.send(JSON.stringify({ op: 'bind_interface_err', rid, error: 'interface already bound by another session' }))
          } catch (_) {}
          return
        }
        interfaces.set(bindIp, { ws, clientId: ws._browserNetClientId })
        try {
          ws.send(JSON.stringify({ op: 'bind_interface_ok', rid, host: bindIp }))
        } catch (_) {}
        return
      }
      if (op === 'unbind_interface') {
        const rid = msg.rid
        const rawHost =
          msg.host != null && String(msg.host).trim() !== ''
            ? String(msg.host).trim()
            : null
        let bindIp = null
        if (rawHost == null) {
          bindIp = getDefaultListenIpv4(ws) || null
        } else if (resolveListenHost) {
          bindIp = resolveListenHost(rawHost, ws) || ipv4Literal(rawHost)
        } else {
          bindIp = ipv4Literal(rawHost)
        }
        if (bindIp) {
          const cur = interfaces.get(bindIp)
          if (cur && cur.ws === ws) interfaces.delete(bindIp)
        }
        try {
          ws.send(JSON.stringify({ op: 'unbind_interface_ok', rid }))
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
    }

    ws.on('message', browserNetWsMessage)

    ws.on('close', function () {
      cleanupWs(ws)
    })
    return browserNetWsMessage
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
        /** @type {Array<[import('ws').RawData, boolean]>} */
        const pending = []
        function stash (data, isBinary) {
          pending.push([data, isBinary])
        }
        ws.on('message', stash)
        function wire () {
          ws.removeListener('message', stash)
          const onMessage = attachWebSocketConnection(ws, req)
          for (const row of pending) {
            onMessage(row[0], row[1])
          }
          pending.length = 0
        }
        if (prepareWebSocket) {
          Promise.resolve(prepareWebSocket(ws, req))
            .then(wire)
            .catch(function () {
              try {
                ws.removeListener('message', stash)
              } catch (_) {}
              try {
                ws.close()
              } catch (_) {}
            })
        } else {
          wire()
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
    const interfaceList = []
    for (const [ip, rec] of interfaces.entries()) {
      interfaceList.push({ host: ip, clientId: rec.clientId })
    }
    return {
      defaultListenIpv4: def || null,
      primaryTunIp: def || null,
      listeners: listenerList,
      interfaces: interfaceList,
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
  BIN_TAG,
  RAW_IP_TAG
}
