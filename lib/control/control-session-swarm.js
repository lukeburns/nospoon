'use strict'

const { once } = require('events')
const Hyperswarm = require('hyperswarm')
const { swarmTopicCapability, timingSafeEqual } = require('../mesh/swarm-topic')
const { readDestinationIp } = require('../route/routing')
const { startKeepalive } = require('../wire/framing')
const { createSharedSwarmInboundPush } = require('../mesh/shared-swarm-inbound')
const { readFirstCompleteFramePayload } = require('./control-http-io')
const {
  discoveryIncludedInPeerTopics,
  swarmHasLiveConnection
} = require('./control-helpers')
const {
  SWARM_STATUS_DEBOUNCE_MS,
  TOPIC_DISCOVERY_POLL_MS
} = require('./control-constants')

module.exports = {

  async _ensureSharedSwarm () {
    if (this._sharedSwarm) return
    const self = this
    this._sharedSwarm = new Hyperswarm({
      keyPair: this._clientKeyPair,
      maxPeers: 512
    })
    this._sharedSwarm.on('connection', function (conn, peerInfo) {
      // NoiseSecretStream emits `error` (e.g. ECONNRESET); must not be uncaught while routing is async.
      conn.on('error', function () {})
      self._routeSwarmConnection(conn, peerInfo).catch(function () {
        try {
          conn.destroy()
        } catch (_) {}
      })
    })
    this._sharedSwarm.on('update', function () {
      self._scheduleSwarmStatusRefresh()
    })
    const swarm = this._sharedSwarm
    const origHandlePeer = swarm._handlePeer.bind(swarm)
    swarm._handlePeer = function (peer, topic) {
      origHandlePeer(peer, topic)
      self._scheduleSwarmStatusRefresh()
    }
    await this._sharedSwarm.listen()
  },
  /**
   * Hyperswarm does not always emit `update` when discovery tags an existing connection with a
   * topic (`_handlePeer` adds `peerInfo.topics` then returns — no new connection). Debounced
   * refresh keeps topic UI (synthetic rows) in sync for both peers.
   */
  _scheduleSwarmStatusRefresh () {
    if (this._swarmStatusDebounceTimer) clearTimeout(this._swarmStatusDebounceTimer)
    const self = this
    this._swarmStatusDebounceTimer = setTimeout(function () {
      self._swarmStatusDebounceTimer = null
      self._emitStatus()
    }, SWARM_STATUS_DEBOUNCE_MS)
  },
  /**
   * Periodically re-run the topic’s DHT lookup so the first peer to join still learns about peers
   * who announce after the initial lookup (Hyperswarm’s built-in refresh interval is very long).
   */
  _startTopicDiscoveryPolling (row) {
    const sess = row._handle && row._handle.discoverySession
    if (!sess) return
    if (row._discoveryPollTimer) {
      clearInterval(row._discoveryPollTimer)
      row._discoveryPollTimer = null
    }
    const self = this
    const tick = function () {
      if (!self._topics.has(row.id)) return
      sess.refresh().catch(function () {})
      self._scheduleSwarmStatusRefresh()
    }
    row._discoveryPollTimer = setInterval(tick, TOPIC_DISCOVERY_POLL_MS)
    tick()
  },
  /**
   * Deliver inner IPv4 packets addressed to our primary or any topic TUN (single-stream demux).
   * @param {Buffer} packet
   * @returns {boolean}
   */
  _deliverLocalMeshPacket (packet) {
    const dest = readDestinationIp(packet)
    if (!dest) return false
    if (this._directPool && dest === this._directPool.localTunIp) {
      try {
        this._directPool.tun.write(packet)
      } catch (_) {}
      return true
    }
    for (const row of this._topics.values()) {
      if (dest === row.localTunIp) {
        const h = row._handle
        if (h && h.tun) {
          try {
            h.tun.write(packet)
          } catch (_) {}
        }
        return true
      }
    }
    return false
  },
  _sharedMeshRelayCtx () {
    return {
      localKey: this._clientKeyPair.publicKey,
      ka: this._sharedKeyAddress,
      ipToKeyHex: null
    }
  },
  /**
   * @param {string|null|undefined} destIp
   * @returns {import('stream').Duplex|null}
   */
  _lookupRelayConnection (destIp) {
    if (!destIp) return null
    const ctx = this._sharedMeshRelayCtx()
    if (this._directPool) {
      const c = this._directPool.router.getConnectionForDestination(destIp, ctx)
      if (c && !c.destroyed) return c
    }
    for (const row of this._topics.values()) {
      const h = row._handle
      if (!h || !h.router) continue
      const c = h.router.getConnectionForDestination(destIp, ctx)
      if (c && !c.destroyed) return c
    }
    return null
  },
  /**
   * Outbound topic TUN uses each topic mesh's router. The same Hyperswarm stream is often wired
   * only through the direct pool (`explicit` join), so topic routers never saw addPeer and packets
   * were dropped in tun.on('data').
   */
  _addSharedConnToTopicMeshRouters (conn) {
    if (!conn || !conn.remotePublicKey || conn.destroyed) return
    const pk = conn.remotePublicKey
    for (const row of this._topics.values()) {
      const h = row._handle
      if (h && typeof h.ensureSharedPeerKeyAddress === 'function') {
        h.ensureSharedPeerKeyAddress(conn)
      }
      if (h && h.router) h.router.addPeer(pk, conn)
    }
  },
  _removeSharedConnFromTopicMeshRouters (conn) {
    if (!conn || !conn.remotePublicKey) return
    const pk = conn.remotePublicKey
    for (const row of this._topics.values()) {
      const h = row._handle
      if (h && h.router) {
        try {
          h.router.removePeer(pk)
        } catch (_) {}
      }
    }
  },
  _addSharedConnToDirectPoolRouter (conn) {
    if (!this._directPool || !conn || !conn.remotePublicKey || conn.destroyed) return
    if (typeof this._directPool.syncSharedInboundToPrimary === 'function') {
      this._directPool.syncSharedInboundToPrimary(conn)
    } else {
      this._directPool.router.addPeer(conn.remotePublicKey, conn)
      if (typeof this._directPool.attachSharedStreamToPeerState === 'function') {
        this._directPool.attachSharedStreamToPeerState(conn)
      }
    }
  },
  _removeSharedConnFromDirectPoolRouter (conn) {
    if (!this._directPool || !conn || !conn.remotePublicKey) return
    try {
      this._directPool.router.removePeer(conn.remotePublicKey)
    } catch (_) {}
  },
  _startKeepaliveOnce (conn) {
    if (!conn || this._keepaliveOnce.has(conn)) return
    this._keepaliveOnce.add(conn)
    startKeepalive(conn)
  },
  /**
   * Single framed-tunnel inbound pipeline for shared Hyperswarm (direct + topic).
   * @param {object} args
   * @param {import('stream').Duplex} args.conn
   * @param {{ st: object, peerIp: string, keyHex: string }|null} [args.directSt]
   * @param {Buffer[]} [args.primeChunks]
   * @param {object} [args.topicWireInbound]
   * @param {object} [args.topicPreauthedInbound]
   */
  _attachSharedPeerInbound (args) {
    const conn = args.conn
    if (!conn.remotePublicKey) return
    const rk = conn.remotePublicKey.toString('hex')

    const prev = this._sharedInboundByPeerKey.get(rk)
    if (prev && prev.conn === conn) {
      if (args.directSt) {
        const st = args.directSt.st
        st.connection = conn
        st.status = 'connected'
        if (this._directPool) {
          this._directPool.router.addPeer(conn.remotePublicKey, conn)
        }
        this._addSharedConnToTopicMeshRouters(conn)
      }
      return
    }

    if (prev && prev.conn !== conn) {
      prev.conn.removeListener('data', prev.onData)
      this._sharedInboundByPeerKey.delete(rk)
    }

    let peerAliasIp =
      args.directSt != null
        ? args.directSt.peerIp
        : args.topicWireInbound != null
          ? args.topicWireInbound.clientIp
          : args.topicPreauthedInbound != null
            ? args.topicPreauthedInbound.clientIp
            : null
    if (peerAliasIp == null || peerAliasIp === '') {
      throw new Error('shared inbound: missing peer alias IP')
    }

    if (args.topicPreauthedInbound) {
      args.topicPreauthedInbound.onTunnelReady()
      this._addSharedConnToDirectPoolRouter(conn)
      this._startKeepaliveOnce(conn)
    }

    let topicFirstFrameAuth = null
    if (args.topicWireInbound) {
      const tw = args.topicWireInbound
      const self = this
      topicFirstFrameAuth = {
        handshakeHash: tw.handshakeHash,
        topicSecret: tw.topicSecret,
        isInitiator: tw.isInitiator,
        conn,
        onSuccess: function () {
          tw.onAuthenticated()
          self._addSharedConnToDirectPoolRouter(conn)
          self._startKeepaliveOnce(conn)
        },
        onFail: tw.onAuthFail
      }
    }

    const self = this
    const push = createSharedSwarmInboundPush({
      ka: this._sharedKeyAddress,
      peerKeyHex: rk,
      peerAliasIp,
      lookupRelayConnection: function (dest) {
        return self._lookupRelayConnection(dest)
      },
      deliverLocalMeshPacket: function (p) {
        return self._deliverLocalMeshPacket(p)
      },
      fallbackTunWrite: function (p) {
        if (self._directPool) {
          try {
            self._directPool.tun.write(p)
          } catch (_) {}
        }
      },
      topicFirstFrameAuth
    })

    const onData = function (chunk) {
      push(chunk)
    }
    conn.on('data', onData)

    const chunks = args.primeChunks || []
    for (let i = 0; i < chunks.length; i++) {
      push(chunks[i])
    }

    this._sharedInboundByPeerKey.set(rk, { conn, onData, push })

    const selfMap = this
    conn.on('close', function () {
      const cur = selfMap._sharedInboundByPeerKey.get(rk)
      if (cur && cur.conn === conn && cur.onData === onData) {
        selfMap._sharedInboundByPeerKey.delete(rk)
        selfMap._removeSharedConnFromTopicMeshRouters(conn)
        selfMap._removeSharedConnFromDirectPoolRouter(conn)
      }
    })

    if (!args.topicWireInbound && !args.topicPreauthedInbound) {
      this._addSharedConnToTopicMeshRouters(conn)
    }

    if (!topicFirstFrameAuth && !args.topicPreauthedInbound) {
      this._startKeepaliveOnce(conn)
    }
  },
  async _routeSwarmConnection (conn, peerInfo) {
    if (!conn.remotePublicKey) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }
    if (peerInfo.explicit && this._directPool) {
      this._directPool.acceptConnection(conn)
      return
    }
    const row = this._pickTopicRowForPeerInfo(peerInfo)
    if (row) {
      row._handle.acceptConnection(conn)
      return
    }
    if (this._topics.size === 0 && this._directPool) {
      this._directPool.acceptConnection(conn)
      return
    }
    await this._demuxUnknownInbound(conn)
  },
  _pickTopicRowForPeerInfo (peerInfo) {
    const topics = peerInfo.topics || []
    for (const topicBuf of topics) {
      const row = this._topicByDiscoveryHex.get(topicBuf.toString('hex'))
      if (row) return row
    }
    return null
  },
  /**
   * Inbound server streams may lack `peerInfo.topics`; sniff first payload to distinguish topic cap vs direct tunnel.
   */
  async _demuxUnknownInbound (conn) {
    try {
      // Server-side streams often finish Noise before Hyperswarm emits `connection`;
      // `handshake` may already have fired, so `once()` would hang forever.
      if (!conn.handshakeHash) await once(conn, 'handshake')
    } catch {
      return
    }
    const h = conn.handshakeHash
    if (!h) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }

    if (conn.isInitiator) {
      if (this._directPool) this._directPool.acceptConnection(conn)
      return
    }

    const payload = await readFirstCompleteFramePayload(conn)
    for (const row of this._topics.values()) {
      const secret = row._handle.topicSecret
      const expected = swarmTopicCapability(!conn.isInitiator, secret, h)
      if (timingSafeEqual(payload, expected)) {
        await row._handle.acceptResponderPreauthed(conn, h)
        return
      }
    }
    if (this._directPool) {
      const hdr = Buffer.allocUnsafe(4)
      hdr.writeUInt32BE(payload.length, 0)
      this._directPool.acceptConnection(conn, { primedFramedChunks: [Buffer.concat([hdr, payload])] })
    } else {
      try {
        conn.destroy()
      } catch (_) {}
    }
  }
}
