const { once } = require('events')
const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const {
  createKeyAddressTable,
  stripHostFromCidr,
  wrapTunnelPayload,
  unwrapTunnelPayload,
  coerceIpv4SourceForMeshEncode
} = require('./key-address')
const {
  createRouter,
  readDestinationIp,
  tunnelSourceAllowedForPeerStream,
  shouldHairpinToLocalStack
} = require('./routing')
const { createPeerIpAllocator } = require('./ip-subnet')
const {
  swarmDiscoveryKey,
  swarmTopicCapability,
  timingSafeEqual,
  normalizeTopicBytes
} = require('./swarm-topic')
const { encodeZ32 } = require('./key-encoding')
const { meshIdentifierStorageKey } = require('./mesh-identifier')

/**
 * Stable topic id for mesh identifiers (SpoonDNS-style `keyTopic.topicId`).
 * @param {string|Buffer} topic
 * @param {string} [explicitTopicId]
 */
function resolveTopicMeshId (topic, explicitTopicId) {
  if (explicitTopicId != null && String(explicitTopicId).trim()) return String(explicitTopicId).trim()
  if (Buffer.isBuffer(topic)) return 'buf:' + topic.toString('hex')
  return String(topic)
}

/**
 * One topic per process: Hyperswarm discovery + pairwise key-address IPv4 over Noise streams.
 * Ephemeral IP assignment; no relay (only direct peer connections carry tun traffic).
 *
 * Discovery uses swarmDiscoveryKey(topicBytes) on the DHT; the preimage (topic string/bytes)
 * is proven after Noise via a hypercore-style capability (see swarm-topic.js).
 *
 * @param {object} opts
 * @param {object} [opts.swarm] — Existing Hyperswarm instance (e.g. shared DHT with other joins). Must have been constructed with `keyPair`. Identity comes from `swarm.keyPair` (seed is ignored). If omitted, a new swarm is created and destroyed on shutdown.
 * @param {string} [opts.topicId] — Logical topic id for {@link mesh-identifier} `keyTopic` (defaults from `topic`)
 * @param {{ onPeerUp?: function(object): void, onPeerDown?: function(object): void }} [opts.hooks] — `onPeerUp`/`onPeerDown` receive `{ peerKeyHex, ipv4, meshId, meshIdKey }`
 * @param {boolean} [opts.quiet=false] — Skip startup / peer console logs
 * @param {boolean} [opts.silentRouter=false] — Pass `silent: true` to {@link createRouter}
 * @param {boolean} [opts.manageProcessSignals=true] — Register SIGINT/SIGTERM → shutdown + exit
 * @param {ReturnType<typeof createKeyAddressTable>} [opts.keyAddress] — shared id↔IP table; local + peer rows are registered here; on shutdown, local + remaining peer IPs are unregistered
 * @param {boolean} [opts.registerConnectionListener=true] — If false (e.g. shared Hyperswarm), caller must invoke {@link SwarmMeshHandle#acceptConnection} / {@link SwarmMeshHandle#acceptResponderPreauthed}
 * @param {function(string): string|null} [opts.consumeReservedPeerIp] — 64-hex remote key → reserved alias for {@link createPeerIpAllocator#claim}
 * @param {function(object): void} [opts.attachSharedSwarmTunnel] — when `swarm` is injected, control plane attaches the single inbound `data` pipeline
 */
async function startSwarmMesh (opts) {
  const {
    topic,
    ip = '10.0.0.1/24',
    ipv6,
    seed,
    mtu = 1400,
    swarm: swarmOpt,
    topicId: topicIdOpt,
    hooks,
    quiet = false,
    silentRouter = false,
    manageProcessSignals = true,
    keyAddress: keyAddressOpt,
    registerConnectionListener = true,
    consumeReservedPeerIp: consumeReservedPeerIpOpt,
    attachSharedSwarmTunnel: attachSharedSwarmTunnelOpt
  } = opts

  const attachSharedSwarmTunnel =
    swarmOpt && typeof attachSharedSwarmTunnelOpt === 'function'
      ? attachSharedSwarmTunnelOpt
      : null

  const topicSecret = normalizeTopicBytes(topic)
  const discoveryKey = swarmDiscoveryKey(topicSecret)
  const topicIdStr = resolveTopicMeshId(topic, topicIdOpt)

  const seedBuf = seed ? Buffer.from(seed, 'hex') : null
  const ownSwarm = !swarmOpt
  let keyPair
  let swarm
  if (swarmOpt) {
    swarm = swarmOpt
    keyPair = swarm.keyPair
    if (!keyPair || !keyPair.publicKey) {
      throw new Error('startSwarmMesh: injected swarm must have keyPair (construct Hyperswarm with { keyPair })')
    }
  } else {
    keyPair = seedBuf ? HyperDHT.keyPair(seedBuf) : HyperDHT.keyPair()
    swarm = new Hyperswarm({
      keyPair,
      maxPeers: 512
    })
  }

  const tun = createTunDevice({ ipv4: ip, ipv6, mtu, quiet })
  const router = createRouter({ silent: silentRouter })

  const localMeshId = {
    kind: 'keyTopic',
    keyHex: keyPair.publicKey.toString('hex'),
    topicId: topicIdStr,
    topicBytes: topicSecret
  }

  const localTunIpStr = stripHostFromCidr(ip)
  const ka =
    keyAddressOpt != null
      ? keyAddressOpt
      : createKeyAddressTable({
          localKey: keyPair.publicKey,
          localIp: localTunIpStr,
          localMeshId
        })
  if (keyAddressOpt != null) {
    ka.register(localTunIpStr, keyPair.publicKey, localMeshId)
  }
  if (typeof ka.setMeshIpv4LiteralGuardCidr === 'function') {
    ka.setMeshIpv4LiteralGuardCidr(ip)
  }
  const peerIpAllocator = createPeerIpAllocator(ip, {
    initialUsed: new Set([localTunIpStr])
  })

  const consumeReservedPeerIp =
    consumeReservedPeerIpOpt && typeof consumeReservedPeerIpOpt === 'function'
      ? consumeReservedPeerIpOpt
      : null

  function pickPeerClientIp (peerKeyHex) {
    const h = String(peerKeyHex || '').trim().toLowerCase()
    if (consumeReservedPeerIp) {
      const want = consumeReservedPeerIp(h)
      if (want != null && String(want).trim()) {
        return peerIpAllocator.claim(String(want).trim())
      }
    }
    return peerIpAllocator.allocate()
  }

  const routingCtx = {
    localKey: keyPair.publicKey,
    ka,
    ipToKeyHex: null,
    localMeshIpv4: localTunIpStr,
    localMeshIpv6: ipv6 ? stripHostFromCidr(String(ipv6)) : null
  }

  function makeTunnelFrameHandler (clientIp, peerKeyHex) {
    return function onTunnelFrame (framedPayload) {
      const packet = unwrapTunnelPayload(ka, framedPayload)
      if (!packet) return
      const destIp = readDestinationIp(packet)
      const peerConn = router.getConnectionForDestination(destIp, routingCtx)
      if (peerConn) {
        if (!tunnelSourceAllowedForPeerStream(packet, clientIp, peerKeyHex, ka)) return
        safeWrite(peerConn, encode(wrapTunnelPayload(ka, packet)))
      } else {
        try {
          tun.write(packet)
        } catch (_) {}
      }
    }
  }

  /** @type {Map<string, { conn: object, clientIp: string, decode: function }>} */
  const byPeerHex = new Map()

  /**
   * When the stream was attached only via the direct pool, `wireConnection` never ran so this topic
   * peer has no IPv4 row in `ka` — topic TUN egress cannot resolve `ipToKey(dst)`. Register the same
   * alias we would use on the wire path, and clean up on `close` if full `wireConnection` never took
   * ownership ({@link #byPeerHex}).
   */
  function ensureSharedPeerKeyAddress (conn) {
    if (!conn || !conn.remotePublicKey || conn.destroyed) return
    const remoteKey = conn.remotePublicKey
    const peerKeyHex = remoteKey.toString('hex')
    if (byPeerHex.has(peerKeyHex)) return

    const peerMeshId = {
      kind: 'keyTopic',
      keyHex: peerKeyHex,
      topicId: topicIdStr,
      topicBytes: topicSecret
    }
    if (ka.ipForMeshIdentifier(peerMeshId)) return

    let clientIp
    try {
      clientIp = pickPeerClientIp(peerKeyHex)
    } catch (_) {
      return
    }
    try {
      ka.register(clientIp, remoteKey, peerMeshId)
    } catch (_) {
      peerIpAllocator.release(clientIp)
      return
    }

    emitPeerUp(peerKeyHex, clientIp, remoteKey)

    conn.on('close', function () {
      if (byPeerHex.has(peerKeyHex)) return
      try {
        ka.unregister(clientIp)
      } catch (_) {}
      try {
        peerIpAllocator.release(clientIp)
      } catch (_) {}
      emitPeerDown(peerKeyHex, clientIp)
    })
  }

  const onPeerUp = hooks && typeof hooks.onPeerUp === 'function' ? hooks.onPeerUp : null
  const onPeerDown = hooks && typeof hooks.onPeerDown === 'function' ? hooks.onPeerDown : null

  /** NoiseSecretStream emits `error` on timeout/reset; without a listener Node treats it as fatal. */
  function attachConnErrorHandler (c) {
    c.on('error', function () {})
  }

  function safeWrite (stream, buf) {
    if (!stream || stream.destroyed) return
    try {
      stream.write(buf)
    } catch (_) {}
  }

  function emitPeerUp (peerKeyHex, clientIp, remoteKey) {
    if (!onPeerUp) return
    const meshId = {
      kind: 'keyTopic',
      keyHex: peerKeyHex,
      topicId: topicIdStr
    }
    onPeerUp({
      peerKeyHex,
      ipv4: clientIp,
      meshId,
      meshIdKey: meshIdentifierStorageKey(meshId),
      remotePublicKey: remoteKey
    })
  }

  function emitPeerDown (peerKeyHex, clientIp) {
    if (!onPeerDown) return
    const meshId = {
      kind: 'keyTopic',
      keyHex: peerKeyHex,
      topicId: topicIdStr
    }
    onPeerDown({
      peerKeyHex,
      ipv4: clientIp,
      meshId,
      meshIdKey: meshIdentifierStorageKey(meshId)
    })
  }

  async function wireConnection (conn) {
    let h = conn.handshakeHash
    if (!h) {
      try {
        await once(conn, 'handshake')
      } catch {
        return
      }
      h = conn.handshakeHash
    }
    if (!h) {
      conn.destroy()
      return
    }

    const remoteKey = conn.remotePublicKey
    const peerKeyHex = remoteKey.toString('hex')

    const existing = byPeerHex.get(peerKeyHex)
    if (existing) {
      existing.conn.removeAllListeners()
      attachConnErrorHandler(existing.conn)
      try { existing.conn.destroy() } catch (_) {}
      router.removePeer(peerKeyHex)
      byPeerHex.delete(peerKeyHex)
    }

    let clientIp
    if (existing) {
      clientIp = existing.clientIp
    } else {
      try {
        clientIp = pickPeerClientIp(peerKeyHex)
      } catch (e) {
        if (!quiet) console.error('Swarm mesh:', e.message)
        conn.destroy()
        return
      }
      const peerMeshId = {
        kind: 'keyTopic',
        keyHex: peerKeyHex,
        topicId: topicIdStr,
        topicBytes: topicSecret
      }
      ka.register(clientIp, remoteKey, peerMeshId)
    }

    let tunnelReady = false

    if (attachSharedSwarmTunnel) {
      attachConnErrorHandler(conn)
      attachSharedSwarmTunnel({
        conn,
        topicWireInbound: {
          peerKeyHex,
          clientIp,
          remoteKey,
          handshakeHash: h,
          topicSecret,
          isInitiator: conn.isInitiator,
          onAuthenticated: function () {
            if (tunnelReady) return
            tunnelReady = true
            router.addPeer(remoteKey, conn)
            byPeerHex.set(peerKeyHex, { conn, clientIp })
            if (!quiet) console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
            emitPeerUp(peerKeyHex, clientIp, remoteKey)
          },
          onAuthFail: function () {
            ka.unregister(clientIp)
            peerIpAllocator.release(clientIp)
            try {
              conn.destroy()
            } catch (_) {}
          }
        }
      })
      conn.on('close', function () {
        const state = byPeerHex.get(peerKeyHex)
        if (state && state.conn === conn) {
          byPeerHex.delete(peerKeyHex)
          router.removePeer(peerKeyHex)
          ka.unregister(state.clientIp)
          peerIpAllocator.release(state.clientIp)
          if (!quiet) console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
          emitPeerDown(peerKeyHex, state.clientIp)
        } else if (!tunnelReady) {
          ka.unregister(clientIp)
          peerIpAllocator.release(clientIp)
        }
      })
      if (conn.isInitiator) {
        conn.write(encode(swarmTopicCapability(true, topicSecret, h)))
      }
      return
    }

    let finalized = false
    let topicAuthFailed = false

    let authDone = false
    const tunnelHandler = makeTunnelFrameHandler(clientIp, peerKeyHex)
    const decode = createDecoder(function (framedPayload) {
      if (!authDone) {
        authDone = true
        const expectedRemote = swarmTopicCapability(!conn.isInitiator, topicSecret, h)
        if (!timingSafeEqual(framedPayload, expectedRemote)) {
          if (!quiet) console.error('Swarm mesh: topic authentication failed')
          topicAuthFailed = true
          ka.unregister(clientIp)
          peerIpAllocator.release(clientIp)
          conn.destroy()
          return
        }
        if (!conn.isInitiator) {
          conn.write(encode(swarmTopicCapability(false, topicSecret, h)))
        }
        router.addPeer(remoteKey, conn)
        startKeepalive(conn)
        finalized = true
        byPeerHex.set(peerKeyHex, { conn, clientIp, decode })
        if (!quiet) console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
        emitPeerUp(peerKeyHex, clientIp, remoteKey)
        return
      }

      tunnelHandler(framedPayload)
    })

    const onData = function (data) {
      decode(data)
    }

    attachConnErrorHandler(conn)

    conn.on('data', onData)

    if (conn.isInitiator) {
      conn.write(encode(swarmTopicCapability(true, topicSecret, h)))
    }

    conn.on('close', function () {
      const state = byPeerHex.get(peerKeyHex)
      if (state && state.conn === conn) {
        byPeerHex.delete(peerKeyHex)
        router.removePeer(peerKeyHex)
        ka.unregister(state.clientIp)
        peerIpAllocator.release(state.clientIp)
        if (!quiet) console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
        emitPeerDown(peerKeyHex, state.clientIp)
      } else if (!finalized && !topicAuthFailed) {
        ka.unregister(clientIp)
        peerIpAllocator.release(clientIp)
      }
    })
  }

  /**
   * Responder path when the first framed payload was already consumed (e.g. shared Hyperswarm demux).
   * @returns {Promise<void>}
   */
  async function acceptResponderPreauthed (conn, h) {
    if (!conn.remotePublicKey) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }
    const remoteKey = conn.remotePublicKey
    const peerKeyHex = remoteKey.toString('hex')

    const existing = byPeerHex.get(peerKeyHex)
    if (existing) {
      existing.conn.removeAllListeners()
      attachConnErrorHandler(existing.conn)
      try { existing.conn.destroy() } catch (_) {}
      router.removePeer(peerKeyHex)
      byPeerHex.delete(peerKeyHex)
    }

    let clientIp
    if (existing) {
      clientIp = existing.clientIp
    } else {
      try {
        clientIp = pickPeerClientIp(peerKeyHex)
      } catch (e) {
        if (!quiet) console.error('Swarm mesh:', e.message)
        try {
          conn.destroy()
        } catch (_) {}
        return
      }
      const peerMeshId = {
        kind: 'keyTopic',
        keyHex: peerKeyHex,
        topicId: topicIdStr,
        topicBytes: topicSecret
      }
      ka.register(clientIp, remoteKey, peerMeshId)
    }

    try {
      conn.write(encode(swarmTopicCapability(false, topicSecret, h)))
    } catch (_) {}

    if (attachSharedSwarmTunnel) {
      attachConnErrorHandler(conn)
      attachSharedSwarmTunnel({
        conn,
        topicPreauthedInbound: {
          peerKeyHex,
          clientIp,
          remoteKey,
          onTunnelReady: function () {
            router.addPeer(remoteKey, conn)
            byPeerHex.set(peerKeyHex, { conn, clientIp })
            if (!quiet) console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
            emitPeerUp(peerKeyHex, clientIp, remoteKey)
          }
        }
      })
      conn.on('close', function () {
        const state = byPeerHex.get(peerKeyHex)
        if (state && state.conn === conn) {
          byPeerHex.delete(peerKeyHex)
          router.removePeer(peerKeyHex)
          ka.unregister(state.clientIp)
          peerIpAllocator.release(state.clientIp)
          if (!quiet) console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
          emitPeerDown(peerKeyHex, state.clientIp)
        }
      })
      return
    }

    router.addPeer(remoteKey, conn)
    startKeepalive(conn)

    const decode = createDecoder(makeTunnelFrameHandler(clientIp, peerKeyHex))
    const onData = function (data) {
      decode(data)
    }
    byPeerHex.set(peerKeyHex, { conn, clientIp, decode })
    if (!quiet) console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
    emitPeerUp(peerKeyHex, clientIp, remoteKey)

    attachConnErrorHandler(conn)
    conn.on('data', onData)

    conn.on('close', function () {
      const state = byPeerHex.get(peerKeyHex)
      if (state && state.conn === conn) {
        byPeerHex.delete(peerKeyHex)
        router.removePeer(peerKeyHex)
        ka.unregister(state.clientIp)
        peerIpAllocator.release(state.clientIp)
        if (!quiet) console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
        emitPeerDown(peerKeyHex, state.clientIp)
      }
    })
  }

  function acceptConnection (conn) {
    return wireConnection(conn)
  }

  if (registerConnectionListener) {
    swarm.on('connection', function (conn) {
      wireConnection(conn).catch(function () {
        try {
          conn.destroy()
        } catch (_) {}
      })
    })
  }

  if (ownSwarm) {
    await swarm.listen()
  }
  const discovery = swarm.join(discoveryKey)
  await discovery.flushed()

  if (!quiet) {
    console.log('')
    console.log('Swarm mesh')
    console.log('Discovery key:', encodeZ32(discoveryKey))
    console.log('Public key:   ', encodeZ32(keyPair.publicKey))
    console.log('Local TUN:    ', stripHostFromCidr(ip), '(pairwise mesh; IPv4 key-address)')
    console.log('')
  }

  const localMeshIpStr = localTunIpStr
  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return
    if (shouldHairpinToLocalStack(destIp, routingCtx)) {
      try {
        tun.write(packet)
      } catch (_) {}
      return
    }
    const connection = router.getConnectionForDestination(destIp, routingCtx)
    if (connection) {
      const p = coerceIpv4SourceForMeshEncode(packet, ka, localMeshIpStr)
      safeWrite(connection, encode(wrapTunnelPayload(ka, p)))
    }
  })

  let exiting = false
  function shutdown () {
    if (exiting) return
    exiting = true
    if (!quiet) console.log('\nShutting down...')
    for (const [peerKeyHex, state] of [...byPeerHex.entries()]) {
      router.removePeer(peerKeyHex)
      try {
        ka.unregister(state.clientIp)
      } catch (_) {}
    }
    byPeerHex.clear()
    if (keyAddressOpt != null) {
      try {
        ka.unregister(localTunIpStr)
      } catch (_) {}
    }
    if (ownSwarm) {
      try {
        swarm.destroy()
      } catch (e) {}
    } else {
      swarm.leave(discoveryKey).catch(function () {})
    }
    try {
      tun.release()
    } catch (e) {}
    if (manageProcessSignals) {
      setTimeout(function () { process.exit(0) }, 300)
    }
  }

  if (manageProcessSignals) {
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
  }

  return {
    swarm,
    tun,
    router,
    keyPair,
    topic: discoveryKey,
    topicSecret,
    topicId: topicIdStr,
    shutdown,
    acceptConnection,
    acceptResponderPreauthed,
    ensureSharedPeerKeyAddress,
    discoverySession: discovery
  }
}

module.exports = {
  startSwarmMesh,
  swarmDiscoveryKey,
  normalizeTopicBytes,
  resolveTopicMeshId
}
