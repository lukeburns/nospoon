const { once } = require('events')
const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const {
  createKeyAddressTable,
  stripHostFromCidr,
  wrapTunnelPayload,
  unwrapTunnelPayload
} = require('./key-address')
const { createRouter, readDestinationIp, readSourceIp } = require('./routing')
const { createPeerIpAllocator } = require('./ip-subnet')
const {
  swarmDiscoveryKey,
  swarmTopicCapability,
  timingSafeEqual,
  normalizeTopicBytes
} = require('./swarm-topic')

/**
 * One topic per process: Hyperswarm discovery + pairwise key-address IPv4 over Noise streams.
 * Ephemeral IP assignment; no relay (only direct peer connections carry tun traffic).
 *
 * Discovery uses swarmDiscoveryKey(topicBytes) on the DHT; the preimage (topic string/bytes)
 * is proven after Noise via a hypercore-style capability (see swarm-topic.js).
 */
async function startSwarmMesh ({ topic, ip = '10.0.0.1/24', ipv6, seed, mtu = 1400 }) {
  const topicSecret = normalizeTopicBytes(topic)
  const discoveryKey = swarmDiscoveryKey(topicSecret)

  const seedBuf = seed ? Buffer.from(seed, 'hex') : null
  const keyPair = seedBuf ? HyperDHT.keyPair(seedBuf) : HyperDHT.keyPair()

  const swarm = new Hyperswarm({
    keyPair,
    maxPeers: 512
  })

  const tun = createTunDevice({ ipv4: ip, ipv6, mtu })
  const router = createRouter()
  const ka = createKeyAddressTable({
    localKey: keyPair.publicKey,
    localIp: stripHostFromCidr(ip)
  })
  const peerIpAllocator = createPeerIpAllocator(ip, {
    initialUsed: new Set([stripHostFromCidr(ip)])
  })

  const routingCtx = {
    localKey: keyPair.publicKey,
    ka,
    ipToKeyHex: null
  }

  /** @type {Map<string, { conn: object, clientIp: string, decode: function }>} */
  const byPeerHex = new Map()

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
        clientIp = peerIpAllocator.allocate()
      } catch (e) {
        console.error('Swarm mesh:', e.message)
        conn.destroy()
        return
      }
      ka.register(clientIp, remoteKey)
    }

    let finalized = false
    let topicAuthFailed = false

    let authDone = false
    const decode = createDecoder(function (framedPayload) {
      if (!authDone) {
        authDone = true
        const expectedRemote = swarmTopicCapability(!conn.isInitiator, topicSecret, h)
        if (!timingSafeEqual(framedPayload, expectedRemote)) {
          console.error('Swarm mesh: topic authentication failed')
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
        console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
        return
      }

      const packet = unwrapTunnelPayload(ka, framedPayload)
      if (!packet) return
      const srcIp = readSourceIp(packet)
      if (srcIp !== clientIp) return
      const destIp = readDestinationIp(packet)
      const peerConn = router.getConnectionForDestination(destIp, routingCtx)
      if (peerConn) {
        safeWrite(peerConn, encode(wrapTunnelPayload(ka, packet)))
      } else {
        try {
          tun.write(packet)
        } catch (_) {}
      }
    })

    attachConnErrorHandler(conn)

    conn.on('data', function (data) {
      decode(data)
    })

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
        console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
      } else if (!finalized && !topicAuthFailed) {
        ka.unregister(clientIp)
        peerIpAllocator.release(clientIp)
      }
    })
  }

  swarm.on('connection', function (conn) {
    wireConnection(conn).catch(function () {
      try { conn.destroy() } catch (_) {}
    })
  })

  await swarm.listen()
  const discovery = swarm.join(discoveryKey)
  await discovery.flushed()

  console.log('')
  console.log('Swarm mesh')
  console.log('Discovery key:', discoveryKey.toString('hex'))
  console.log('Public key:   ', keyPair.publicKey.toString('hex'))
  console.log('Local TUN:    ', stripHostFromCidr(ip), '(pairwise mesh; IPv4 key-address)')
  console.log('')

  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return
    const connection = router.getConnectionForDestination(destIp, routingCtx)
    if (connection) {
      safeWrite(connection, encode(wrapTunnelPayload(ka, packet)))
    }
  })

  let exiting = false
  function shutdown () {
    if (exiting) return
    exiting = true
    console.log('\nShutting down...')
    try { swarm.destroy() } catch (e) {}
    try { tun.release() } catch (e) {}
    setTimeout(function () { process.exit(0) }, 300)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  return { swarm, tun, keyPair, topic: discoveryKey, topicSecret }
}

module.exports = {
  startSwarmMesh,
  swarmDiscoveryKey,
  normalizeTopicBytes
}
