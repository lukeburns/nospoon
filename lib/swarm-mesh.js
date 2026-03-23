const crypto = require('crypto')
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

/** Derive 32-byte Hyperswarm topic from an arbitrary string (topic possession = capability). */
function topicKeyFromString (s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest()
}

/**
 * One topic per process: Hyperswarm discovery + pairwise key-address IPv4 over Noise streams.
 * Ephemeral IP assignment; no relay (only direct peer connections carry tun traffic).
 */
async function startSwarmMesh ({ topic, ip = '10.0.0.1/24', ipv6, seed, mtu = 1400 }) {
  const topicBuf = Buffer.isBuffer(topic) && topic.length === 32
    ? topic
    : topicKeyFromString(topic)

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

  function wireConnection (conn) {
    const remoteKey = conn.remotePublicKey
    const peerKeyHex = remoteKey.toString('hex')

    const existing = byPeerHex.get(peerKeyHex)
    if (existing) {
      existing.conn.removeAllListeners()
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

    router.addPeer(remoteKey, conn)

    const decode = createDecoder(function (framedPayload) {
      const packet = unwrapTunnelPayload(ka, framedPayload)
      if (!packet) return
      const srcIp = readSourceIp(packet)
      if (srcIp !== clientIp) return
      const destIp = readDestinationIp(packet)
      const peerConn = router.getConnectionForDestination(destIp, routingCtx)
      if (peerConn) {
        peerConn.write(encode(wrapTunnelPayload(ka, packet)))
      } else {
        tun.write(packet)
      }
    })

    conn.on('data', function (data) {
      decode(data)
    })

    startKeepalive(conn)

    byPeerHex.set(peerKeyHex, { conn, clientIp, decode })

    conn.on('close', function () {
      const state = byPeerHex.get(peerKeyHex)
      if (!state || state.conn !== conn) return
      byPeerHex.delete(peerKeyHex)
      router.removePeer(peerKeyHex)
      ka.unregister(state.clientIp)
      peerIpAllocator.release(state.clientIp)
      console.log(`Peer disconnected: ${peerKeyHex.slice(0, 8)}...`)
    })

    console.log(`Peer connected: ${peerKeyHex.slice(0, 8)}... → ${clientIp}`)
  }

  swarm.on('connection', function (conn) {
    wireConnection(conn)
  })

  await swarm.listen()
  const discovery = swarm.join(topicBuf)
  await discovery.flushed()

  console.log('')
  console.log('Swarm mesh')
  console.log('Topic (sha256):', topicBuf.toString('hex'))
  console.log('Public key:   ', keyPair.publicKey.toString('hex'))
  console.log('Local TUN:    ', stripHostFromCidr(ip), '(pairwise mesh; IPv4 key-address)')
  console.log('')

  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return
    const connection = router.getConnectionForDestination(destIp, routingCtx)
    if (connection) {
      connection.write(encode(wrapTunnelPayload(ka, packet)))
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

  return { swarm, tun, keyPair, topic: topicBuf }
}

module.exports = { startSwarmMesh, topicKeyFromString }
