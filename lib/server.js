const HyperDHT = require('hyperdht')
const crypto = require('crypto')
const fs = require('fs')
const net = require('net')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const {
  createKeyAddressTable,
  stripHostFromCidr,
  wrapTunnelPayload,
  unwrapTunnelPayload
} = require('./key-address')
const {
  createRouter,
  readDestinationIp,
  tunnelSourceAllowedForPeerStream,
  shouldHairpinToLocalStack
} = require('./routing')
const { enableServerForwarding, disableServerForwarding } = require('./full-tunnel')
const { ipToInt, parseSubnet, createPeerIpAllocator } = require('./ip-subnet')
const { encodeHubDirectory, isDirectoryFrame } = require('./hub-directory')
const { parse32Bytes, encodeZ32, formatKeyShortFromHex } = require('./key-encoding')

function loadPeers (configPath, serverCidr) {
  const raw = fs.readFileSync(configPath, 'utf-8')
  const config = JSON.parse(raw)

  if (!config.peers || typeof config.peers !== 'object') {
    throw new Error('Config must have a "peers" object mapping public keys to IPs')
  }

  const subnet = serverCidr ? parseSubnet(serverCidr) : null

  const seen = new Set()
  /** @type {Map<string, string>} keyHex → ip */
  const out = new Map()
  for (const [keyStr, ip] of Object.entries(config.peers)) {
    let keyHex
    try {
      keyHex = parse32Bytes(keyStr, 'peers.json key').toString('hex')
    } catch (e) {
      throw new Error(`peers.json: ${e.message}`)
    }
    const label = formatKeyShortFromHex(keyHex)

    if (!net.isIPv4(ip) && !net.isIPv6(ip)) {
      throw new Error(`Invalid IP for peer ${label}: ${ip}`)
    }

    // IPv4-specific validation
    if (net.isIPv4(ip)) {
      const ipInt = ipToInt(ip)

      if (ipInt === 0) {
        throw new Error(`Invalid IP for peer ${label}: 0.0.0.0`)
      }
      if ((ipInt >>> 24) === 127) {
        throw new Error(`Invalid IP for peer ${label}: loopback address`)
      }

      if (subnet) {
        if ((ipInt & subnet.mask) >>> 0 !== subnet.network) {
          throw new Error(`Peer ${label} IP ${ip} is not in server subnet`)
        }
        if (ipInt === subnet.network) {
          throw new Error(`Peer ${label} IP ${ip} is the network address`)
        }
        if (ipInt === subnet.broadcast) {
          throw new Error(`Peer ${label} IP ${ip} is the broadcast address`)
        }
        if (ipInt === subnet.hostIp) {
          throw new Error(`Peer ${label} IP ${ip} conflicts with server IP`)
        }
      }
    }

    if (seen.has(ip)) {
      throw new Error(`Duplicate IP assignment in peers config: ${ip}`)
    }
    seen.add(ip)
    out.set(keyHex, ip)
  }

  return out
}

/**
 * @param {object} opts
 * @param {object} [opts.dht] — Existing HyperDHT instance (shared with other code). If omitted, a new instance is created and destroyed on shutdown.
 */
async function startServer ({ ip = '10.0.0.1/24', ipv6, seed, mtu = 1400, config, fullTunnel, outInterface, allowedKeys, dht: dhtOpt }) {
  const seedBuf = seed
    ? Buffer.from(seed, 'hex')
    : crypto.randomBytes(32)

  if (config && Array.isArray(allowedKeys) && allowedKeys.length) {
    throw new Error('Use either --config or positional peer keys, not both')
  }

  /** CLI allowlist: only these remote public keys may connect (firewall). */
  const allowedKeySet = Array.isArray(allowedKeys) && allowedKeys.length
    ? new Set(allowedKeys.map(function (k) { return k.toLowerCase() }))
    : null

  // Load allowed peers if config provided (fixed IP per key; raw IPv4 on wire)
  const allowedPeers = config ? loadPeers(config, ip) : null

  const hasFirewall = !!config || (allowedKeySet && allowedKeySet.size > 0)

  /** Authenticated mode: map peer alias IP (from packet dst) → key hex — same info as key-address would use */
  let ipToPeerKeyHex = null
  if (allowedPeers) {
    ipToPeerKeyHex = new Map()
    for (const [keyHex, peerIp] of allowedPeers) {
      ipToPeerKeyHex.set(peerIp, keyHex)
    }
  }

  const keyPair = HyperDHT.keyPair(seedBuf)
  const ownDht = !dhtOpt
  const dht = dhtOpt || new HyperDHT()
  const tun = createTunDevice({ ipv4: ip, ipv6, mtu })
  const router = createRouter()

  const localMeshIpv4 = stripHostFromCidr(ip)
  const localMeshIpv6 = ipv6 ? stripHostFromCidr(String(ipv6)) : null

  const routingCtx = {
    localKey: keyPair.publicKey,
    ka: null,
    ipToKeyHex: ipToPeerKeyHex,
    localMeshIpv4,
    localMeshIpv6
  }

  const kaOpen = !allowedPeers
    ? createKeyAddressTable({
      localKey: keyPair.publicKey,
      localIp: stripHostFromCidr(ip)
    })
    : null

  if (kaOpen && typeof kaOpen.setMeshIpv4LiteralGuardCidr === 'function') {
    kaOpen.setMeshIpv4LiteralGuardCidr(ip)
  }

  routingCtx.ka = kaOpen

  const peerIpAllocator = !allowedPeers && kaOpen ? createPeerIpAllocator(ip) : null

  /** Key-address mode only: hub broadcasts peer key list for spoke-to-spoke aliasing. */
  const hubConnections = new Set()

  function broadcastHubDirectory () {
    if (!kaOpen) return
    const keys = []
    for (const c of hubConnections) {
      if (!c.destroyed) keys.push(c.remotePublicKey.toString('hex'))
    }
    keys.sort()
    let payload
    try {
      payload = encodeHubDirectory(keys)
    } catch (e) {
      console.error('Hub directory encode failed:', e.message)
      return
    }
    const frame = encode(payload)
    for (const c of hubConnections) {
      if (!c.destroyed) c.write(frame)
    }
  }

  const serverOpts = {
    firewall (remotePublicKey) {
      const keyHex = remotePublicKey.toString('hex')
      if (allowedKeySet && allowedKeySet.size > 0) {
        if (!allowedKeySet.has(keyHex)) {
          console.log(`Firewalled peer not in CLI allowlist: ${formatKeyShortFromHex(keyHex)}`)
          return true
        }
        return false
      }
      if (allowedPeers) {
        const allowed = allowedPeers.has(keyHex)
        if (!allowed) {
          console.log(`Firewalled unknown peer: ${formatKeyShortFromHex(keyHex)}`)
        }
        return !allowed
      }
      return false // open mode, allow all
    }
  }

  const server = dht.createServer(serverOpts, function (connection) {
    const clientKeyHex = connection.remotePublicKey.toString('hex')
    const clientKeyShort = formatKeyShortFromHex(clientKeyHex)

    let clientIp = allowedPeers
      ? allowedPeers.get(clientKeyHex)
      : null

    if (!allowedPeers && kaOpen && peerIpAllocator) {
      try {
        clientIp = peerIpAllocator.allocate()
      } catch (e) {
        console.error(`Peer ${clientKeyShort}: ${e.message}`)
        connection.end()
        return
      }
      // Open mode: incremental local aliases (.2, .3, … in the server subnet) for
      // each peer key; register before any key-address decode.
      kaOpen.register(clientIp, connection.remotePublicKey)
      router.addPeer(connection.remotePublicKey, connection)
      hubConnections.add(connection)
      broadcastHubDirectory()
    }

    console.log(`Client connected: ${clientKeyShort}` + (clientIp ? ` → ${clientIp}` : ''))
    startKeepalive(connection)

    if (allowedPeers && clientIp) {
      router.addPeer(connection.remotePublicKey, connection)
    }

    const decode = createDecoder(function (framedPayload) {
      if (isDirectoryFrame(framedPayload)) return
      const packet = unwrapTunnelPayload(kaOpen, framedPayload)
      if (!packet) return

      const destIp = readDestinationIp(packet)
      const peerConn = router.getConnectionForDestination(destIp, routingCtx)

      if (peerConn) {
        if (
          clientIp &&
          !tunnelSourceAllowedForPeerStream(packet, clientIp, clientKeyHex, kaOpen)
        ) {
          return
        }
        peerConn.write(encode(wrapTunnelPayload(kaOpen, packet)))
      } else {
        // Internet or local stack: inner src may be any host (replies from the wider net).
        tun.write(packet)
      }
    })

    connection.on('data', function (data) {
      decode(data)
    })

    connection.on('error', function (err) {
      console.error(`Connection error (${clientKeyShort}):`, err.message)
    })

    connection.on('close', function () {
      console.log(`Client disconnected: ${clientKeyShort}`)
      if (kaOpen) {
        hubConnections.delete(connection)
        broadcastHubDirectory()
      }
      if (clientIp) {
        router.removePeer(clientKeyHex)
        if (peerIpAllocator && kaOpen) {
          kaOpen.unregister(clientIp)
          peerIpAllocator.release(clientIp)
        }
      }
    })
  })

  // Route outgoing TUN packets to the correct client (or hairpin to local stack)
  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return

    const connection = router.getConnectionForDestination(destIp, routingCtx)
    if (connection) {
      connection.write(encode(wrapTunnelPayload(kaOpen, packet)))
      return
    }
    if (shouldHairpinToLocalStack(destIp, routingCtx)) {
      try {
        tun.write(packet)
      } catch (_) {}
    }
  })

  await server.listen(keyPair)

  // Enable NAT if full tunnel mode
  let natState = null
  if (fullTunnel) {
    // Derive subnet from server IP for iptables rules
    const ipParts = ip.split('/')
    const octets = ipParts[0].split('.')
    const subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/${ipParts[1] || '24'}`

    if (!hasFirewall) {
      console.log('')
      console.log('WARNING: --full-tunnel without an allowlist (--config or peer keys) creates an OPEN PROXY')
      console.log('         Anyone with the public key can route internet traffic through this server')
      console.log('')
    }

    natState = enableServerForwarding(outInterface, subnet, tun.name)
  }

  const tunIp = ip.split('/')[0]

  console.log('')
  console.log('Server listening')
  console.log('TUN IP:     ', tunIp)
  console.log('Public key: ', encodeZ32(keyPair.publicKey))
  if (allowedPeers) {
    console.log('Allowed peers (--config):', allowedPeers.size)
    for (const [key, peerIp] of allowedPeers) {
      console.log(`  ${encodeZ32(Buffer.from(key, 'hex'))} → ${peerIp}`)
    }
  } else if (allowedKeySet && allowedKeySet.size > 0) {
    console.log('Allowed peers (CLI):', allowedKeySet.size, '— incremental aliases .2, .3, …')
    for (const k of allowedKeySet) {
      console.log(`  ${encodeZ32(Buffer.from(k, 'hex'))}`)
    }
    console.log('Tunnel:      IPv4 wire uses key-address (IPv6 passes through raw)')
  } else {
    console.log('Auth:        OPEN (no allowlist — any client can connect)')
    console.log('Tunnel:      IPv4 wire uses key-address (IPv6 passes through raw)')
  }
  console.log('')
  console.log('Client command:')
  console.log(`  sudo nospoon client ${encodeZ32(keyPair.publicKey)}`)

  let exiting = false
  function shutdown () {
    if (exiting) return
    exiting = true
    console.log('\nShutting down...')
    if (natState) disableServerForwarding(natState)
    try { tun.release() } catch (e) {}
    server.close()
    if (ownDht) dht.destroy()
    setTimeout(function () { process.exit(0) }, 500)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  return { server, dht, tun, seed: seedBuf, keyPair }
}

module.exports = { startServer }
