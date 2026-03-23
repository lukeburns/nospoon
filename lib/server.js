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
const { createRouter, readDestinationIp, readSourceIp } = require('./routing')
const { enableServerForwarding, disableServerForwarding } = require('./full-tunnel')

function ipToInt (ip) {
  const octets = ip.split('.').map(Number)
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
}

function intToIp (x) {
  const u = x >>> 0
  return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`
}

/** Lowest unused host in subnet (excluding network, broadcast, server address). */
function createPeerIpAllocator (serverCidr) {
  const { hostIp, network, broadcast } = parseSubnet(serverCidr)
  const used = new Set()

  function allocate () {
    const net = network >>> 0
    const bc = broadcast >>> 0
    const host = hostIp >>> 0
    for (let addr = (net + 1) >>> 0; addr < bc; addr = (addr + 1) >>> 0) {
      if (addr === host) continue
      const ip = intToIp(addr)
      if (used.has(ip)) continue
      used.add(ip)
      return ip
    }
    throw new Error('No free IPv4 address in server subnet for peer alias')
  }

  function release (ip) {
    used.delete(ip)
  }

  return { allocate, release }
}

function parseSubnet (cidr) {
  const [ip, prefixStr] = cidr.split('/')
  const prefix = parseInt(prefixStr || '24', 10)
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const hostIp = ipToInt(ip)
  const network = (hostIp & mask) >>> 0
  const broadcast = (network | ~mask) >>> 0

  return { hostIp, network, broadcast, mask, prefix }
}

function loadPeers (configPath, serverCidr) {
  const raw = fs.readFileSync(configPath, 'utf-8')
  const config = JSON.parse(raw)

  if (!config.peers || typeof config.peers !== 'object') {
    throw new Error('Config must have a "peers" object mapping public keys to IPs')
  }

  const subnet = serverCidr ? parseSubnet(serverCidr) : null

  const seen = new Set()
  for (const [key, ip] of Object.entries(config.peers)) {
    const label = key.slice(0, 8) + '...'

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
  }

  // publicKeyHex → ip
  return new Map(Object.entries(config.peers))
}

async function startServer ({ ip = '10.0.0.1/24', ipv6, seed, mtu = 1400, config, fullTunnel, outInterface, allowedKeys }) {
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
  const dht = new HyperDHT()
  const tun = createTunDevice({ ipv4: ip, ipv6, mtu })
  const router = createRouter()

  const routingCtx = {
    localKey: keyPair.publicKey,
    ka: null,
    ipToKeyHex: ipToPeerKeyHex
  }

  const kaOpen = !allowedPeers
    ? createKeyAddressTable({
      localKey: keyPair.publicKey,
      localIp: stripHostFromCidr(ip)
    })
    : null

  routingCtx.ka = kaOpen

  const peerIpAllocator = !allowedPeers && kaOpen ? createPeerIpAllocator(ip) : null

  const serverOpts = {
    firewall (remotePublicKey) {
      const keyHex = remotePublicKey.toString('hex')
      if (allowedKeySet && allowedKeySet.size > 0) {
        if (!allowedKeySet.has(keyHex)) {
          console.log(`Firewalled peer not in CLI allowlist: ${keyHex.slice(0, 8)}...`)
          return true
        }
        return false
      }
      if (allowedPeers) {
        const allowed = allowedPeers.has(keyHex)
        if (!allowed) {
          console.log(`Firewalled unknown peer: ${keyHex.slice(0, 8)}...`)
        }
        return !allowed
      }
      return false // open mode, allow all
    }
  }

  const server = dht.createServer(serverOpts, function (connection) {
    const clientKeyHex = connection.remotePublicKey.toString('hex')
    const clientKeyShort = clientKeyHex.slice(0, 8) + '...'

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
    }

    console.log(`Client connected: ${clientKeyShort}` + (clientIp ? ` → ${clientIp}` : ''))
    startKeepalive(connection)

    if (allowedPeers && clientIp) {
      router.addPeer(connection.remotePublicKey, connection)
    }

    const decode = createDecoder(function (framedPayload) {
      const packet = unwrapTunnelPayload(kaOpen, framedPayload)
      const srcIp = readSourceIp(packet)

      if (allowedPeers) {
        // Authenticated mode: verify source IP matches assigned IP
        if (srcIp !== clientIp) return
      } else if (clientIp && srcIp !== clientIp) {
        // Open mode: src must match this server's incremental alias for peer
        return
      }

      const destIp = readDestinationIp(packet)
      const peerConn = router.getConnectionForDestination(destIp, routingCtx)

      if (peerConn) {
        // Destination is another client — forward directly
        peerConn.write(encode(wrapTunnelPayload(kaOpen, packet)))
      } else {
        // Destination is the server or external — send to TUN
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
      if (clientIp) {
        router.removePeer(clientKeyHex)
        if (peerIpAllocator && kaOpen) {
          kaOpen.unregister(clientIp)
          peerIpAllocator.release(clientIp)
        }
      }
    })
  })

  // Route outgoing TUN packets to the correct client
  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return

    const connection = router.getConnectionForDestination(destIp, routingCtx)
    if (connection) {
      connection.write(encode(wrapTunnelPayload(kaOpen, packet)))
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
  console.log('Public key: ', keyPair.publicKey.toString('hex'))
  if (allowedPeers) {
    console.log('Allowed peers (--config):', allowedPeers.size)
    for (const [key, peerIp] of allowedPeers) {
      console.log(`  ${key.slice(0, 8)}... → ${peerIp}`)
    }
  } else if (allowedKeySet && allowedKeySet.size > 0) {
    console.log('Allowed peers (CLI):', allowedKeySet.size, '— incremental aliases .2, .3, …')
    for (const k of allowedKeySet) {
      console.log(`  ${k.slice(0, 8)}...`)
    }
    console.log('Tunnel:      IPv4 wire uses key-address (IPv6 passes through raw)')
  } else {
    console.log('Auth:        OPEN (no allowlist — any client can connect)')
    console.log('Tunnel:      IPv4 wire uses key-address (IPv6 passes through raw)')
  }
  console.log('')
  console.log('Client command:')
  console.log(`  sudo nospoon client ${keyPair.publicKey.toString('hex')}`)

  let exiting = false
  function shutdown () {
    if (exiting) return
    exiting = true
    console.log('\nShutting down...')
    if (natState) disableServerForwarding(natState)
    try { tun.release() } catch (e) {}
    server.close()
    dht.destroy()
    setTimeout(function () { process.exit(0) }, 500)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  return { server, dht, tun, seed: seedBuf, keyPair }
}

module.exports = { startServer }
