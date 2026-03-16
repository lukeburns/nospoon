const HyperDHT = require('hyperdht')
const crypto = require('crypto')
const fs = require('fs')
const net = require('net')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const { createRouter, readDestinationIp, readSourceIp } = require('./routing')
const { enableServerForwarding, disableServerForwarding } = require('./full-tunnel')

function loadPeers (configPath) {
  const raw = fs.readFileSync(configPath, 'utf-8')
  const config = JSON.parse(raw)

  if (!config.peers || typeof config.peers !== 'object') {
    throw new Error('Config must have a "peers" object mapping public keys to IPs')
  }

  const seen = new Set()
  for (const [key, ip] of Object.entries(config.peers)) {
    if (!net.isIPv4(ip) && !net.isIPv6(ip)) {
      throw new Error(`Invalid IP for peer ${key.slice(0, 8)}...: ${ip}`)
    }
    if (seen.has(ip)) {
      throw new Error(`Duplicate IP assignment in peers config: ${ip}`)
    }
    seen.add(ip)
  }

  // publicKeyHex → ip
  return new Map(Object.entries(config.peers))
}

async function startServer ({ ip = '10.0.0.1/24', ipv6, seed, mtu = 1400, config, fullTunnel, outInterface }) {
  const seedBuf = seed
    ? Buffer.from(seed, 'hex')
    : crypto.randomBytes(32)

  // Load allowed peers if config provided
  const allowedPeers = config ? loadPeers(config) : null

  const keyPair = HyperDHT.keyPair(seedBuf)
  const dht = new HyperDHT()
  const tun = createTunDevice({ ipv4: ip, ipv6, mtu })
  const router = createRouter()

  const serverOpts = {
    firewall (remotePublicKey) {
      if (!allowedPeers) return false // open mode, allow all
      const keyHex = remotePublicKey.toString('hex')
      const allowed = allowedPeers.has(keyHex)
      if (!allowed) {
        console.log(`Firewalled unknown peer: ${keyHex.slice(0, 8)}...`)
      }
      return !allowed // true = reject, false = allow
    }
  }

  const server = dht.createServer(serverOpts, function (connection) {
    const clientKeyHex = connection.remotePublicKey.toString('hex')
    const clientKeyShort = clientKeyHex.slice(0, 8) + '...'

    let clientIp = allowedPeers
      ? allowedPeers.get(clientKeyHex)
      : null

    console.log(`Client connected: ${clientKeyShort}` + (clientIp ? ` → ${clientIp}` : ''))
    startKeepalive(connection)

    if (clientIp) {
      router.add(clientIp, connection)
    }

    const decode = createDecoder(function (packet) {
      const srcIp = readSourceIp(packet)

      if (allowedPeers) {
        // Authenticated mode: verify source IP matches assigned IP
        if (srcIp !== clientIp) return
      } else if (!clientIp && srcIp) {
        // Open mode: learn client IP from first packet
        const existing = router.getByIp(srcIp)
        if (existing && !existing.destroyed) {
          // IP already taken by another client — drop packet
          return
        }
        clientIp = srcIp
        router.add(clientIp, connection)
      } else if (clientIp && srcIp !== clientIp) {
        // Open mode: source IP changed after learning — drop
        return
      }

      const destIp = readDestinationIp(packet)
      const peerConn = destIp ? router.getByIp(destIp) : null

      if (peerConn && !peerConn.destroyed) {
        // Destination is another client — forward directly
        peerConn.write(encode(packet))
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
        router.remove(clientIp)
      }
    })
  })

  // Route outgoing TUN packets to the correct client
  tun.on('data', function (packet) {
    const destIp = readDestinationIp(packet)
    if (!destIp) return

    const connection = router.getByIp(destIp)
    if (connection && !connection.destroyed) {
      connection.write(encode(packet))
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

    if (!allowedPeers) {
      console.log('')
      console.log('WARNING: --full-tunnel without --config creates an OPEN PROXY')
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
    console.log('Allowed peers:', allowedPeers.size)
    for (const [key, peerIp] of allowedPeers) {
      console.log(`  ${key.slice(0, 8)}... → ${peerIp}`)
    }
  } else {
    console.log('Auth:        OPEN (no --config, any client can connect)')
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
