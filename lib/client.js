const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const {
  createKeyAddressTable,
  stripHostFromCidr,
  wrapTunnelPayload,
  unwrapTunnelPayload
} = require('./key-address')
const { enableClientFullTunnel, addHostExemption, disableClientFullTunnel } = require('./full-tunnel')
const { createPeerIpAllocator } = require('./ip-subnet')
const { isDirectoryFrame, decodeHubDirectory } = require('./hub-directory')
const { encodeZ32 } = require('./key-encoding')

const INITIAL_RETRY_MS = 1000
const MAX_RETRY_MS = 30000
const MAX_FAILURES_BEFORE_RESTART = 3

/**
 * @param {object} opts
 * @param {object} [opts.dht] — Existing HyperDHT instance. If omitted, a new instance is created and destroyed on shutdown. When injected, `restartDht` reconnects without replacing the instance (full-tunnel “fresh DHT” recovery may be weaker).
 */
async function startClient ({ key, ip = '10.0.0.1/24', ipv6, seed, mtu = 1400, fullTunnel, peerIp = '10.0.0.2', dht: dhtOpt }) {
  const serverPublicKey = Buffer.from(key, 'hex')
  const ownDht = !dhtOpt
  let dht = dhtOpt || new HyperDHT()

  const seedBuf = seed ? Buffer.from(seed, 'hex') : null
  const connectOpts = {
    keyPair: seedBuf ? HyperDHT.keyPair(seedBuf) : HyperDHT.keyPair()
  }
  if (seed) {
    console.log('Client public key:', connectOpts.keyPair.publicKey.toString('hex'))
    console.log('(give this to the server operator for the peers config)')
    console.log('')
  }

  const tun = createTunDevice({ ipv4: ip, ipv6, mtu })

  let shuttingDown = false
  let activeConnection = null
  let kaClient = null
  let peerAliasAllocator = null
  let retryDelay = INITIAL_RETRY_MS
  let fullTunnelActive = false
  let consecutiveFailures = 0

  function connect () {
    const connection = dht.connect(serverPublicKey, connectOpts)
    activeConnection = connection

    let decode = null

    connection.on('open', function () {
      retryDelay = INITIAL_RETRY_MS
      consecutiveFailures = 0
      const localKey = connectOpts.keyPair.publicKey
      kaClient = createKeyAddressTable({
        localKey,
        localIp: stripHostFromCidr(ip)
      })
      kaClient.register(peerIp, serverPublicKey)

      peerAliasAllocator = createPeerIpAllocator(ip, {
        initialUsed: new Set([stripHostFromCidr(ip), peerIp])
      })

      function applyHubDirectory (json) {
        const myHex = localKey.toString('hex')
        const serverHex = serverPublicKey.toString('hex')
        for (const p of json.peers) {
          if (!p || typeof p.k !== 'string') continue
          const k = p.k.toLowerCase()
          if (k === myHex || k === serverHex) continue
          let pkBuf
          try {
            pkBuf = Buffer.from(k, 'hex')
          } catch {
            continue
          }
          if (pkBuf.length !== 32) continue
          try {
            kaClient.keyToIp(pkBuf)
            continue
          } catch (_) {}
          try {
            const alias = peerAliasAllocator.allocate()
            kaClient.register(alias, pkBuf)
            console.log(`Hub directory: spoke peer ${alias} (key ${encodeZ32(Buffer.from(k, 'hex'))})`)
          } catch (e) {
            console.error('Hub directory:', e.message)
          }
        }
      }

      decode = createDecoder(function (framedPayload) {
        if (isDirectoryFrame(framedPayload)) {
          try {
            applyHubDirectory(decodeHubDirectory(framedPayload))
          } catch (e) {
            console.error('Hub directory:', e.message)
          }
          return
        }
        const packet = unwrapTunnelPayload(kaClient, framedPayload)
        if (packet) tun.write(packet)
      })

      console.log('Connected to server')
      console.log(`Local TUN ${stripHostFromCidr(ip)}, peer key mapped at ${peerIp}`)
      console.log('Tunnel: IPv4 wire uses key-address (IPv6 passes through raw)')
      startKeepalive(connection)

      if (fullTunnel) {
        // Get the actual IP the DHT stream is talking to
        const serverHost = connection.rawStream
          ? connection.rawStream.remoteHost
          : null

        console.log('DHT remote endpoint:', serverHost)

        if (!fullTunnelActive) {
          enableClientFullTunnel(serverHost, tun.name)
          fullTunnelActive = true
        } else {
          // Reconnected — exempt the new server address if it changed
          addHostExemption(serverHost)
        }
      }
    })

    connection.on('data', function (data) {
      if (decode) decode(data)
    })

    connection.on('error', function (err) {
      console.error('Connection error:', err.message)
    })

    connection.on('close', function () {
      activeConnection = null
      decode = null
      kaClient = null
      peerAliasAllocator = null

      if (shuttingDown) return

      consecutiveFailures++

      // If full tunnel is active and we've failed too many times,
      // the server's IP may have changed. DHT lookups to other nodes
      // go through tun0 (dead tunnel) and fail. We need to temporarily
      // remove the tunnel routes so DHT can reach the internet directly,
      // find the server at its new IP, and re-establish the tunnel.
      if (fullTunnelActive && consecutiveFailures >= MAX_FAILURES_BEFORE_RESTART) {
        console.log(`${consecutiveFailures} consecutive failures — restarting DHT to find server...`)
        restartDht()
        return
      }

      const jitter = Math.floor(Math.random() * 1000)
      const delay = retryDelay + jitter
      console.log(`Connection lost. Reconnecting in ${Math.round(delay / 1000)}s...`)

      setTimeout(function () {
        if (!shuttingDown) connect()
      }, delay)

      retryDelay = Math.min(retryDelay * 2, MAX_RETRY_MS)
    })
  }

  // Full DHT restart: remove tunnel routes so DHT lookups can reach
  // the real internet, create a fresh DHT instance, and reconnect.
  // The tunnel routes are re-added when the new connection opens.
  function restartDht () {
    console.log('Removing tunnel routes for DHT restart...')
    disableClientFullTunnel()
    fullTunnelActive = false

    if (ownDht) {
      const oldDht = dht
      dht = new HyperDHT()
      oldDht.destroy().catch(function () {})
    } else {
      console.log('(external DHT: reconnecting without replacing instance)')
    }

    retryDelay = INITIAL_RETRY_MS
    consecutiveFailures = 0

    console.log('Routes removed — reconnecting...')
    connect()
  }

  // Route TUN packets to the active connection (key-address after stream opens)
  tun.on('data', function (packet) {
    if (!activeConnection || activeConnection.destroyed || !kaClient) return
    activeConnection.write(encode(wrapTunnelPayload(kaClient, packet)))
  })

  connect()

  function shutdown () {
    if (shuttingDown) return
    shuttingDown = true
    console.log('\nShutting down...')
    if (fullTunnelActive) disableClientFullTunnel()
    try { tun.release() } catch (e) {}
    if (activeConnection) activeConnection.end()
    if (ownDht) dht.destroy()
    setTimeout(function () { process.exit(0) }, 500)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  return { dht, tun }
}

module.exports = { startClient }
