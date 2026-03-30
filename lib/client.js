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

function noop () {}

/**
 * Same encrypted stream as the full client uses for `dht.connect(serverKey, { keyPair })`,
 * but with a **shared** HyperDHT (equivalent to passing `opts.dht` into {@link createClient}).
 * Framing, TUN, and application keepalive remain the caller’s responsibility if you use this alone.
 *
 * Ambient / server-mode peers use the same wire: DHT to an announcer that runs {@link startServer},
 * not a Hyperswarm topic — still a normal nospoon client stream once connected.
 *
 * @param {import('hyperdht')} dht
 * @param {string} remoteKeyHex — 64 lowercase hex (32-byte remote public key)
 * @param {{ publicKey: Buffer, secretKey: Buffer }} keyPair — usually `HyperDHT.keyPair(Buffer.from(seed, 'hex'))`
 * @returns {import('stream').Duplex & { destroy: function(): void, remotePublicKey: Buffer }}
 */
function connectAsClient (dht, remoteKeyHex, keyPair) {
  if (!dht || typeof dht.connect !== 'function') {
    throw new Error('connectAsClient: dht with .connect is required')
  }
  const h = String(remoteKeyHex).trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error('connectAsClient: expected 64 hex character remote key')
  }
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('connectAsClient: keyPair with publicKey and secretKey is required')
  }
  return dht.connect(Buffer.from(h, 'hex'), { keyPair })
}

/**
 * @param {{ cli?: boolean }} opts
 * @returns {{ info: function(string): void, error: function(...args): void }}
 */
function resolveLogger (opts) {
  if (opts.logger && typeof opts.logger.info === 'function') {
    const err = opts.logger.error || opts.logger.info
    return { info: opts.logger.info.bind(opts.logger), error: err.bind(opts.logger) }
  }
  if (opts.cli) {
    return { info: console.log.bind(console), error: console.error.bind(console) }
  }
  return { info: noop, error: noop }
}

/**
 * Programmatic nospoon **client**: TUN + key-address over HyperDHT to a **server** announcer
 * (`nospoon server`, same transport as `nospoon client` CLI). This is the same path ambient mesh
 * uses when SpoonDNS dials a peer by public key — not topic-based Hyperswarm mesh.
 *
 * @param {object} opts
 * @param {string} opts.key — 64 hex, remote server public key
 * @param {string} [opts.ip='10.0.0.1/24'] — local TUN IPv4 CIDR
 * @param {object} [opts.ipv6]
 * @param {string} [opts.seed] — 32-byte seed hex for fixed client keyPair
 * @param {number} [opts.mtu=1400]
 * @param {boolean} [opts.fullTunnel]
 * @param {string} [opts.peerIp='10.0.0.2'] — virtual IPv4 for the server key inside the tunnel
 * @param {import('hyperdht')} [opts.dht] — shared HyperDHT; if omitted, {@link shutdown} destroys a new instance
 * @param {boolean} [opts.cli=false] — when true: SIGINT/SIGTERM call {@link shutdown} and **process.exit(0)**
 * @param {{ info?: function(string): void, error?: function(...args): void }} [opts.logger] — overrides default logging (default: console if cli, else silent)
 * @param {{ onStreamOpen?: function(): void, onStreamClose?: function(): void, onStreamError?: function(Error): void }} [opts.hooks] — stream lifecycle for embedders (still runs on reconnects)
 * @returns {{ dht: import('hyperdht'), tun: object, shutdown: function(): void }}
 */
function createClient (opts) {
  const key = opts.key
  if (!key || typeof key !== 'string') throw new Error('createClient: key is required')
  const serverPublicKey = Buffer.from(String(key).trim(), 'hex')
  if (serverPublicKey.length !== 32) throw new Error('createClient: key must be 32 bytes (64 hex chars)')

  const ip = opts.ip != null ? opts.ip : '10.0.0.1/24'
  const ipv6 = opts.ipv6
  const seed = opts.seed
  const mtu = opts.mtu != null ? Number(opts.mtu) : 1400
  const fullTunnel = Boolean(opts.fullTunnel)
  const peerIp = opts.peerIp != null ? opts.peerIp : '10.0.0.2'
  const dhtOpt = opts.dht
  const cli = Boolean(opts.cli)
  const logger = resolveLogger(opts)
  const hooks = opts.hooks && typeof opts.hooks === 'object' ? opts.hooks : null

  const ownDht = !dhtOpt
  let dht = dhtOpt || new HyperDHT()

  const seedBuf = seed ? Buffer.from(seed, 'hex') : null
  const connectOpts = {
    keyPair: seedBuf ? HyperDHT.keyPair(seedBuf) : HyperDHT.keyPair()
  }
  if (seed && cli) {
    logger.info('Client public key: ' + connectOpts.keyPair.publicKey.toString('hex'))
    logger.info('(give this to the server operator for the peers config)')
    logger.info('')
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
    const connection = connectAsClient(dht, serverPublicKey.toString('hex'), connectOpts.keyPair)
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
            logger.info(`Hub directory: spoke peer ${alias} (key ${encodeZ32(Buffer.from(k, 'hex'))})`)
          } catch (e) {
            logger.error('Hub directory:', e.message)
          }
        }
      }

      decode = createDecoder(function (framedPayload) {
        if (isDirectoryFrame(framedPayload)) {
          try {
            applyHubDirectory(decodeHubDirectory(framedPayload))
          } catch (e) {
            logger.error('Hub directory:', e.message)
          }
          return
        }
        const packet = unwrapTunnelPayload(kaClient, framedPayload)
        if (packet) tun.write(packet)
      })

      if (cli) {
        logger.info('Connected to server')
        logger.info(`Local TUN ${stripHostFromCidr(ip)}, peer key mapped at ${peerIp}`)
        logger.info('Tunnel: IPv4 wire uses key-address (IPv6 passes through raw)')
      }
      startKeepalive(connection)
      if (hooks && typeof hooks.onStreamOpen === 'function') {
        try {
          hooks.onStreamOpen()
        } catch (_) {}
      }

      if (fullTunnel) {
        const serverHost = connection.rawStream
          ? connection.rawStream.remoteHost
          : null

        if (cli) logger.info('DHT remote endpoint: ' + serverHost)

        if (!fullTunnelActive) {
          enableClientFullTunnel(serverHost, tun.name)
          fullTunnelActive = true
        } else {
          addHostExemption(serverHost)
        }
      }
    })

    connection.on('data', function (data) {
      if (decode) decode(data)
    })

    connection.on('error', function (err) {
      logger.error('Connection error:', err.message)
      if (hooks && typeof hooks.onStreamError === 'function') {
        try {
          hooks.onStreamError(err instanceof Error ? err : new Error(String(err)))
        } catch (_) {}
      }
    })

    connection.on('close', function () {
      activeConnection = null
      decode = null
      kaClient = null
      peerAliasAllocator = null

      if (shuttingDown) return

      if (hooks && typeof hooks.onStreamClose === 'function') {
        try {
          hooks.onStreamClose()
        } catch (_) {}
      }

      consecutiveFailures++

      if (fullTunnelActive && consecutiveFailures >= MAX_FAILURES_BEFORE_RESTART) {
        if (cli) {
          logger.info(`${consecutiveFailures} consecutive failures — restarting DHT to find server...`)
        }
        restartDht()
        return
      }

      const jitter = Math.floor(Math.random() * 1000)
      const delay = retryDelay + jitter
      if (cli) {
        logger.info(`Connection lost. Reconnecting in ${Math.round(delay / 1000)}s...`)
      }

      setTimeout(function () {
        if (!shuttingDown) connect()
      }, delay)

      retryDelay = Math.min(retryDelay * 2, MAX_RETRY_MS)
    })
  }

  function restartDht () {
    if (cli) logger.info('Removing tunnel routes for DHT restart...')
    disableClientFullTunnel()
    fullTunnelActive = false

    if (ownDht) {
      const oldDht = dht
      dht = new HyperDHT()
      oldDht.destroy().catch(function () {})
    } else {
      if (cli) logger.info('(external DHT: reconnecting without replacing instance)')
    }

    retryDelay = INITIAL_RETRY_MS
    consecutiveFailures = 0

    if (cli) logger.info('Routes removed — reconnecting...')
    connect()
  }

  tun.on('data', function (packet) {
    if (!activeConnection || activeConnection.destroyed || !kaClient) return
    activeConnection.write(encode(wrapTunnelPayload(kaClient, packet)))
  })

  connect()

  function shutdown () {
    if (shuttingDown) return
    shuttingDown = true
    if (cli) logger.info('\nShutting down...')
    if (fullTunnelActive) disableClientFullTunnel()
    try { tun.release() } catch (e) {}
    if (activeConnection) activeConnection.end()
    if (ownDht) dht.destroy()
    if (cli) {
      setTimeout(function () { process.exit(0) }, 500)
    }
  }

  if (cli) {
    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
  }

  return { dht, tun, shutdown }
}

/**
 * CLI entry: same as {@link createClient} with `cli: true` (signals + `process.exit` on shutdown).
 * @param {object} opts — same as createClient except `cli` is forced true
 */
async function startClient (opts) {
  return createClient({ ...opts, cli: true })
}

module.exports = { createClient, startClient, connectAsClient }
