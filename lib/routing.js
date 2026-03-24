// Reads destination/source from IP packet headers. Peer forwarding uses the
// key-address table (ip ↔ key): destination IP resolves to a key, then we
// look up the live DHT connection by key — not a parallel ip→connection map.

const { formatKeyShortFromHex } = require('./key-encoding')

const IPV4_MIN_LENGTH = 20
const IPV6_MIN_LENGTH = 40

/**
 * @param {{ silent?: boolean }} [opts] — set `silent: true` when embedding (e.g. SpoonDNS TUI) to skip route logs
 */
function createRouter (opts) {
  const silent = opts && opts.silent === true
  // remote public key hex → HyperDHT connection
  const byKeyHex = new Map()

  function addPeer (publicKey, connection) {
    const hex = Buffer.isBuffer(publicKey) ? publicKey.toString('hex') : publicKey
    byKeyHex.set(hex, connection)
    if (!silent) console.log(`Route added: key ${formatKeyShortFromHex(hex)} → connection`)
  }

  function removePeer (publicKey) {
    const hex = Buffer.isBuffer(publicKey) ? publicKey.toString('hex') : publicKey
    byKeyHex.delete(hex)
    if (!silent) console.log(`Route removed: key ${formatKeyShortFromHex(hex)}`)
  }

  /**
   * @param {string|null|undefined} destIp — from readDestinationIp
   * @param {object} ctx
   * @param {Buffer} ctx.localKey — this host’s public key (packets to self go to TUN, not a peer)
   * @param {object|null} ctx.ka — key-address table (open mode); ipToKey resolves dst → peer key
   * @param {Map<string,string>|null} [ctx.ipToKeyHex] — authenticated mode: peer alias ip → key hex (when ka is null)
   */
  function getConnectionForDestination (destIp, ctx) {
    if (!destIp) return null
    const { localKey, ka, ipToKeyHex } = ctx

    if (ka) {
      let peerKey
      try {
        peerKey = ka.ipToKey(destIp)
      } catch {
        return null
      }
      if (peerKey.equals(localKey)) return null
      const conn = byKeyHex.get(peerKey.toString('hex'))
      return conn && !conn.destroyed ? conn : null
    }

    if (ipToKeyHex) {
      const keyHex = ipToKeyHex.get(destIp)
      if (!keyHex) return null
      const conn = byKeyHex.get(keyHex)
      return conn && !conn.destroyed ? conn : null
    }

    return null
  }

  function activeCount () {
    return byKeyHex.size
  }

  return { addPeer, removePeer, getConnectionForDestination, activeCount }
}

function readIpVersion (packet) {
  if (packet.length < 1) return null
  return (packet[0] >>> 4) & 0x0f
}

function formatIpv4 (packet, offset) {
  return `${packet[offset]}.${packet[offset + 1]}.${packet[offset + 2]}.${packet[offset + 3]}`
}

function formatIpv6 (packet, offset) {
  const groups = []
  for (let i = 0; i < 8; i++) {
    const word = (packet[offset + i * 2] << 8) | packet[offset + i * 2 + 1]
    groups.push(word.toString(16))
  }

  // Collapse longest run of consecutive 0 groups into ::
  let bestStart = -1
  let bestLen = 0
  let curStart = -1
  let curLen = 0

  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart === -1) curStart = i
      curLen++
      if (curLen > bestLen) {
        bestStart = curStart
        bestLen = curLen
      }
    } else {
      curStart = -1
      curLen = 0
    }
  }

  if (bestLen > 1) {
    const before = groups.slice(0, bestStart)
    const after = groups.slice(bestStart + bestLen)
    const mid = bestStart === 0 || bestStart + bestLen === 8 ? ':' : ''
    return before.join(':') + '::' + mid + after.join(':')
  }

  return groups.join(':')
}

// Read destination IP from an IP packet header (IPv4 or IPv6)
function readDestinationIp (packet) {
  const version = readIpVersion(packet)

  if (version === 4 && packet.length >= IPV4_MIN_LENGTH) {
    return formatIpv4(packet, 16)
  }

  if (version === 6 && packet.length >= IPV6_MIN_LENGTH) {
    return formatIpv6(packet, 24)
  }

  return null
}

// Read source IP from an IP packet header (IPv4 or IPv6)
function readSourceIp (packet) {
  const version = readIpVersion(packet)

  if (version === 4 && packet.length >= IPV4_MIN_LENGTH) {
    return formatIpv4(packet, 12)
  }

  if (version === 6 && packet.length >= IPV6_MIN_LENGTH) {
    return formatIpv6(packet, 8)
  }

  return null
}

module.exports = { createRouter, readDestinationIp, readSourceIp }
