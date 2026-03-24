/**
 * Key ↔ local IPv4 / IPv6 alias translation for tunnel payloads.
 *
 * Wire format — IPv4 (20-byte header, no options):
 *   [ IPv4 bytes 0–11 ][ 32-byte src key ][ 32-byte dst key ][ IP payload ]
 *   Fixed prefix: 76 bytes (WIRE_IPV4_KEY_HEADER_LEN).
 *
 * Wire format — IPv6 (40-byte base header, no extension headers):
 *   [ IPv6 bytes 0–7 ][ 32-byte src key ][ 32-byte dst key ][ IP payload ]
 *   Fixed prefix: 72 bytes (WIRE_IPV6_KEY_HEADER_LEN).
 *
 * Decode picks IPv4 vs IPv6 from the first nibble of byte 0 (4 vs 6).
 *
 * Checksums: IPv4 header checksum + L4; IPv6 has no header checksum; TCP/UDP/ICMPv6 use
 * IPv6 pseudo-header for L4. See module body for details.
 *
 * Multiple aliases per key: ip→key unique per IP; key→ip keeps first registered alias.
 */

const net = require('net')

/** Next-header values that start extension headers (not upper-layer directly). */
const IPV6_EXTENSION_HEADERS = new Set([0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254])

const KEY_LEN = 32
const IPV4_HEADER_LEN = 20
const IPV4_PREFIX_LEN = 12
const WIRE_IPV4_KEY_HEADER_LEN = IPV4_PREFIX_LEN + KEY_LEN + KEY_LEN

const IPV6_HEADER_LEN = 40
const IPV6_PREFIX_LEN = 8
const WIRE_IPV6_KEY_HEADER_LEN = IPV6_PREFIX_LEN + KEY_LEN + KEY_LEN

const PROTO_ICMP = 1
const PROTO_TCP = 6
const PROTO_UDP = 17
const PROTO_ICMPV6 = 58

const VER_IPV4 = 4
const VER_IPV6 = 6

function createKeyAddressTable (opts = {}) {
  const ipToKeyMap = new Map()
  const keyHexToIp = new Map()

  function normalizeIp (ip) {
    if (Buffer.isBuffer(ip)) {
      if (ip.length === 4) return ipv4BufferToString(ip)
      if (ip.length === 16) return ipv6BufferToCanonicalString(ip)
      throw new Error('IP buffer must be 4 bytes (IPv4) or 16 bytes (IPv6)')
    }
    if (typeof ip === 'string') {
      if (net.isIPv4(ip)) return ip
      if (net.isIPv6(ip)) return canonicalizeIpv6String(ip)
      throw new Error(`Invalid IP string: ${ip}`)
    }
    throw new Error('IP must be a string or Buffer')
  }

  function register (ip, key) {
    const ipStr = normalizeIp(ip)
    const k = toKeyBuffer(key)
    const hex = k.toString('hex')
    if (ipToKeyMap.has(ipStr) && ipToKeyMap.get(ipStr).toString('hex') !== hex) {
      throw new Error(`IP ${ipStr} already mapped to a different key`)
    }
    ipToKeyMap.set(ipStr, k)
    if (!keyHexToIp.has(hex)) keyHexToIp.set(hex, ipStr)
  }

  /** Remove a peer mapping (e.g. on disconnect). Does not remove localIp/localKey. */
  function unregister (ip) {
    const ipStr = normalizeIp(ip)
    const k = ipToKeyMap.get(ipStr)
    if (!k) return
    ipToKeyMap.delete(ipStr)
    const hex = k.toString('hex')
    if (keyHexToIp.get(hex) === ipStr) {
      keyHexToIp.delete(hex)
    }
  }

  if (opts.localIp != null && opts.localKey != null) {
    register(opts.localIp, opts.localKey)
  }

  function ipToKey (ip) {
    const ipStr = normalizeIp(ip)
    const k = ipToKeyMap.get(ipStr)
    if (!k) throw new Error(`No key registered for IP ${ipStr}`)
    return k
  }

  function keyToIp (key) {
    const k = toKeyBuffer(key)
    const ipStr = keyHexToIp.get(k.toString('hex'))
    if (!ipStr) throw new Error(`No IP registered for key ${k.toString('hex').slice(0, 16)}...`)
    return ipStringToBuffer(ipStr)
  }

  function encode (packet) {
    const ver = readIpVersion(packet)
    if (ver === VER_IPV4) return encodeIpv4(packet)
    if (ver === VER_IPV6) return encodeIpv6(packet)
    throw new Error(`Unsupported IP version ${ver}`)
  }

  function decode (buf) {
    if (buf.length < 1) throw new Error('Buffer too short')
    const ver = (buf[0] >> 4) & 0x0f
    if (ver === VER_IPV4) return decodeIpv4(buf)
    if (ver === VER_IPV6) return decodeIpv6(buf)
    throw new Error(`Unsupported wire version nibble ${ver}`)
  }

  function encodeIpv4 (packet) {
    assertIpv4NoOptions(packet)
    const srcKey = ipToKey(packet.subarray(12, 16))
    const dstKey = ipToKey(packet.subarray(16, 20))
    const prefix = Buffer.from(packet.subarray(0, IPV4_PREFIX_LEN))
    prefix.writeUInt16BE(0, 10)
    return Buffer.concat([prefix, srcKey, dstKey, packet.subarray(IPV4_HEADER_LEN)])
  }

  function encodeIpv6 (packet) {
    assertIpv6BaseOnly(packet)
    const srcKey = ipToKey(packet.subarray(8, 24))
    const dstKey = ipToKey(packet.subarray(24, 40))
    const prefix = Buffer.from(packet.subarray(0, IPV6_PREFIX_LEN))
    return Buffer.concat([prefix, srcKey, dstKey, packet.subarray(IPV6_HEADER_LEN)])
  }

  function decodeIpv4 (buf) {
    if (buf.length < WIRE_IPV4_KEY_HEADER_LEN) {
      throw new Error(`Buffer too short for IPv4 key frame (need >= ${WIRE_IPV4_KEY_HEADER_LEN})`)
    }
    const srcIp = keyToIp(buf.subarray(IPV4_PREFIX_LEN, IPV4_PREFIX_LEN + KEY_LEN))
    const dstIp = keyToIp(buf.subarray(IPV4_PREFIX_LEN + KEY_LEN, WIRE_IPV4_KEY_HEADER_LEN))
    const rest = buf.subarray(WIRE_IPV4_KEY_HEADER_LEN)

    const header = Buffer.allocUnsafe(IPV4_HEADER_LEN)
    buf.copy(header, 0, 0, IPV4_PREFIX_LEN)
    srcIp.copy(header, 12)
    dstIp.copy(header, 16)

    const totalLen = IPV4_HEADER_LEN + rest.length
    header.writeUInt16BE(totalLen, 2)
    header.writeUInt16BE(0, 10)
    header.writeUInt16BE(computeIpv4HeaderChecksum(header), 10)

    const packet = Buffer.concat([header, rest])
    recomputeL4ChecksumIpv4(packet)
    return packet
  }

  function decodeIpv6 (buf) {
    if (buf.length < WIRE_IPV6_KEY_HEADER_LEN) {
      throw new Error(`Buffer too short for IPv6 key frame (need >= ${WIRE_IPV6_KEY_HEADER_LEN})`)
    }
    const srcIp = keyToIp(buf.subarray(IPV6_PREFIX_LEN, IPV6_PREFIX_LEN + KEY_LEN))
    const dstIp = keyToIp(buf.subarray(IPV6_PREFIX_LEN + KEY_LEN, WIRE_IPV6_KEY_HEADER_LEN))
    const rest = buf.subarray(WIRE_IPV6_KEY_HEADER_LEN)

    const header = Buffer.allocUnsafe(IPV6_HEADER_LEN)
    buf.copy(header, 0, 0, IPV6_PREFIX_LEN)
    srcIp.copy(header, 8)
    dstIp.copy(header, 24)

    const payloadLen = rest.length
    header.writeUInt16BE(payloadLen, 4)

    const packet = Buffer.concat([header, rest])
    recomputeL4ChecksumIpv6(packet)
    return packet
  }

  return { register, unregister, ipToKey, keyToIp, encode, decode }
}

function readIpVersion (packet) {
  if (packet.length < 1) throw new Error('Packet too short')
  return (packet[0] >> 4) & 0x0f
}

function toKeyBuffer (key) {
  if (Buffer.isBuffer(key)) {
    if (key.length !== KEY_LEN) throw new Error(`Key must be ${KEY_LEN} bytes`)
    return key
  }
  if (typeof key === 'string') {
    if (!/^[0-9a-fA-F]{64}$/.test(key)) throw new Error('Key hex string must be 64 hex chars')
    return Buffer.from(key, 'hex')
  }
  throw new Error('Key must be a Buffer or hex string')
}

function ipv4BufferToString (buf) {
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`
}

function ipv6BufferToCanonicalString (buf) {
  return ipv6BufferToString(buf)
}

/** Full 8-group form (no ::) for stable Map keys. */
function ipv6BufferToString (buf) {
  const parts = []
  for (let i = 0; i < 8; i++) {
    parts.push(buf.readUInt16BE(i * 2).toString(16))
  }
  return parts.join(':')
}

function canonicalizeIpv6String (ip) {
  const buf = ipv6StringToBuffer(ip)
  return ipv6BufferToString(buf)
}

function ipv6HextetCount (parts) {
  let n = 0
  for (const p of parts) {
    if (p.includes('.')) n += 2
    else n += 1
  }
  return n
}

function parseIpv6HextetsToBuffer (parts) {
  const words = []
  for (const p of parts) {
    if (p.includes('.')) {
      const octets = p.split('.').map(Number)
      if (octets.length !== 4) throw new Error(`Bad IPv4-in-IPv6 tail: ${p}`)
      words.push((octets[0] << 8) | octets[1])
      words.push((octets[2] << 8) | octets[3])
    } else {
      words.push(parseInt(p, 16))
    }
  }
  if (words.length !== 8) throw new Error(`Bad IPv6 hextet count: ${words.length}`)
  const buf = Buffer.allocUnsafe(16)
  for (let i = 0; i < 8; i++) buf.writeUInt16BE(words[i] & 0xffff, i * 2)
  return buf
}

function ipv6StringToBuffer (ip) {
  if (!net.isIPv6(ip)) throw new Error(`Invalid IPv6 string: ${ip}`)
  const scopeIdx = ip.indexOf('%')
  const base = scopeIdx === -1 ? ip : ip.slice(0, scopeIdx)

  if (!base.includes('::')) {
    const raw = base.split(':')
    return parseIpv6HextetsToBuffer(raw)
  }

  const [l, r] = base.split('::', 2)
  const left = l ? l.split(':').filter(Boolean) : []
  const right = r ? r.split(':').filter(Boolean) : []
  const missing = 8 - ipv6HextetCount(left) - ipv6HextetCount(right)
  if (missing < 0) throw new Error(`Invalid IPv6 (too many segments): ${ip}`)
  const all = [...left, ...new Array(missing).fill('0'), ...right]
  return parseIpv6HextetsToBuffer(all)
}

function ipStringToBuffer (ipStr) {
  if (net.isIPv4(ipStr)) return ipStringToBufferV4(ipStr)
  if (net.isIPv6(ipStr)) return ipv6StringToBuffer(ipStr)
  throw new Error(`Unknown IP format: ${ipStr}`)
}

function ipStringToBufferV4 (ipStr) {
  const parts = ipStr.split('.')
  if (parts.length !== 4) throw new Error(`Invalid IPv4 string: ${ipStr}`)
  const b = Buffer.allocUnsafe(4)
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i], 10)
    if (n < 0 || n > 255) throw new Error(`Invalid IPv4 octet: ${ipStr}`)
    b[i] = n
  }
  return b
}

function assertIpv4NoOptions (packet) {
  if (packet.length < IPV4_HEADER_LEN) throw new Error('Packet too short for IPv4')
  const version = (packet[0] >> 4) & 0x0f
  if (version !== VER_IPV4) throw new Error('Expected IPv4 packet')
  const ihl = (packet[0] & 0x0f) * 4
  if (ihl !== IPV4_HEADER_LEN) {
    throw new Error('IPv4 with options (IHL != 5) not supported')
  }
}

function assertIpv6BaseOnly (packet) {
  if (packet.length < IPV6_HEADER_LEN) throw new Error('Packet too short for IPv6')
  const version = (packet[0] >> 4) & 0x0f
  if (version !== VER_IPV6) throw new Error('Expected IPv6 packet')
  const nh = packet[6]
  if (IPV6_EXTENSION_HEADERS.has(nh)) {
    throw new Error('IPv6 extension headers not supported (next header starts an extension chain)')
  }
  const payloadLen = packet.readUInt16BE(4)
  if (packet.length !== IPV6_HEADER_LEN + payloadLen) {
    throw new Error('IPv6 packet length does not match payload length (extensions or padding?)')
  }
}

function fold16 (sum) {
  let s = sum
  while (s >> 16) s = (s & 0xffff) + (s >> 16)
  return (~s) & 0xffff
}

function ipv4HeaderChecksum (header20) {
  let sum = 0
  for (let i = 0; i < IPV4_HEADER_LEN; i += 2) {
    sum += header20.readUInt16BE(i)
  }
  return fold16(sum)
}

function computeIpv4HeaderChecksum (header20) {
  const h = Buffer.from(header20)
  h.writeUInt16BE(0, 10)
  return ipv4HeaderChecksum(h)
}

function sumPseudoHeaderIpv4 (srcIp, dstIp, proto, segmentLen) {
  const ph = Buffer.alloc(12)
  srcIp.copy(ph, 0)
  dstIp.copy(ph, 4)
  ph[8] = 0
  ph[9] = proto
  ph.writeUInt16BE(segmentLen, 10)
  let sum = 0
  for (let i = 0; i < 12; i += 2) sum += ph.readUInt16BE(i)
  return sum
}

/** RFC 2460 / 8200 IPv6 pseudo-header for upper-layer checksum. */
function sumPseudoHeaderIpv6 (srcIp, dstIp, nextHeader, upperLength) {
  const ph = Buffer.alloc(40)
  srcIp.copy(ph, 0)
  dstIp.copy(ph, 16)
  ph.writeUInt32BE(upperLength, 32)
  ph[36] = 0
  ph[37] = 0
  ph[38] = 0
  ph[39] = nextHeader
  let sum = 0
  for (let i = 0; i < 40; i += 2) sum += ph.readUInt16BE(i)
  return sum
}

function recomputeL4ChecksumIpv4 (packet) {
  if (packet.length < IPV4_HEADER_LEN) return
  const proto = packet[9]
  const totalLen = packet.readUInt16BE(2)
  const ipPayloadLen = totalLen - IPV4_HEADER_LEN
  if (ipPayloadLen < 0) return

  if (proto === PROTO_ICMP) {
    if (packet.length < IPV4_HEADER_LEN + 4) return
    packet.writeUInt16BE(0, IPV4_HEADER_LEN + 2)
    let sum = 0
    const icmpEnd = packet.length
    let i = IPV4_HEADER_LEN
    while (i + 1 < icmpEnd) {
      sum += packet.readUInt16BE(i)
      i += 2
    }
    if (i < icmpEnd) sum += packet[i] << 8
    packet.writeUInt16BE(fold16(sum), IPV4_HEADER_LEN + 2)
    return
  }

  if (proto !== PROTO_TCP && proto !== PROTO_UDP) return

  const segmentLen = ipPayloadLen
  if (packet.length < IPV4_HEADER_LEN + segmentLen) return

  const srcIp = packet.subarray(12, 16)
  const dstIp = packet.subarray(16, 20)
  const csumOffset = proto === PROTO_TCP ? 16 : 6

  packet.writeUInt16BE(0, IPV4_HEADER_LEN + csumOffset)

  let sum = sumPseudoHeaderIpv4(srcIp, dstIp, proto, segmentLen)
  const end = IPV4_HEADER_LEN + segmentLen
  let i = IPV4_HEADER_LEN
  while (i + 1 < end) {
    sum += packet.readUInt16BE(i)
    i += 2
  }
  if (i < end) sum += packet[i] << 8
  let csum = fold16(sum)
  if (proto === PROTO_UDP && csum === 0) csum = 0xffff
  packet.writeUInt16BE(csum, IPV4_HEADER_LEN + csumOffset)
}

function recomputeL4ChecksumIpv6 (packet) {
  if (packet.length < IPV6_HEADER_LEN) return
  const nextHeader = packet[6]
  const payloadLen = packet.readUInt16BE(4)
  if (packet.length < IPV6_HEADER_LEN + payloadLen) return

  const srcIp = packet.subarray(8, 24)
  const dstIp = packet.subarray(24, 40)

  if (nextHeader === PROTO_ICMPV6) {
    packet.writeUInt16BE(0, IPV6_HEADER_LEN + 2)
    let sum = sumPseudoHeaderIpv6(srcIp, dstIp, PROTO_ICMPV6, payloadLen)
    let i = IPV6_HEADER_LEN
    while (i + 1 < packet.length) {
      sum += packet.readUInt16BE(i)
      i += 2
    }
    if (i < packet.length) sum += packet[i] << 8
    packet.writeUInt16BE(fold16(sum), IPV6_HEADER_LEN + 2)
    return
  }

  if (nextHeader !== PROTO_TCP && nextHeader !== PROTO_UDP) return

  const segmentLen = payloadLen
  const csumOffset = nextHeader === PROTO_TCP ? 16 : 6
  packet.writeUInt16BE(0, IPV6_HEADER_LEN + csumOffset)

  let sum = sumPseudoHeaderIpv6(srcIp, dstIp, nextHeader, segmentLen)
  const end = IPV6_HEADER_LEN + segmentLen
  let i = IPV6_HEADER_LEN
  while (i + 1 < end) {
    sum += packet.readUInt16BE(i)
    i += 2
  }
  if (i < end) sum += packet[i] << 8
  let csum = fold16(sum)
  if (nextHeader === PROTO_UDP && csum === 0) csum = 0xffff
  packet.writeUInt16BE(csum, IPV6_HEADER_LEN + csumOffset)
}

/** Strip `/prefix` from a CIDR string (IPv4 or IPv6). */
function stripHostFromCidr (cidr) {
  const i = cidr.indexOf('/')
  return i === -1 ? cidr : cidr.slice(0, i)
}

/**
 * Before IPv4 key-address encode, ensure source IP is in `ka`. Some stacks (notably macOS) inject
 * packets on the TUN with source set to a LAN address instead of the mesh TUN IP; rewrite src to
 * `localTunIpStr` and fix IPv4 + L4 checksums.
 *
 * @param {Buffer} packet
 * @param {ReturnType<typeof createKeyAddressTable>} ka
 * @param {string} localTunIpStr — mesh host IP (e.g. 10.0.2.1)
 */
function coerceIpv4SourceForMeshEncode (packet, ka, localTunIpStr) {
  const v = (packet[0] >> 4) & 0x0f
  if (v !== 4 || packet.length < IPV4_HEADER_LEN) return packet
  const src = `${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}`
  try {
    ka.ipToKey(src)
    return packet
  } catch {
    const out = Buffer.from(packet)
    const octets = localTunIpStr.split('.').map(Number)
    out[12] = octets[0]
    out[13] = octets[1]
    out[14] = octets[2]
    out[15] = octets[3]
    out.writeUInt16BE(0, 10)
    out.writeUInt16BE(computeIpv4HeaderChecksum(out.subarray(0, IPV4_HEADER_LEN)), 10)
    recomputeL4ChecksumIpv4(out)
    return out
  }
}

/**
 * After length framing: IPv4 payloads are key-address wire bytes; IPv6 passes through raw.
 * `ka` null disables translation (e.g. authenticated server mode).
 */
function wrapTunnelPayload (ka, ipPacket) {
  if (!ka) return ipPacket
  const v = (ipPacket[0] >> 4) & 0x0f
  if (v === VER_IPV6) return ipPacket
  if (v === VER_IPV4) return ka.encode(ipPacket)
  return ipPacket
}

/**
 * @returns {Buffer|null} Decoded IPv4 packet, raw passthrough for non–key-address payloads, or null if
 *   IPv4 decode failed (e.g. src/dst key no longer registered after a peer disconnected — stale
 *   frames can still arrive on another connection).
 */
function unwrapTunnelPayload (ka, framedPayload) {
  if (!ka) return framedPayload
  if (!framedPayload || framedPayload.length < 1) return null
  const v = (framedPayload[0] >> 4) & 0x0f
  if (v === VER_IPV6) return framedPayload
  if (v === VER_IPV4) {
    try {
      return ka.decode(framedPayload)
    } catch {
      return null
    }
  }
  return framedPayload
}

module.exports = {
  createKeyAddressTable,
  KEY_LEN,
  IPV4_HEADER_LEN,
  IPV4_PREFIX_LEN,
  WIRE_IPV4_KEY_HEADER_LEN,
  /** @deprecated use WIRE_IPV4_KEY_HEADER_LEN */
  WIRE_KEY_HEADER_LEN: WIRE_IPV4_KEY_HEADER_LEN,
  IPV6_HEADER_LEN,
  IPV6_PREFIX_LEN,
  WIRE_IPV6_KEY_HEADER_LEN,
  computeIpv4HeaderChecksum,
  stripHostFromCidr,
  coerceIpv4SourceForMeshEncode,
  wrapTunnelPayload,
  unwrapTunnelPayload
}
