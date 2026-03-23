/**
 * Key ↔ local IPv4 alias translation for tunnel payloads.
 *
 * Wire format (IPv4 with 20-byte header only; no IP options):
 *   [ IPv4 bytes 0–11 ][ 32-byte src key ][ 32-byte dst key ][ IP payload ]
 * Total fixed prefix: 76 bytes before the original IP payload (everything after byte 20).
 *
 * Checksums:
 * - IPv4 header checksum covers only the 20-byte IPv4 header. The kernel expects a
 *   valid header checksum on packets delivered to a TUN unless you use checksum
 *   offload (platform/driver dependent; not assumed here).
 * - TCP, UDP, and ICMP embed addresses (directly or via a pseudo-header). After
 *   restoring src/dst IPv4 addresses from keys, we recompute those checksums so the
 *   inner packet is valid for the stack.
 *
 * On encode, bytes 10–11 of the copied IPv4 prefix are zeroed; they are not meaningful
 * on the wire because the middle segment is not a valid IPv4 header.
 *
 * Multiple IPv4 aliases may map to the same key (e.g. different discovery contexts).
 * ip→key must still be unique per IP. For decode, key→ip keeps one arbitrary alias per
 * key (first registered wins); any is acceptable for reconstructing valid IPv4 headers.
 */

const KEY_LEN = 32
const IPV4_HEADER_LEN = 20
const IPV4_PREFIX_LEN = 12
const WIRE_KEY_HEADER_LEN = IPV4_PREFIX_LEN + KEY_LEN + KEY_LEN

const PROTO_ICMP = 1
const PROTO_TCP = 6
const PROTO_UDP = 17

function createKeyAddressTable (opts = {}) {
  const ipToKeyMap = new Map()
  const keyHexToIp = new Map()

  function normalizeIp (ip) {
    if (Buffer.isBuffer(ip)) {
      if (ip.length !== 4) throw new Error('IPv4 buffer must be 4 bytes')
      return `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`
    }
    if (typeof ip === 'string') return ip
    throw new Error('IP must be a string or 4-byte Buffer')
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

  /**
   * Replace IPv4 src/dst with 32-byte keys. Only IPv4, IHL=5 (20-byte header), no options.
   */
  function encode (packet) {
    assertIpv4NoOptions(packet)
    const srcKey = ipToKey(packet.subarray(12, 16))
    const dstKey = ipToKey(packet.subarray(16, 20))
    const prefix = Buffer.from(packet.subarray(0, IPV4_PREFIX_LEN))
    prefix.writeUInt16BE(0, 10)
    return Buffer.concat([prefix, srcKey, dstKey, packet.subarray(IPV4_HEADER_LEN)])
  }

  /**
   * Replace keys with local IPv4 aliases and fix checksums for the reconstructed packet.
   */
  function decode (buf) {
    if (buf.length < WIRE_KEY_HEADER_LEN) {
      throw new Error(`Buffer too short for key frame (need >= ${WIRE_KEY_HEADER_LEN})`)
    }
    const srcIp = keyToIp(buf.subarray(IPV4_PREFIX_LEN, IPV4_PREFIX_LEN + KEY_LEN))
    const dstIp = keyToIp(buf.subarray(IPV4_PREFIX_LEN + KEY_LEN, WIRE_KEY_HEADER_LEN))
    const rest = buf.subarray(WIRE_KEY_HEADER_LEN)

    const header = Buffer.allocUnsafe(IPV4_HEADER_LEN)
    buf.copy(header, 0, 0, IPV4_PREFIX_LEN)
    srcIp.copy(header, 12)
    dstIp.copy(header, 16)

    const totalLen = IPV4_HEADER_LEN + rest.length
    header.writeUInt16BE(totalLen, 2)
    header.writeUInt16BE(0, 10)
    header.writeUInt16BE(computeIpv4HeaderChecksum(header), 10)

    const packet = Buffer.concat([header, rest])
    recomputeL4Checksum(packet)
    return packet
  }

  return { register, ipToKey, keyToIp, encode, decode }
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

function ipStringToBuffer (ipStr) {
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
  if (version !== 4) throw new Error('Only IPv4 supported')
  const ihl = (packet[0] & 0x0f) * 4
  if (ihl !== IPV4_HEADER_LEN) {
    throw new Error('IPv4 with options (IHL != 5) not supported')
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

/** Write IPv4 header checksum (expects bytes 10–11 to be zero before calling). */
function computeIpv4HeaderChecksum (header20) {
  const h = Buffer.from(header20)
  h.writeUInt16BE(0, 10)
  return ipv4HeaderChecksum(h)
}

/** Sum of 16-bit words of the 12-byte TCP/UDP pseudo-header (RFC 793 / 768). */
function sumPseudoHeader (srcIp, dstIp, proto, segmentLen) {
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

function recomputeL4Checksum (packet) {
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

  let sum = sumPseudoHeader(srcIp, dstIp, proto, segmentLen)
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

module.exports = {
  createKeyAddressTable,
  KEY_LEN,
  IPV4_HEADER_LEN,
  IPV4_PREFIX_LEN,
  WIRE_KEY_HEADER_LEN,
  computeIpv4HeaderChecksum
}
