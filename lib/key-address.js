/**
 * Key ↔ local IPv4 / IPv6 alias translation for tunnel payloads.
 *
 * Wire format — IPv4 (20-byte header, no options):
 *   [ IPv4 bytes 0–11 ][ flags ][ src slot ][ dst slot ][ IP payload ]
 *   flags (byte 12): bit0 = src is 32-byte endpoint id; bit1 = ditto for dst; bits2–7 reserved (0).
 *   Each slot is either KEY_LEN bytes (alias IP registered in table) or 4 bytes (literal IPv4).
 *   Header length: 21 (both literal) … 77 (both keyed).
 *   If `setMeshIpv4LiteralGuardCidr` was called, decode rejects any **literal**
 *   slot whose IPv4 lies in that CIDR — aliases must use keyed slots so peers cannot impersonate mesh
 *   addresses with raw literals.
 *
 * Wire format — IPv6 (40-byte base header, no extension headers):
 *   [ IPv6 bytes 0–7 ][ 32-byte src endpoint id ][ 32-byte dst endpoint id ][ IP payload ]
 *   Fixed prefix: 72 bytes (WIRE_IPV6_KEY_HEADER_LEN).
 *
 * Endpoint id = BLAKE2b( domain, ed25519_public_key, topic_bytes ). Empty `topic_bytes` matches
 * direct / hub client–server mode (`MeshIdentifier` kind `key`). Topic meshes pass the same topic
 * preimage as {@link ./swarm-topic.js} (UTF-8 string or raw bytes).
 *
 * Decode picks IPv4 vs IPv6 from the first nibble of byte 0 (4 vs 6).
 *
 * Checksums: IPv4 header checksum + L4; IPv6 has no header checksum; TCP/UDP/ICMPv6 use
 * IPv6 pseudo-header for L4. See module body for details.
 *
 * Routing still resolves destination IP → peer Ed25519 public key; `ipToKey` returns the pubkey.
 * Multiple aliases per same (pubkey, topic): ip→endpoint unique per IP; inverse wire→ip keeps the
 * first registered alias per endpoint id (same as pre-endpoint multi-alias behavior).
 */

const net = require('net')
const hc = require('hypercore-crypto')
const { meshIdentifierStorageKey } = require('./mesh-identifier')
const { normalizeTopicBytes } = require('./swarm-topic')
const { parseSubnet } = require('./ip-subnet')

/** Domain separation for endpoint ids (distinct from DHT discovery keys in swarm-topic). */
const ENDPOINT_ID_DOMAIN = Buffer.from('nospoon/key-address-endpoint', 'utf8')

const EMPTY_TOPIC_BYTES = Buffer.alloc(0)

/**
 * @param {Buffer} publicKey — 32-byte Ed25519 public key
 * @param {Buffer} [topicBytes] — topic preimage; omit or empty buffer for direct / kind `key`
 * @returns {Buffer} 32-byte wire endpoint id
 */
function endpointPublicId (publicKey, topicBytes) {
  if (!Buffer.isBuffer(publicKey) || publicKey.length !== KEY_LEN) {
    throw new Error('endpointPublicId: publicKey must be a 32-byte Buffer')
  }
  const t =
    topicBytes == null
      ? EMPTY_TOPIC_BYTES
      : Buffer.isBuffer(topicBytes)
        ? topicBytes
        : normalizeTopicBytes(topicBytes)
  return hc.hash([ENDPOINT_ID_DOMAIN, publicKey, t])
}

/**
 * Topic preimage for wire endpoint id from a {@link import('./mesh-identifier').MeshIdentifier}.
 * @param {import('./mesh-identifier').MeshIdentifier} meshId
 */
function topicBytesForMesh (meshId) {
  if (meshId.kind === 'key') return EMPTY_TOPIC_BYTES
  if (meshId.kind === 'keyTopic') {
    if (meshId.topicBytes != null) {
      if (!Buffer.isBuffer(meshId.topicBytes)) throw new Error('topicBytes must be a Buffer')
      return Buffer.from(meshId.topicBytes)
    }
    return normalizeTopicBytes(meshId.topicId)
  }
  throw new Error(`unknown MeshIdentifier kind: ${meshId.kind}`)
}

function meshLabelForStorage (meshId) {
  if (meshId.kind === 'key') {
    return Object.freeze({ kind: 'key', keyHex: normalizeKeyHexForMesh(meshId.keyHex) })
  }
  return Object.freeze({
    kind: 'keyTopic',
    keyHex: normalizeKeyHexForMesh(meshId.keyHex),
    topicId: String(meshId.topicId).trim()
  })
}

/** Next-header values that start extension headers (not upper-layer directly). */
const IPV6_EXTENSION_HEADERS = new Set([0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254])

const KEY_LEN = 32
const IPV4_HEADER_LEN = 20
const IPV4_PREFIX_LEN = 12

/** bit set → src/dst on wire is a registered alias (endpoint id), else literal IPv4 */
const IPV4_WIRE_FLAG_SRC_KEYED = 0x01
const IPV4_WIRE_FLAG_DST_KEYED = 0x02
const IPV4_WIRE_FLAG_MASK = IPV4_WIRE_FLAG_SRC_KEYED | IPV4_WIRE_FLAG_DST_KEYED

const IPV4_WIRE_HEADER_LEN_MIN = IPV4_PREFIX_LEN + 1 + 4 + 4
const IPV4_WIRE_HEADER_LEN_MAX = IPV4_PREFIX_LEN + 1 + KEY_LEN + KEY_LEN

/** @deprecated use {@link IPV4_WIRE_HEADER_LEN_MAX} (both-alias path is longest header) */
const WIRE_IPV4_KEY_HEADER_LEN = IPV4_WIRE_HEADER_LEN_MAX

function ipv4WireHeaderLen (flags) {
  const srcLen = (flags & IPV4_WIRE_FLAG_SRC_KEYED) ? KEY_LEN : 4
  const dstLen = (flags & IPV4_WIRE_FLAG_DST_KEYED) ? KEY_LEN : 4
  return IPV4_PREFIX_LEN + 1 + srcLen + dstLen
}

const IPV6_HEADER_LEN = 40
const IPV6_PREFIX_LEN = 8
const WIRE_IPV6_KEY_HEADER_LEN = IPV6_PREFIX_LEN + KEY_LEN + KEY_LEN

const PROTO_ICMP = 1
const PROTO_TCP = 6
const PROTO_UDP = 17
const PROTO_ICMPV6 = 58

const VER_IPV4 = 4
const VER_IPV6 = 6

/**
 * @param {object} [opts]
 * @param {string} [opts.localIp]
 * @param {Buffer} [opts.localKey]
 * @param {import('./mesh-identifier').MeshIdentifier} [opts.localMeshId] — e.g. `{ kind: 'keyTopic', keyHex, topicId, topicBytes? }` for topic TUN local address
 * @param {string} [opts.meshIpv4LiteralGuardCidr] — same as calling `setMeshIpv4LiteralGuardCidr` after construct
 */
function createKeyAddressTable (opts = {}) {
  const ipToPubKey = new Map()
  /** @type {Map<string, Buffer>} ip string → 32-byte endpoint id */
  const ipToEndpointId = new Map()
  const endpointHexToIp = new Map()
  /** @type {Map<string, import('./mesh-identifier').MeshIdentifier>} */
  const ipToMeshId = new Map()
  /** @type {Map<string, string>} storageKey -> IPv4/IPv6 string */
  const meshIdToIp = new Map()

  /** @type {{ network: number, mask: number } | null} */
  let meshIpv4LiteralGuard = null

  function setMeshIpv4LiteralGuardCidr (cidr) {
    if (cidr == null || String(cidr).trim() === '') {
      meshIpv4LiteralGuard = null
      return
    }
    const { network, mask } = parseSubnet(String(cidr).trim())
    meshIpv4LiteralGuard = { network: network >>> 0, mask: mask >>> 0 }
  }

  if (opts.meshIpv4LiteralGuardCidr != null) {
    setMeshIpv4LiteralGuardCidr(opts.meshIpv4LiteralGuardCidr)
  }

  function rejectLiteralIpv4InMeshCidr (buf4) {
    if (!meshIpv4LiteralGuard || !buf4 || buf4.length < 4) return
    const x = buf4.readUInt32BE(0) >>> 0
    const { network, mask } = meshIpv4LiteralGuard
    if ((x & mask) === (network & mask)) {
      throw new Error(
        'IPv4 wire: literal address in mesh alias CIDR (use a keyed endpoint slot)'
      )
    }
  }

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

  /**
   * @param {string|Buffer} ip
   * @param {string|Buffer} key — 32-byte Ed25519 public key
   * @param {import('./mesh-identifier').MeshIdentifier} [meshId] — defaults to kind `key` for this pubkey; optional label for DNS / routing
   */
  function register (ip, key, meshId) {
    const ipStr = normalizeIp(ip)
    const k = toKeyBuffer(key)
    const hex = k.toString('hex')
    if (meshId != null) {
      if (meshId.kind === 'key' && normalizeKeyHexForMesh(meshId.keyHex) !== hex) {
        throw new Error('meshId.keyHex must match register key')
      }
      if (meshId.kind === 'keyTopic' && normalizeKeyHexForMesh(meshId.keyHex) !== hex) {
        throw new Error('meshId.keyHex must match register key')
      }
    }

    const midForWire = meshId != null ? meshId : { kind: 'key', keyHex: hex }
    const eid = endpointPublicId(k, topicBytesForMesh(midForWire))
    const eHex = eid.toString('hex')

    if (ipToPubKey.has(ipStr) && ipToPubKey.get(ipStr).toString('hex') !== hex) {
      throw new Error(`IP ${ipStr} already mapped to a different key`)
    }
    ipToPubKey.set(ipStr, k)
    ipToEndpointId.set(ipStr, eid)
    if (!endpointHexToIp.has(eHex)) endpointHexToIp.set(eHex, ipStr)

    if (meshId != null) {
      const sk = meshIdentifierStorageKey(meshId)
      if (meshIdToIp.has(sk) && meshIdToIp.get(sk) !== ipStr) {
        throw new Error(`MeshIdentifier ${sk} already mapped to a different IP`)
      }
      const existingMesh = ipToMeshId.get(ipStr)
      if (existingMesh && meshIdentifierStorageKey(existingMesh) !== sk) {
        throw new Error(`IP ${ipStr} already has a different MeshIdentifier`)
      }
      ipToMeshId.set(ipStr, meshLabelForStorage(meshId))
      meshIdToIp.set(sk, ipStr)
    }
  }

  /** Remove a peer mapping (e.g. on disconnect). Does not remove localIp/localKey. */
  function unregister (ip) {
    const ipStr = normalizeIp(ip)
    const mesh = ipToMeshId.get(ipStr)
    if (mesh) {
      meshIdToIp.delete(meshIdentifierStorageKey(mesh))
      ipToMeshId.delete(ipStr)
    }
    const eid = ipToEndpointId.get(ipStr)
    if (!eid) return
    const eHex = eid.toString('hex')
    ipToPubKey.delete(ipStr)
    ipToEndpointId.delete(ipStr)
    if (endpointHexToIp.get(eHex) === ipStr) {
      endpointHexToIp.delete(eHex)
    }
  }

  /** @returns {import('./mesh-identifier').MeshIdentifier | null} */
  function meshIdentifierForIp (ip) {
    const ipStr = normalizeIp(ip)
    const m = ipToMeshId.get(ipStr)
    return m || null
  }

  /** @returns {string | null} IP string */
  function ipForMeshIdentifier (meshId) {
    const sk = meshIdentifierStorageKey(meshId)
    return meshIdToIp.has(sk) ? meshIdToIp.get(sk) : null
  }

  if (opts.localIp != null && opts.localKey != null) {
    register(opts.localIp, opts.localKey, opts.localMeshId != null ? opts.localMeshId : undefined)
  }

  function ipToKey (ip) {
    const ipStr = normalizeIp(ip)
    const k = ipToPubKey.get(ipStr)
    if (!k) throw new Error(`No key registered for IP ${ipStr}`)
    return k
  }

  function ipToWireEndpoint (ip) {
    const ipStr = normalizeIp(ip)
    const e = ipToEndpointId.get(ipStr)
    if (!e) throw new Error(`No key registered for IP ${ipStr}`)
    return e
  }

  /** Resolve a 32-byte wire endpoint id (from framing) to tunnel IP buffer. */
  function endpointIdToIp (wireId) {
    const k = toKeyBuffer(wireId)
    const ipStr = endpointHexToIp.get(k.toString('hex'))
    if (!ipStr) {
      throw new Error(`No IP registered for wire endpoint ${k.toString('hex').slice(0, 16)}...`)
    }
    return ipStringToBuffer(ipStr)
  }

  /**
   * For a 32-byte Ed25519 public key, resolve the IP registered for its direct (empty-topic)
   * endpoint id (first alias if multiple IPs share that endpoint).
   */
  function keyToIp (key) {
    const k = toKeyBuffer(key)
    return endpointIdToIp(endpointPublicId(k, EMPTY_TOPIC_BYTES))
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
    const srcBuf = packet.subarray(12, 16)
    const dstBuf = packet.subarray(16, 20)
    const srcKey = ipToEndpointId.has(normalizeIp(srcBuf))
    const dstKey = ipToEndpointId.has(normalizeIp(dstBuf))
    let flags = 0
    if (srcKey) flags |= IPV4_WIRE_FLAG_SRC_KEYED
    if (dstKey) flags |= IPV4_WIRE_FLAG_DST_KEYED
    const prefix = Buffer.from(packet.subarray(0, IPV4_PREFIX_LEN))
    prefix.writeUInt16BE(0, 10)
    const srcWire = srcKey ? ipToWireEndpoint(srcBuf) : Buffer.from(srcBuf)
    const dstWire = dstKey ? ipToWireEndpoint(dstBuf) : Buffer.from(dstBuf)
    return Buffer.concat([
      prefix,
      Buffer.from([flags]),
      srcWire,
      dstWire,
      packet.subarray(IPV4_HEADER_LEN)
    ])
  }

  function encodeIpv6 (packet) {
    assertIpv6BaseOnly(packet)
    const srcE = ipToWireEndpoint(packet.subarray(8, 24))
    const dstE = ipToWireEndpoint(packet.subarray(24, 40))
    const prefix = Buffer.from(packet.subarray(0, IPV6_PREFIX_LEN))
    return Buffer.concat([prefix, srcE, dstE, packet.subarray(IPV6_HEADER_LEN)])
  }

  function decodeIpv4 (buf) {
    if (buf.length < IPV4_WIRE_HEADER_LEN_MIN) {
      throw new Error(`Buffer too short for IPv4 wire frame (need >= ${IPV4_WIRE_HEADER_LEN_MIN})`)
    }
    const flags = buf[IPV4_PREFIX_LEN]
    if ((flags & ~IPV4_WIRE_FLAG_MASK) !== 0) {
      throw new Error(`IPv4 wire frame: reserved flag bits must be zero (got ${flags})`)
    }
    const headerEnd = ipv4WireHeaderLen(flags)
    if (buf.length < headerEnd) {
      throw new Error(`Buffer too short: IPv4 wire header needs ${headerEnd} bytes`)
    }
    let off = IPV4_PREFIX_LEN + 1
    let srcIp
    if (flags & IPV4_WIRE_FLAG_SRC_KEYED) {
      srcIp = endpointIdToIp(buf.subarray(off, off + KEY_LEN))
      off += KEY_LEN
    } else {
      srcIp = Buffer.from(buf.subarray(off, off + 4))
      rejectLiteralIpv4InMeshCidr(srcIp)
      off += 4
    }
    let dstIp
    if (flags & IPV4_WIRE_FLAG_DST_KEYED) {
      dstIp = endpointIdToIp(buf.subarray(off, off + KEY_LEN))
      off += KEY_LEN
    } else {
      dstIp = Buffer.from(buf.subarray(off, off + 4))
      rejectLiteralIpv4InMeshCidr(dstIp)
      off += 4
    }
    const rest = buf.subarray(off)
    if (off !== headerEnd) throw new Error('IPv4 wire decode: internal length mismatch')

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
    const srcIp = endpointIdToIp(buf.subarray(IPV6_PREFIX_LEN, IPV6_PREFIX_LEN + KEY_LEN))
    const dstIp = endpointIdToIp(buf.subarray(IPV6_PREFIX_LEN + KEY_LEN, WIRE_IPV6_KEY_HEADER_LEN))
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

  return {
    register,
    unregister,
    ipToKey,
    ipToWireEndpoint,
    endpointIdToIp,
    keyToIp,
    encode,
    decode,
    meshIdentifierForIp,
    ipForMeshIdentifier,
    setMeshIpv4LiteralGuardCidr
  }
}

function normalizeKeyHexForMesh (k) {
  return String(k).trim().toLowerCase()
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
 * IPv4 datagram whose header length field matches the buffer (full-tunnel / arbitrary dst, not wire format).
 */
function looksLikeRawIpv4Datagram (buf) {
  if (buf.length < IPV4_HEADER_LEN) return false
  try {
    assertIpv4NoOptions(buf)
  } catch {
    return false
  }
  const totalLen = buf.readUInt16BE(2)
  return totalLen === buf.length && totalLen >= IPV4_HEADER_LEN
}

/**
 * After length framing: IPv4 uses extended key-address wire (alias slots keyed, literals passthrough).
 * IPv6 passes through raw. `ka` null disables translation (e.g. authenticated server mode).
 */
function wrapTunnelPayload (ka, ipPacket) {
  if (!ka) return ipPacket
  const v = (ipPacket[0] >> 4) & 0x0f
  if (v === VER_IPV6) return ipPacket
  if (v === VER_IPV4) return ka.encode(ipPacket)
  return ipPacket
}

/**
 * @returns {Buffer|null} Decoded IPv4 wire frame; or raw IPv4 datagram if the buffer is a full
 *   datagram (not wire); null if corrupt. IPv6 passes through raw.
 */
function unwrapTunnelPayload (ka, framedPayload) {
  if (!ka) return framedPayload
  if (!framedPayload || framedPayload.length < 1) return null
  const v = (framedPayload[0] >> 4) & 0x0f
  if (v === VER_IPV6) return framedPayload
  if (v === VER_IPV4) {
    if (framedPayload.length >= IPV4_WIRE_HEADER_LEN_MIN) {
      try {
        return ka.decode(framedPayload)
      } catch (_) {}
    }
    if (looksLikeRawIpv4Datagram(framedPayload)) {
      return Buffer.from(framedPayload)
    }
    return null
  }
  return framedPayload
}

module.exports = {
  createKeyAddressTable,
  endpointPublicId,
  KEY_LEN,
  IPV4_HEADER_LEN,
  IPV4_PREFIX_LEN,
  IPV4_WIRE_FLAG_SRC_KEYED,
  IPV4_WIRE_FLAG_DST_KEYED,
  IPV4_WIRE_HEADER_LEN_MIN,
  IPV4_WIRE_HEADER_LEN_MAX,
  ipv4WireHeaderLen,
  WIRE_IPV4_KEY_HEADER_LEN,
  /** @deprecated use WIRE_IPV4_KEY_HEADER_LEN or IPV4_WIRE_HEADER_LEN_MAX */
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
