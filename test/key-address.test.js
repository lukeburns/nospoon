const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  createKeyAddressTable,
  computeIpv4HeaderChecksum,
  coerceIpv4SourceForMeshEncode,
  endpointPublicId,
  IPV4_HEADER_LEN,
  IPV4_PREFIX_LEN,
  IPV4_WIRE_FLAG_DST_KEYED,
  IPV4_WIRE_FLAG_SRC_KEYED,
  IPV6_HEADER_LEN,
  unwrapTunnelPayload,
  wrapTunnelPayload
} = require('../lib/mesh/key-address')

const PROTO_ICMP = 1
const PROTO_TCP = 6
const PROTO_UDP = 17
const PROTO_ICMPV6 = 58

const keyA = Buffer.alloc(32, 0x01)
const keyB = Buffer.alloc(32, 0x02)

function fold16 (sum) {
  let s = sum
  while (s >> 16) s = (s & 0xffff) + (s >> 16)
  return (~s) & 0xffff
}

/** fd00::1 / fd00::2 as 16-byte buffers */
const fd00_1 = Buffer.from('fd000000000000000000000000000001', 'hex')
const fd00_2 = Buffer.from('fd000000000000000000000000000002', 'hex')

function ipv6Packet ({ src, dst, nextHeader, payload }) {
  if (payload.length > 65535) throw new Error('payload too long')
  const h = Buffer.allocUnsafe(IPV6_HEADER_LEN)
  h.writeUInt32BE(0x60000000, 0)
  h.writeUInt16BE(payload.length, 4)
  h[6] = nextHeader
  h[7] = 64
  src.copy(h, 8)
  dst.copy(h, 24)
  return Buffer.concat([h, payload])
}

function udp6Payload ({ sport, dport, data, srcIp, dstIp }) {
  const udpLen = 8 + data.length
  const u = Buffer.allocUnsafe(udpLen)
  u.writeUInt16BE(sport, 0)
  u.writeUInt16BE(dport, 2)
  u.writeUInt16BE(udpLen, 4)
  u.writeUInt16BE(0, 6)
  data.copy(u, 8)
  const ph = Buffer.alloc(40)
  srcIp.copy(ph, 0)
  dstIp.copy(ph, 16)
  ph.writeUInt32BE(udpLen, 32)
  ph[36] = 0
  ph[37] = 0
  ph[38] = 0
  ph[39] = PROTO_UDP
  let sum = 0
  for (let i = 0; i < 40; i += 2) sum += ph.readUInt16BE(i)
  let i = 0
  while (i + 1 < udpLen) {
    sum += u.readUInt16BE(i)
    i += 2
  }
  if (i < udpLen) sum += u[i] << 8
  let c = fold16(sum)
  if (c === 0) c = 0xffff
  u.writeUInt16BE(c, 6)
  return u
}

function ipv4Packet ({ src, dst, proto, payload }) {
  const totalLen = IPV4_HEADER_LEN + payload.length
  const h = Buffer.allocUnsafe(IPV4_HEADER_LEN)
  h[0] = 0x45
  h.writeUInt16BE(totalLen, 2)
  h.writeUInt16BE(0xabcd, 4)
  h[8] = 64
  h[9] = proto
  h.writeUInt16BE(0, 10)
  src.copy(h, 12)
  dst.copy(h, 16)
  h.writeUInt16BE(computeIpv4HeaderChecksum(h), 10)
  return Buffer.concat([h, payload])
}

function udpPayload ({ sport, dport, data = Buffer.alloc(0) }) {
  const udpLen = 8 + data.length
  const u = Buffer.allocUnsafe(udpLen)
  u.writeUInt16BE(sport, 0)
  u.writeUInt16BE(dport, 2)
  u.writeUInt16BE(udpLen, 4)
  u.writeUInt16BE(0, 6)
  data.copy(u, 8)
  const src = Buffer.from([10, 0, 0, 1])
  const dst = Buffer.from([10, 0, 0, 2])
  let sum = 0
  const ph = Buffer.alloc(12)
  src.copy(ph, 0)
  dst.copy(ph, 4)
  ph[8] = 0
  ph[9] = PROTO_UDP
  ph.writeUInt16BE(udpLen, 10)
  for (let i = 0; i < 12; i += 2) sum += ph.readUInt16BE(i)
  let i = 0
  while (i + 1 < udpLen) {
    sum += u.readUInt16BE(i)
    i += 2
  }
  if (i < udpLen) sum += u[i] << 8
  let c = fold16(sum)
  if (c === 0) c = 0xffff
  u.writeUInt16BE(c, 6)
  return u
}

describe('key-address', function () {
  it('endpointPublicId scopes the same Ed25519 key by topic preimage', function () {
    const pk = Buffer.alloc(32, 7)
    const a = endpointPublicId(pk, Buffer.from('topic-a', 'utf8'))
    const b = endpointPublicId(pk, Buffer.from('topic-b', 'utf8'))
    const direct = endpointPublicId(pk, Buffer.alloc(0))
    assert.notDeepEqual(a, b)
    assert.notDeepEqual(a, direct)
  })

  it('round-trips IPv4 + UDP with keys and valid checksums', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const udp = udpPayload({ sport: 4000, dport: 5000, data: Buffer.from('ping') })
    const packet = ipv4Packet({ src, dst, proto: PROTO_UDP, payload: udp })

    const table = createKeyAddressTable({
      localIp: '10.0.0.1',
      localKey: keyA
    })
    table.register('10.0.0.2', keyB)

    const wire = table.encode(packet)
    assert.equal(wire.length, packet.length + IPV4_PREFIX_LEN + 1 + 64 - IPV4_HEADER_LEN)
    assert.equal(wire[IPV4_PREFIX_LEN], IPV4_WIRE_FLAG_SRC_KEYED | IPV4_WIRE_FLAG_DST_KEYED)
    assert.equal(wire.readUInt32BE(0) >>> 0, packet.readUInt32BE(0) >>> 0)

    const back = table.decode(wire)
    assert.equal(back.length, packet.length)
    assert.deepEqual(back, packet)
  })

  it('round-trips minimal TCP segment', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const tcp = Buffer.alloc(20)
    tcp.writeUInt16BE(44000, 0)
    tcp.writeUInt16BE(80, 2)
    tcp.writeUInt32BE(1, 4)
    tcp.writeUInt32BE(0, 8)
    tcp.writeUInt16BE(0x5000, 12)
    tcp.writeUInt16BE(0, 16)
    tcp.writeUInt16BE(0, 18)

    const ph = Buffer.alloc(12)
    src.copy(ph, 0)
    dst.copy(ph, 4)
    ph[8] = 0
    ph[9] = PROTO_TCP
    ph.writeUInt16BE(20, 10)
    let sum = 0
    for (let i = 0; i < 12; i += 2) sum += ph.readUInt16BE(i)
    for (let i = 0; i < 20; i += 2) sum += tcp.readUInt16BE(i)
    let c = fold16(sum)
    tcp.writeUInt16BE(c, 16)

    const packet = ipv4Packet({ src, dst, proto: PROTO_TCP, payload: tcp })

    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)

    const back = table.decode(table.encode(packet))
    assert.deepEqual(back, packet)
  })

  it('round-trips ICMP echo', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const icmp = Buffer.alloc(8)
    icmp[0] = 8
    icmp[1] = 0
    icmp.writeUInt16BE(0, 2)
    icmp.writeUInt16BE(1, 4)
    icmp.writeUInt16BE(0, 6)
    let sum = 0
    for (let i = 0; i < 8; i += 2) sum += icmp.readUInt16BE(i)
    icmp.writeUInt16BE(fold16(sum), 2)

    const packet = ipv4Packet({ src, dst, proto: PROTO_ICMP, payload: icmp })

    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)

    const back = table.decode(table.encode(packet))
    assert.deepEqual(back, packet)
  })

  it('round-trips IPv4 with literal dst when dst is not an alias (full-tunnel style)', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([8, 8, 8, 8])
    const icmp = Buffer.alloc(8)
    icmp[0] = 8
    icmp[1] = 0
    icmp.writeUInt16BE(0, 2)
    icmp.writeUInt16BE(1, 4)
    icmp.writeUInt16BE(0, 6)
    let sum = 0
    for (let i = 0; i < 8; i += 2) sum += icmp.readUInt16BE(i)
    icmp.writeUInt16BE(fold16(sum), 2)

    const packet = ipv4Packet({ src, dst, proto: PROTO_ICMP, payload: icmp })
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    const wire = table.encode(packet)
    assert.equal(wire[IPV4_PREFIX_LEN], IPV4_WIRE_FLAG_SRC_KEYED)
    assert.deepEqual(table.decode(wire), packet)
  })

  it('decode rejects literal IPv4 in mesh guard CIDR (spoofed alias slot)', function () {
    const prefix = Buffer.alloc(12)
    prefix[0] = 0x45
    prefix.writeUInt16BE(28, 2)
    prefix.writeUInt16BE(0, 4)
    prefix[8] = 64
    prefix[9] = PROTO_ICMP
    prefix.writeUInt16BE(0, 10)
    const wire = Buffer.concat([
      prefix,
      Buffer.from([0]),
      Buffer.from([10, 0, 0, 33]),
      Buffer.from([8, 8, 8, 8]),
      Buffer.alloc(0)
    ])
    const table = createKeyAddressTable({ meshIpv4LiteralGuardCidr: '10.0.0.0/24' })
    assert.throws(function () {
      table.decode(wire)
    }, /literal address in mesh/)
  })

  it('decode allows literals outside mesh guard CIDR', function () {
    const prefix = Buffer.alloc(12)
    prefix[0] = 0x45
    prefix.writeUInt16BE(28, 2)
    prefix.writeUInt16BE(0, 4)
    prefix[8] = 64
    prefix[9] = PROTO_ICMP
    prefix.writeUInt16BE(0, 10)
    const wire = Buffer.concat([
      prefix,
      Buffer.from([0]),
      Buffer.from([8, 8, 8, 8]),
      Buffer.from([1, 1, 1, 1]),
      Buffer.alloc(0)
    ])
    const table = createKeyAddressTable({ meshIpv4LiteralGuardCidr: '10.0.0.0/24' })
    assert.doesNotThrow(function () {
      table.decode(wire)
    })
  })

  it('coerceIpv4SourceForMeshEncode preserves global src (internet reply to mesh peer)', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    const src = Buffer.from([93, 184, 216, 34])
    const dst = Buffer.from([10, 0, 0, 2])
    const icmp = Buffer.alloc(8)
    icmp[0] = 0
    icmp[1] = 0
    icmp.writeUInt16BE(0, 2)
    icmp.writeUInt16BE(0, 4)
    icmp.writeUInt16BE(0, 6)
    const packet = ipv4Packet({ src, dst, proto: PROTO_ICMP, payload: icmp })
    const out = coerceIpv4SourceForMeshEncode(packet, table, '10.0.0.1')
    assert.deepEqual(out.subarray(12, 16), src)
    assert.deepEqual(out.subarray(16, 20), dst)
  })

  it('coerceIpv4SourceForMeshEncode does not throw on runt TCP (short L4)', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    const b = Buffer.alloc(27)
    b[0] = 0x45
    b.writeUInt16BE(27, 2)
    b[8] = 64
    b[9] = PROTO_TCP
    b[12] = 192
    b[13] = 168
    b[14] = 1
    b[15] = 1
    b[16] = 10
    b[17] = 0
    b[18] = 0
    b[19] = 2
    b.writeUInt16BE(computeIpv4HeaderChecksum(b.subarray(0, 20)), 10)
    assert.doesNotThrow(function () {
      coerceIpv4SourceForMeshEncode(b, table, '10.0.0.1')
    })
  })

  it('coerceIpv4SourceForMeshEncode rewrites RFC1918 src when not in ka', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    const src = Buffer.from([192, 168, 1, 99])
    const dst = Buffer.from([10, 0, 0, 2])
    const icmp = Buffer.alloc(8)
    icmp[0] = 0
    icmp[1] = 0
    icmp.writeUInt16BE(0, 2)
    icmp.writeUInt16BE(0, 4)
    icmp.writeUInt16BE(0, 6)
    const packet = ipv4Packet({ src, dst, proto: PROTO_ICMP, payload: icmp })
    const out = coerceIpv4SourceForMeshEncode(packet, table, '10.0.0.1')
    assert.deepEqual(out.subarray(12, 16), Buffer.from([10, 0, 0, 1]))
  })

  it('mesh keyed aliases round-trip with meshLiteralGuard set', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const udp = udpPayload({ sport: 1, dport: 2, data: Buffer.alloc(0) })
    const packet = ipv4Packet({ src, dst, proto: PROTO_UDP, payload: udp })
    const table = createKeyAddressTable({
      localIp: '10.0.0.1',
      localKey: keyA,
      meshIpv4LiteralGuardCidr: '10.0.0.0/24'
    })
    table.register('10.0.0.2', keyB)
    assert.deepEqual(table.decode(table.encode(packet)), packet)
  })

  it('round-trips IPv6 + UDP with keys and valid checksums', function () {
    const udp = udp6Payload({
      sport: 52000,
      dport: 53000,
      data: Buffer.from('v6'),
      srcIp: fd00_1,
      dstIp: fd00_2
    })
    const packet = ipv6Packet({
      src: fd00_1,
      dst: fd00_2,
      nextHeader: PROTO_UDP,
      payload: udp
    })

    const table = createKeyAddressTable({
      localIp: 'fd00::1',
      localKey: keyA
    })
    table.register('fd00::2', keyB)

    const back = table.decode(table.encode(packet))
    assert.deepEqual(back, packet)
  })

  it('round-trips IPv6 TCP and ICMPv6 echo', function () {
    const tcp = Buffer.alloc(20)
    tcp.writeUInt16BE(44000, 0)
    tcp.writeUInt16BE(80, 2)
    tcp.writeUInt32BE(2, 4)
    tcp.writeUInt32BE(0, 8)
    tcp.writeUInt16BE(0x5000, 12)
    tcp.writeUInt16BE(0, 16)
    tcp.writeUInt16BE(0, 18)

    const ph = Buffer.alloc(40)
    fd00_1.copy(ph, 0)
    fd00_2.copy(ph, 16)
    ph.writeUInt32BE(20, 32)
    ph[39] = PROTO_TCP
    let sum = 0
    for (let i = 0; i < 40; i += 2) sum += ph.readUInt16BE(i)
    for (let i = 0; i < 20; i += 2) sum += tcp.readUInt16BE(i)
    tcp.writeUInt16BE(fold16(sum), 16)

    const pktTcp = ipv6Packet({
      src: fd00_1,
      dst: fd00_2,
      nextHeader: PROTO_TCP,
      payload: tcp
    })

    const table = createKeyAddressTable({ localIp: 'fd00::1', localKey: keyA })
    table.register('fd00::2', keyB)
    assert.deepEqual(table.decode(table.encode(pktTcp)), pktTcp)

    const icmp6 = Buffer.alloc(8)
    icmp6[0] = 128
    icmp6[1] = 0
    icmp6.writeUInt16BE(0, 2)
    icmp6.writeUInt16BE(1, 4)
    icmp6.writeUInt16BE(0, 6)
    const phI = Buffer.alloc(40)
    fd00_1.copy(phI, 0)
    fd00_2.copy(phI, 16)
    phI.writeUInt32BE(8, 32)
    phI[39] = PROTO_ICMPV6
    sum = 0
    for (let i = 0; i < 40; i += 2) sum += phI.readUInt16BE(i)
    for (let i = 0; i < 8; i += 2) sum += icmp6.readUInt16BE(i)
    icmp6.writeUInt16BE(fold16(sum), 2)

    const pktIcmp = ipv6Packet({
      src: fd00_1,
      dst: fd00_2,
      nextHeader: PROTO_ICMPV6,
      payload: icmp6
    })
    assert.deepEqual(table.decode(table.encode(pktIcmp)), pktIcmp)
  })

  it('allows multiple IPs for the same key (contextual aliases)', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    table.register('10.0.0.3', keyB)
    assert.deepEqual(table.ipToKey(Buffer.from([10, 0, 0, 2])), keyB)
    assert.deepEqual(table.ipToKey(Buffer.from([10, 0, 0, 3])), keyB)
    // decode uses first registered alias for that key
    assert.equal(table.keyToIp(keyB).join('.'), '10.0.0.2')
  })

  it('unwrapTunnelPayload returns null after peer unregistered (stale frames)', function () {
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const udp = udpPayload({ sport: 1, dport: 2, data: Buffer.alloc(0) })
    const packet = ipv4Packet({ src, dst, proto: PROTO_UDP, payload: udp })
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    const wire = table.encode(packet)
    table.unregister('10.0.0.2')
    assert.equal(unwrapTunnelPayload(table, wire), null)
  })

  it('unwrapTunnelPayload returns null for non-IP first nibble (in-band control)', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    const controlLike = Buffer.from([0x00, 0x03, 0x7b, 0x7d])
    assert.equal(unwrapTunnelPayload(table, controlLike), null)
  })

  it('unregister removes peer mapping so the same IP can be reused', function () {
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    table.unregister('10.0.0.2')
    table.register('10.0.0.2', keyB)
    const src = Buffer.from([10, 0, 0, 1])
    const dst = Buffer.from([10, 0, 0, 2])
    const udp = udpPayload({ sport: 1, dport: 2, data: Buffer.alloc(0) })
    const packet = ipv4Packet({ src, dst, proto: PROTO_UDP, payload: udp })
    assert.doesNotThrow(function () { table.encode(packet) })
  })

  it('localMeshId registers topic-scoped identity for local TUN address', function () {
    const bHex = keyB.toString('hex')
    const localMesh = { kind: 'keyTopic', keyHex: keyA.toString('hex'), topicId: 'tid-1' }
    const table = createKeyAddressTable({
      localIp: '10.0.0.1',
      localKey: keyA,
      localMeshId: localMesh
    })
    assert.deepEqual(table.meshIdentifierForIp('10.0.0.1'), {
      kind: 'keyTopic',
      keyHex: keyA.toString('hex'),
      topicId: 'tid-1'
    })
    table.register('10.0.0.2', keyB, { kind: 'keyTopic', keyHex: bHex, topicId: 'tid-1' })
    assert.equal(table.ipForMeshIdentifier({ kind: 'keyTopic', keyHex: bHex, topicId: 'tid-1' }), '10.0.0.2')
  })

  it('meshIdentifierForIp / ipForMeshIdentifier optional mesh metadata', function () {
    const bHex = keyB.toString('hex')
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    const meshKey = { kind: 'key', keyHex: bHex }
    const meshTopic = { kind: 'keyTopic', keyHex: bHex, topicId: 'topic-uuid' }
    table.register('10.0.0.2', keyB, meshKey)
    table.register('10.0.0.3', keyB, meshTopic)
    assert.deepEqual(table.meshIdentifierForIp('10.0.0.2'), { kind: 'key', keyHex: bHex })
    assert.deepEqual(table.meshIdentifierForIp('10.0.0.3'), { kind: 'keyTopic', keyHex: bHex, topicId: 'topic-uuid' })
    assert.equal(table.ipForMeshIdentifier(meshKey), '10.0.0.2')
    assert.equal(table.ipForMeshIdentifier(meshTopic), '10.0.0.3')
    table.unregister('10.0.0.2')
    assert.equal(table.ipForMeshIdentifier(meshKey), null)
  })
})
