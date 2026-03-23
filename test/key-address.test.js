const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  createKeyAddressTable,
  computeIpv4HeaderChecksum,
  IPV4_HEADER_LEN
} = require('../lib/key-address')

const PROTO_ICMP = 1
const PROTO_TCP = 6
const PROTO_UDP = 17

const keyA = Buffer.alloc(32, 0x01)
const keyB = Buffer.alloc(32, 0x02)

function fold16 (sum) {
  let s = sum
  while (s >> 16) s = (s & 0xffff) + (s >> 16)
  return (~s) & 0xffff
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
    assert.equal(wire.length, packet.length - 8 + 64)
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

  it('encode fails when IP is not registered', function () {
    const packet = ipv4Packet({
      src: Buffer.from([10, 0, 0, 1]),
      dst: Buffer.from([10, 0, 0, 3]),
      proto: PROTO_UDP,
      payload: udpPayload({ sport: 1, dport: 2 })
    })
    const table = createKeyAddressTable({ localIp: '10.0.0.1', localKey: keyA })
    table.register('10.0.0.2', keyB)
    assert.throws(function () {
      table.encode(packet)
    }, /No key registered/)
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
})
