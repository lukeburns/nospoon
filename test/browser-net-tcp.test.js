'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const {
  parseIpv4Tcp,
  buildIpv4TcpPacket,
  ipv4HeaderChecksum,
  FLAG_SYN,
  FLAG_ACK,
  FLAG_PSH
} = require('../lib/browser-net-tcp')

test('parseIpv4Tcp round-trips header fields', function () {
  const pkt = buildIpv4TcpPacket({
    srcIp: '10.0.0.2',
    dstIp: '10.0.0.1',
    srcPort: 49152,
    dstPort: 8080,
    seq: 0x1000,
    ack: 0x2000,
    flags: FLAG_SYN | FLAG_ACK,
    payload: Buffer.from('hello')
  })
  const p = parseIpv4Tcp(pkt)
  assert.ok(p)
  assert.equal(p.srcIp, '10.0.0.2')
  assert.equal(p.dstIp, '10.0.0.1')
  assert.equal(p.srcPort, 49152)
  assert.equal(p.dstPort, 8080)
  assert.equal(p.seq, 0x1000)
  assert.equal(p.ack, 0x2000)
  assert.equal(p.payload.toString(), 'hello')
})

test('IPv4 header checksum is valid for built packet', function () {
  const pkt = buildIpv4TcpPacket({
    srcIp: '192.168.1.1',
    dstIp: '192.168.1.2',
    srcPort: 1,
    dstPort: 2,
    seq: 1,
    ack: 2,
    flags: FLAG_PSH | FLAG_ACK,
    payload: Buffer.alloc(0)
  })
  const stored = pkt.readUInt16BE(10)
  pkt.writeUInt16BE(0, 10)
  const calc = ipv4HeaderChecksum(pkt, 0, 20)
  assert.equal(calc, stored)
})
