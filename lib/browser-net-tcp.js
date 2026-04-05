'use strict'

/**
 * Minimal IPv4 + TCP parse/build for {@link ./browser-net-proxy.js} (no IP options, no TCP options).
 */

const IPV4_PROTO_TCP = 6

/** @param {Buffer} b */
function ipv4HeaderChecksum (b, ipOff, ipLen) {
  let sum = 0
  for (let i = 0; i < ipLen; i += 2) {
    sum += b.readUInt16BE(ipOff + i)
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16)
  return (~sum) & 0xffff
}

/**
 * @param {Buffer} ipPacket — full IPv4 datagram
 * @param {number} ipOff
 * @param {number} ipLen — total IP length
 * @param {number} tcpOff
 * @param {number} tcpLen — TCP segment length (header + payload)
 */
function tcpChecksum (ipPacket, ipOff, ipLen, tcpOff, tcpLen) {
  const src = ipPacket.subarray(ipOff + 12, ipOff + 16)
  const dst = ipPacket.subarray(ipOff + 16, ipOff + 20)
  let sum = 0
  sum += src.readUInt16BE(0)
  sum += src.readUInt16BE(2)
  sum += dst.readUInt16BE(0)
  sum += dst.readUInt16BE(2)
  sum += IPV4_PROTO_TCP + tcpLen
  for (let i = 0; i < tcpLen; i += 2) {
    if (i + 1 < tcpLen) {
      sum += ipPacket.readUInt16BE(tcpOff + i)
    } else {
      sum += (ipPacket[tcpOff + i] << 8) & 0xff00
    }
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16)
  return (~sum) & 0xffff
}

/**
 * @param {Buffer} packet — unwrapped inner IPv4 packet
 * @returns {null | {
 *   srcIp: string,
 *   dstIp: string,
 *   srcPort: number,
 *   dstPort: number,
 *   seq: number,
 *   ack: number,
 *   flags: number,
 *   window: number,
 *   ipHeaderLen: number,
 *   tcpHeaderLen: number,
 *   payload: Buffer
 * }}
 */
function parseIpv4Tcp (packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 40) return null
  const ver = (packet[0] >>> 4) & 0x0f
  if (ver !== 4) return null
  const ihl = (packet[0] & 0x0f) * 4
  if (ihl < 20 || packet.length < ihl + 20) return null
  if (packet[9] !== IPV4_PROTO_TCP) return null
  const totalLen = packet.readUInt16BE(2)
  if (totalLen > packet.length || totalLen < ihl + 20) return null
  const srcIp = `${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}`
  const dstIp = `${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}`
  const tcpOff = ihl
  const srcPort = packet.readUInt16BE(tcpOff)
  const dstPort = packet.readUInt16BE(tcpOff + 2)
  const seq = packet.readUInt32BE(tcpOff + 4) >>> 0
  const ack = packet.readUInt32BE(tcpOff + 8) >>> 0
  const dataOffWords = (packet[tcpOff + 12] >>> 4) & 0x0f
  const tcpHeaderLen = dataOffWords * 4
  if (tcpHeaderLen < 20 || totalLen < ihl + tcpHeaderLen) return null
  const flags = packet[tcpOff + 13]
  const window = packet.readUInt16BE(tcpOff + 14)
  const payloadLen = totalLen - ihl - tcpHeaderLen
  const payload =
    payloadLen > 0
      ? packet.subarray(ihl + tcpHeaderLen, ihl + tcpHeaderLen + payloadLen)
      : Buffer.alloc(0)
  return {
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    seq,
    ack,
    flags,
    window,
    ipHeaderLen: ihl,
    tcpHeaderLen,
    payload
  }
}

const FLAG_FIN = 0x01
const FLAG_SYN = 0x02
const FLAG_RST = 0x04
const FLAG_PSH = 0x08
const FLAG_ACK = 0x10

/**
 * Build IPv4 TCP reply (20+20 byte headers, optional payload).
 * @param {object} p
 * @param {string} p.srcIp
 * @param {string} p.dstIp
 * @param {number} p.srcPort
 * @param {number} p.dstPort
 * @param {number} p.seq
 * @param {number} p.ack
 * @param {number} p.flags
 * @param {Buffer} [p.payload]
 */
function buildIpv4TcpPacket (p) {
  const payload = p.payload && p.payload.length ? p.payload : Buffer.alloc(0)
  const ipHeaderLen = 20
  const tcpHeaderLen = 20
  const totalLen = ipHeaderLen + tcpHeaderLen + payload.length
  const buf = Buffer.allocUnsafe(totalLen)

  buf[0] = 0x45
  buf[1] = 0
  buf.writeUInt16BE(totalLen, 2)
  buf.writeUInt16BE(Math.floor(Math.random() * 0xffff) || 1, 4)
  buf.writeUInt16BE(0x4000, 6)
  buf[8] = 64
  buf[9] = IPV4_PROTO_TCP
  buf.writeUInt16BE(0, 10)
  writeIpv4(buf, 12, p.srcIp)
  writeIpv4(buf, 16, p.dstIp)
  buf.writeUInt16BE(ipv4HeaderChecksum(buf, 0, ipHeaderLen), 10)

  const t = ipHeaderLen
  buf.writeUInt16BE(p.srcPort & 0xffff, t)
  buf.writeUInt16BE(p.dstPort & 0xffff, t + 2)
  buf.writeUInt32BE(p.seq >>> 0, t + 4)
  buf.writeUInt32BE(p.ack >>> 0, t + 8)
  buf[t + 12] = (5 << 4) & 0xff
  buf[t + 13] = p.flags & 0xff
  buf.writeUInt16BE(0xffff, t + 14)
  buf.writeUInt16BE(0, t + 18)

  const csumTcp = tcpChecksum(buf, 0, ipHeaderLen, t, tcpHeaderLen + payload.length)
  buf.writeUInt16BE(csumTcp, t + 16)

  if (payload.length) payload.copy(buf, t + tcpHeaderLen)
  return buf
}

/** @param {Buffer} buf @param {number} off @param {string} ip */
function writeIpv4 (buf, off, ip) {
  const parts = String(ip).split('.')
  for (let i = 0; i < 4; i++) {
    buf[off + i] = Number(parts[i]) & 0xff
  }
}

module.exports = {
  parseIpv4Tcp,
  buildIpv4TcpPacket,
  FLAG_FIN,
  FLAG_SYN,
  FLAG_RST,
  FLAG_PSH,
  FLAG_ACK,
  ipv4HeaderChecksum,
  tcpChecksum
}
