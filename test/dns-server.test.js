'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const dgram = require('dgram')
const dns = require('dns-packet')
const { createDnsServer } = require('../lib/dns-server')

describe('dns-server', function () {
  it('manual IPv4-only: AAAA returns NOERROR with empty answers (NODATA)', async function () {
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: () => ({ ipv4: '10.254.0.1' }),
      resolveMeshA: () => null,
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0xbeef,
      questions: [{ type: 'AAAA', name: 'whois' }]
    })

    assert.equal(res.rcode, 'NOERROR')
    assert.equal(res.answers.length, 0)

    await server.stop()
  })

  it('manual IPv6-only: A returns NOERROR with empty answers (NODATA)', async function () {
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: () => ({ ipv6: '2001:db8::1' }),
      resolveMeshA: () => null,
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0xcafe,
      questions: [{ type: 'A', name: 'only6' }]
    })

    assert.equal(res.rcode, 'NOERROR')
    assert.equal(res.answers.length, 0)

    await server.stop()
  })
})

function findFreePort () {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4')
    s.bind(0, '127.0.0.1', () => {
      const p = s.address().port
      s.close(() => resolve(p))
    })
    s.on('error', reject)
  })
}

function queryDns (port, packet) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    const buf = dns.encode(packet)
    sock.once('message', (msg) => {
      try {
        resolve(dns.decode(msg))
      } catch (e) {
        reject(e)
      } finally {
        sock.close()
      }
    })
    sock.once('error', reject)
    sock.send(buf, port, '127.0.0.1', (err) => {
      if (err) reject(err)
    })
  })
}
