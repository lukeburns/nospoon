'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const dgram = require('dgram')
const dns = require('dns-packet')
const { createDnsServer } = require('../lib/dns-server')
const { encodeKeyLabel } = require('../lib/dns-mesh-name')

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

  it('manual A overrides mesh A for the same name', async function () {
    const z32Label = encodeKeyLabel('11'.repeat(32))
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: (name) =>
        name === z32Label ? { ipv4: '127.0.0.1' } : null,
      resolveMeshA: () => '10.99.0.7',
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0xabcd,
      questions: [{ type: 'A', name: z32Label }]
    })

    assert.equal(res.rcode, 'NOERROR')
    assert.equal(res.answers.length, 1)
    assert.equal(res.answers[0].type, 'A')
    assert.equal(res.answers[0].data, '127.0.0.1')

    await server.stop()
  })

  it('CID-shaped hostname: A uses resolveCidGatewayA', async function () {
    const cidLabel = 'b' + 'y'.repeat(51)
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: () => null,
      resolveMeshA: () => null,
      resolveCidGatewayA: () => '10.8.0.1',
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0x1111,
      questions: [{ type: 'A', name: cidLabel }]
    })

    assert.equal(res.rcode, 'NOERROR')
    assert.equal(res.answers.length, 1)
    assert.equal(res.answers[0].type, 'A')
    assert.equal(res.answers[0].data, '10.8.0.1')

    await server.stop()
  })

  it('CID-shaped hostname: AAAA returns NODATA', async function () {
    const cidLabel = 'b' + 'z'.repeat(51)
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: () => null,
      resolveMeshA: () => null,
      resolveCidGatewayA: () => '10.8.0.2',
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0x2222,
      questions: [{ type: 'AAAA', name: cidLabel }]
    })

    assert.equal(res.rcode, 'NOERROR')
    assert.equal(res.answers.length, 0)

    await server.stop()
  })

  it('mesh key.topic: A with no mesh IP returns NODATA (NOERROR), not NXDOMAIN', async function () {
    const z32Label = encodeKeyLabel('33'.repeat(32))
    const name = `${z32Label}.spoon`
    const port = await findFreePort()
    const server = createDnsServer({
      port,
      lookupManual: () => null,
      resolveMeshA: () => null,
      forward: false
    })
    await server.start()

    const res = await queryDns(port, {
      type: 'query',
      id: 0x3333,
      questions: [{ type: 'A', name }]
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
