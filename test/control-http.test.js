'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { ControlPlaneSessionManager } = require('../lib/control-http')

describe('control-http', function () {
  it('ControlPlaneSessionManager exposes stable client z32 before any sessions', function () {
    const m = new ControlPlaneSessionManager()
    const s = m.getStatus()
    assert.equal(typeof s.clientPublicKeyZ32, 'string')
    assert.ok(s.clientPublicKeyZ32.length > 8)
    assert.deepEqual(s.topics, [])
    assert.equal(s.directPool, null)
    assert.deepEqual(s.directPeers, [])
    assert.equal(s.primaryCidrOverride, null)
    assert.ok(s.meshReservations)
    assert.equal(s.meshReservations.primaryCidr, null)
    assert.deepEqual(s.meshReservations.primary, [])
    assert.ok(s.dns)
    assert.equal(s.dns.enabled, true)
    assert.equal(s.dns.listening, false)
    return m.destroy()
  })

  it('accepts primaryCidr override in constructor', function () {
    const m = new ControlPlaneSessionManager({
      primaryCidr: '10.0.99.1/24'
    })
    assert.equal(m.getStatus().primaryCidrOverride, '10.0.99.1/24')
    return m.destroy()
  })

  it('whois returns null for unknown addresses and rejects bad keys', function () {
    const m = new ControlPlaneSessionManager()
    assert.equal(m.whoisIp(''), null)
    assert.equal(m.whoisIp('not-an-ip'), null)
    assert.equal(m.whoisIp('10.0.0.99'), null)
    assert.throws(function () {
      m.whoisKey('nope', null)
    })
    return m.destroy()
  })

  it('dnsResolveMeshIpv4 resolves the local key to primary TUN host using reserved primary CIDR', function () {
    const m = new ControlPlaneSessionManager()
    m._meshIpReservations.setPrimaryCidr('10.0.77.1/24')
    const hex = m._clientKeyPair.publicKey.toString('hex')
    assert.equal(m.dnsResolveMeshIpv4({ kind: 'key', keyHex: hex }), '10.0.77.1')
    return m.destroy()
  })

  it('dnsResolveMeshIpv4 resolves local keyTopic to topic row localTunIp', function () {
    const m = new ControlPlaneSessionManager()
    const id = '00000000-0000-4000-8000-0000000000aa'
    m._topics.set(id, {
      id,
      topic: 't',
      localTunIp: '10.1.2.3',
      _handle: {},
      _peers: new Map(),
      _ifacePolicy: {},
      _peerPolicies: new Map()
    })
    const hex = m._clientKeyPair.publicKey.toString('hex')
    assert.equal(
      m.dnsResolveMeshIpv4({ kind: 'keyTopic', keyHex: hex, topicRef: id }),
      '10.1.2.3'
    )
    return m.destroy()
  })
})
