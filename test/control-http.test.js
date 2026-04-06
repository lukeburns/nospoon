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
    assert.ok(s.dns.whoisAuth)
    assert.ok(s.dns.ipfsDweb)
    assert.equal(s.dns.ipfsDweb.mode, 'helia')
    assert.equal(s.dns.ipfsDweb.canUpload, false)
    assert.ok(s.dns.ipfsDweb.browserNetDweb)
    assert.equal(s.dns.ipfsDweb.browserNetDweb.listening, false)
    assert.equal(s.dns.ipfsDweb.browserNetDweb.wsPort, 8766)
    assert.equal(s.dns.ipfsDweb.browserNetDweb.dnsHost, 'middle')
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

  it('resolveBrowserNetListenBind keeps z32.spoon as keyTopic (topic TUN), not primary', function () {
    const m = new ControlPlaneSessionManager()
    m._meshIpReservations.setPrimaryCidr('10.0.88.1/24')
    const topicId = '00000000-0000-4000-8000-0000000000cc'
    m._topics.set(topicId, {
      id: topicId,
      topic: 'spoon',
      localTunIp: '10.2.2.1',
      _handle: {},
      _peers: new Map(),
      _ifacePolicy: {},
      _peerPolicies: new Map()
    })
    const hex = m._clientKeyPair.publicKey.toString('hex')
    const { formatMeshTopicDnsName } = require('../lib/dns-mesh-name')
    const wire = formatMeshTopicDnsName(hex, 'spoon')
    assert.equal(m.resolveBrowserNetListenBind(wire), '10.2.2.1')
    assert.notEqual(m.resolveBrowserNetListenBind(wire), '10.0.88.1')
    return m.destroy()
  })

  it('resolveBrowserNetConnectHost passes through IPv4 and resolves mesh DNS', function () {
    const m = new ControlPlaneSessionManager()
    m._meshIpReservations.setPrimaryCidr('10.0.77.1/24')
    const hex = m._clientKeyPair.publicKey.toString('hex')
    assert.equal(m.resolveBrowserNetConnectHost('10.0.77.2'), '10.0.77.2')
    const { formatKeyToDnsName } = require('../lib/dns-mesh-name')
    const name = formatKeyToDnsName(hex)
    assert.equal(m.resolveBrowserNetConnectHost(name), '10.0.77.1')
    assert.equal(m.resolveBrowserNetConnectHost('example.invalid'), null)
    return m.destroy()
  })

  it('getBrowserNetOutboundRoute returns null without an active relay connection', function () {
    const m = new ControlPlaneSessionManager()
    assert.equal(m.getBrowserNetOutboundRoute('10.0.0.5'), null)
    return m.destroy()
  })
})
