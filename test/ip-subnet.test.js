const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  pickFreeTenDotZeroSubnet,
  createPeerIpAllocator,
  allocateLowestAvailableIpv4,
  ipv4ContainedInCidr
} = require('../lib/ip-subnet')

describe('ip-subnet auto range', function () {
  it('pickFreeTenDotZeroSubnet skips assigned hosts', function () {
    const assigned = new Set(['10.0.0.1', '10.0.1.1'])
    const p = pickFreeTenDotZeroSubnet(assigned)
    assert.equal(p.cidr, '10.0.2.1/24')
    assert.equal(p.peerAlias, '10.0.2.2')
  })

  it('pickFreeTenDotZeroSubnet returns first octet when empty', function () {
    const p = pickFreeTenDotZeroSubnet(new Set())
    assert.equal(p.cidr, '10.0.0.1/24')
    assert.equal(p.peerAlias, '10.0.0.2')
  })

  it('allocateLowestAvailableIpv4 skips CIDR host and used set', function () {
    const ip = allocateLowestAvailableIpv4('10.0.0.1/24', new Set(['10.0.0.1']))
    assert.equal(ip, '10.0.0.2')
  })

  it('peer allocator claim takes a specific address', function () {
    const a = createPeerIpAllocator('10.0.0.1/24', {
      initialUsed: new Set(['10.0.0.1'])
    })
    const ip = a.claim('10.0.0.5')
    assert.equal(ip, '10.0.0.5')
    assert.throws(function () {
      a.claim('10.0.0.5')
    })
  })

  it('ipv4ContainedInCidr', function () {
    assert.equal(ipv4ContainedInCidr('10.0.5.9', '10.0.5.1/24'), true)
    assert.equal(ipv4ContainedInCidr('10.0.6.1', '10.0.5.1/24'), false)
  })
})
