const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { pickFreeTenDotZeroSubnet } = require('../lib/ip-subnet')

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
})
