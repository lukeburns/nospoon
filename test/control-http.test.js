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
    assert.equal(s.dns.enabled, false)
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
})
