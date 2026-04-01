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
    return m.destroy()
  })
})
