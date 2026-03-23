const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { topicKeyFromString } = require('../lib/swarm-mesh')

describe('swarm-mesh', function () {
  it('topicKeyFromString is 32-byte sha256', function () {
    const k = topicKeyFromString('hello')
    assert.equal(k.length, 32)
    const k2 = topicKeyFromString('hello')
    assert.ok(k.equals(k2))
    assert.ok(!k.equals(topicKeyFromString('goodbye')))
  })
})
