const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { swarmDiscoveryKey, normalizeTopicBytes } = require('../lib/mesh/swarm-mesh')

describe('swarm-mesh', function () {
  it('swarmDiscoveryKey is 32-byte blake2b over domain + topic', function () {
    const k = swarmDiscoveryKey('hello')
    assert.equal(k.length, 32)
    const k2 = swarmDiscoveryKey('hello')
    assert.ok(k.equals(k2))
    assert.ok(!k.equals(swarmDiscoveryKey('goodbye')))
    assert.ok(k.equals(swarmDiscoveryKey(normalizeTopicBytes('hello'))))
  })
})
