const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  swarmTopicCapability,
  timingSafeEqual
} = require('../lib/mesh/swarm-topic')

describe('swarm-topic', function () {
  it('each side verifies the remote role namespace (hypercore-style)', function () {
    const topic = Buffer.from('shared-secret-topic', 'utf8')
    const handshakeHash = Buffer.alloc(32, 7)

    const initiatorSends = swarmTopicCapability(true, topic, handshakeHash)
    // Responder is !isInitiator → expects swarmTopicCapability(true, …) from initiator
    const responderExpectsFromInitiator = swarmTopicCapability(!false, topic, handshakeHash)
    assert.ok(timingSafeEqual(initiatorSends, responderExpectsFromInitiator))

    const responderSends = swarmTopicCapability(false, topic, handshakeHash)
    // Initiator is isInitiator → expects swarmTopicCapability(false, …) from responder
    const initiatorExpectsFromResponder = swarmTopicCapability(!true, topic, handshakeHash)
    assert.ok(timingSafeEqual(responderSends, initiatorExpectsFromResponder))
  })

  it('wrong topic preimage does not verify', function () {
    const handshakeHash = Buffer.alloc(32, 3)
    const a = swarmTopicCapability(true, Buffer.from('a'), handshakeHash)
    const b = swarmTopicCapability(false, Buffer.from('b'), handshakeHash)
    assert.ok(!timingSafeEqual(a, b))
  })
})
