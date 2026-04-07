const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  isHeliaMeshAnnounceFrame,
  encodeHeliaMeshAnnounce,
  tryDecodeHeliaMeshAnnounce
} = require('../lib/ipfs-mesh-announce')

describe('ipfs-mesh-announce', function () {
  const samplePeer =
    '12D3KooWBmLLnPiCoEog4iefNQP7JJgdZJNQKKchxk7rEzHHVb5'

  it('round-trips peerId and port', function () {
    const buf = encodeHeliaMeshAnnounce({ peerId: samplePeer, port: 4011 })
    assert.ok(isHeliaMeshAnnounceFrame(buf))
    const ann = tryDecodeHeliaMeshAnnounce(buf)
    assert.ok(ann)
    assert.equal(ann.peerId, samplePeer)
    assert.equal(ann.port, 4011)
  })

  it('defaults port to 4011 when omitted in JSON', function () {
    const buf = encodeHeliaMeshAnnounce({ peerId: samplePeer })
    const ann = tryDecodeHeliaMeshAnnounce(buf)
    assert.ok(ann)
    assert.equal(ann.port, 4011)
  })

  it('rejects tunnel-like IPv4 first byte', function () {
    const tunLike = Buffer.alloc(40)
    tunLike[0] = 0x45
    assert.ok(!isHeliaMeshAnnounceFrame(tunLike))
  })
})
