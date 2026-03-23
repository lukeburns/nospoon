const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  isDirectoryFrame,
  encodeHubDirectory,
  decodeHubDirectory
} = require('../lib/hub-directory')

describe('hub-directory', function () {
  it('round-trips peer key list', function () {
    const keys = [
      'aa'.repeat(32),
      'bb'.repeat(32)
    ]
    const buf = encodeHubDirectory(keys)
    assert.ok(isDirectoryFrame(buf))
    const json = decodeHubDirectory(buf)
    assert.equal(json.v, 1)
    assert.equal(json.peers.length, 2)
    assert.equal(json.peers[0].k, 'aa'.repeat(32))
    assert.equal(json.peers[1].k, 'bb'.repeat(32))
  })

  it('rejects tunnel-like IPv4 first byte', function () {
    const tunLike = Buffer.alloc(40)
    tunLike[0] = 0x45
    assert.ok(!isDirectoryFrame(tunLike))
  })
})
