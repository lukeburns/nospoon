const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { parse32Bytes, toHex32, encodeZ32 } = require('../lib/key-encoding')
const z32 = require('z32')

describe('key-encoding', function () {
  const buf = Buffer.alloc(32, 0xab)

  it('round-trips hex', function () {
    const hex = buf.toString('hex')
    assert.deepEqual(parse32Bytes(hex, 't'), buf)
  })

  it('round-trips z32', function () {
    const s = z32.encode(buf)
    assert.deepEqual(parse32Bytes(s, 't'), buf)
  })

  it('toHex32 / encodeZ32', function () {
    assert.equal(toHex32(buf), buf.toString('hex'))
    assert.equal(encodeZ32(buf), z32.encode(buf))
  })
})
