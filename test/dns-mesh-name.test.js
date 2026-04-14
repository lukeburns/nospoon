'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  parseMeshDnsName,
  normalizeFqdn,
  formatMeshTopicDnsName
} = require('../lib/dns/dns-mesh-name')
const { encodeZ32 } = require('../lib/wire/key-encoding')
const crypto = require('crypto')
const HyperDHT = require('hyperdht')

describe('dns-mesh-name', function () {
  it('normalizeFqdn lowercases and strips trailing dot', function () {
    assert.equal(normalizeFqdn('Foo.BAR.'), 'foo.bar')
  })

  it('parseMeshDnsName single label z32 key', function () {
    const kp = HyperDHT.keyPair(crypto.randomBytes(32))
    const hex = kp.publicKey.toString('hex')
    const label = encodeZ32(kp.publicKey)
    const m = parseMeshDnsName(label)
    assert.ok(m)
    assert.equal(m.kind, 'key')
    assert.equal(m.keyHex, hex)
  })

  it('parseMeshDnsName key.topicRef', function () {
    const kp = HyperDHT.keyPair(crypto.randomBytes(32))
    const hex = kp.publicKey.toString('hex')
    const label = encodeZ32(kp.publicKey)
    const m = parseMeshDnsName(`${label}.mytopic`)
    assert.ok(m)
    assert.equal(m.kind, 'keyTopic')
    assert.equal(m.keyHex, hex)
    assert.equal(m.topicRef, 'mytopic')
  })

  it('formatMeshTopicDnsName round-trips label', function () {
    const kp = HyperDHT.keyPair(crypto.randomBytes(32))
    const hex = kp.publicKey.toString('hex')
    const fq = formatMeshTopicDnsName(hex, 'secret')
    const m = parseMeshDnsName(fq)
    assert.ok(m)
    assert.equal(m.topicRef, 'secret')
  })
})
