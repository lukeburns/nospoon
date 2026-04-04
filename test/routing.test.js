'use strict'

const test = require('node:test')
const assert = require('node:assert')
const HyperDHT = require('hyperdht')
const { createKeyAddressTable } = require('../lib/key-address')
const { shouldHairpinToLocalStack } = require('../lib/routing')

test('shouldHairpinToLocalStack is true for local mesh IP via ka', () => {
  const kp = HyperDHT.keyPair()
  const ka = createKeyAddressTable({ localKey: kp.publicKey, localIp: '10.0.0.1' })
  const ctx = { localKey: kp.publicKey, ka }
  assert.strictEqual(shouldHairpinToLocalStack('10.0.0.1', ctx), true)
  assert.strictEqual(shouldHairpinToLocalStack('10.0.0.2', ctx), false)
})

test('shouldHairpinToLocalStack without ka uses localMeshIpv4', () => {
  const kp = HyperDHT.keyPair()
  const ctx = { localKey: kp.publicKey, ka: null, localMeshIpv4: '10.0.0.1' }
  assert.strictEqual(shouldHairpinToLocalStack('10.0.0.1', ctx), true)
  assert.strictEqual(shouldHairpinToLocalStack('10.0.0.2', ctx), false)
})
