'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { apply, restore, isActive } = require('../lib/dns-system-override-darwin')

describe('dns-system-override-darwin', function () {
  it('non-darwin: apply is a no-op and does not throw', function () {
    if (process.platform === 'darwin') {
      return
    }
    const r = apply({ port: 53, address: '127.0.0.1' })
    assert.equal(r.applied, false)
    assert.equal(isActive(), false)
    restore()
    assert.equal(isActive(), false)
  })

  it('darwin: skips when port is not 53', function () {
    if (process.platform !== 'darwin') {
      return
    }
    const r = apply({ port: 5353, address: '127.0.0.1' })
    assert.equal(r.applied, false)
    assert.ok(r.message && r.message.includes('53'))
    restore()
  })

  it('darwin: skips when bind address is not loopback-wide', function () {
    if (process.platform !== 'darwin') {
      return
    }
    const r = apply({ port: 53, address: '10.0.0.1' })
    assert.equal(r.applied, false)
    assert.ok(r.message && r.message.includes('127.0.0.1'))
    restore()
  })
})
