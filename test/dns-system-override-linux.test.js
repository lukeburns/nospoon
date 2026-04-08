'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { apply, restore, isActive } = require('../lib/dns-system-override-linux')

describe('dns-system-override-linux', function () {
  it('non-linux: apply is a no-op', function () {
    if (process.platform === 'linux') {
      return
    }
    const r = apply({ port: 53, address: '127.0.0.1' })
    assert.equal(r.applied, false)
    assert.equal(isActive(), false)
    restore()
  })

  it('linux: skips when port is not 53', function () {
    if (process.platform !== 'linux') {
      return
    }
    const r = apply({ port: 5353, address: '127.0.0.1' })
    assert.equal(r.applied, false)
    assert.ok(r.message && r.message.includes('53'))
    restore()
  })
})
