'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { apply, restore, isActive } = require('../lib/dns-system-override')

describe('dns-system-override (facade)', function () {
  it('does not activate when port is not 53 (any platform)', function () {
    const r = apply({ port: 5353, address: '127.0.0.1' })
    assert.equal(r.applied, false)
    assert.equal(isActive(), false)
    restore()
  })
})
