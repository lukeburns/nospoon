'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  apply,
  restore,
  isActive,
  mergeResolvConfBackupWithDnsServers
} = require('../lib/dns-system-override-linux')

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

  it('mergeResolvConfBackupWithDnsServers replaces nameserver lines', function () {
    const backup =
      'nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch lan\noptions edns0\n'
    const out = mergeResolvConfBackupWithDnsServers(backup, ['1.1.1.1'])
    assert.ok(out.includes('nameserver 1.1.1.1'))
    assert.ok(!out.includes('8.8.8.8'))
    assert.ok(out.includes('search lan'))
    assert.ok(out.includes('options edns0'))
  })

  it('mergeResolvConfBackupWithDnsServers prepends when no nameserver lines', function () {
    const backup = 'search foo\n'
    const out = mergeResolvConfBackupWithDnsServers(backup, ['9.9.9.9'])
    assert.match(out, /^nameserver 9\.9\.9\.9\n/)
    assert.ok(out.includes('search foo'))
  })

  it('mergeResolvConfBackupWithDnsServers writes multiple nameserver lines', function () {
    const backup = 'nameserver 8.8.8.8\nsearch x\n'
    const out = mergeResolvConfBackupWithDnsServers(backup, ['1.1.1.1', '9.9.9.9'])
    assert.ok(out.includes('nameserver 1.1.1.1'))
    assert.ok(out.includes('nameserver 9.9.9.9'))
    assert.ok(!out.includes('8.8.8.8'))
    assert.ok(out.includes('search x'))
  })
})
