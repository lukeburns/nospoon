'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const {
  mergeSessionDnsWithPreApply,
  parseNameserversFromResolvBackup
} = require('../lib/dns/dns-restore-merge')

describe('dns-restore-merge', function () {
  it('puts session upstream first and appends pre-apply fallbacks', function () {
    const m = mergeSessionDnsWithPreApply(
      ['1.1.1.1'],
      ['8.8.8.8', '8.8.4.4']
    )
    assert.deepEqual(m, ['1.1.1.1', '8.8.8.8', '8.8.4.4'])
  })

  it('dedupes against session address', function () {
    const m = mergeSessionDnsWithPreApply(['1.1.1.1'], ['1.1.1.1', '9.9.9.9'])
    assert.deepEqual(m, ['1.1.1.1', '9.9.9.9'])
  })

  it('drops loopback from pre-apply list', function () {
    const m = mergeSessionDnsWithPreApply(['1.1.1.1'], ['127.0.0.1', '8.8.8.8'])
    assert.deepEqual(m, ['1.1.1.1', '8.8.8.8'])
  })

  it('parseNameserversFromResolvBackup reads lines', function () {
    const ns = parseNameserversFromResolvBackup(
      'nameserver 1.1.1.1\nsearch lan\nnameserver 8.8.8.8\n'
    )
    assert.deepEqual(ns, ['1.1.1.1', '8.8.8.8'])
  })
})
