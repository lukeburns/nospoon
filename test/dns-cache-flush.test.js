'use strict'

const { describe, it } = require('node:test')
const { flushSystemDnsCache } = require('../lib/dns-cache-flush')

describe('dns-cache-flush', function () {
  it('flushSystemDnsCache does not throw', function () {
    flushSystemDnsCache()
  })
})
