'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { MeshIpReservationManager } = require('../lib/mesh-ip-reservations')

const KEY_A =
  'a'.repeat(64)
const KEY_B =
  'b'.repeat(64)

describe('MeshIpReservationManager', function () {
  it('reserves primary keys in subnet without collision', function () {
    const m = new MeshIpReservationManager()
    m.setPrimaryCidr('10.0.0.1/24')
    const used = new Set(['10.0.0.1'])
    const ip1 = m.reservePrimaryKey(KEY_A, used)
    const ip2 = m.reservePrimaryKey(KEY_B, used)
    assert.notEqual(ip1, ip2)
    assert.match(ip1, /^10\.0\.0\.\d+$/)
    used.add(ip1)
    used.add(ip2)
    const again = m.reservePrimaryKey(KEY_A, used)
    assert.equal(again, ip1)
  })

  it('consumes primary reservation once', function () {
    const m = new MeshIpReservationManager()
    m.setPrimaryCidr('10.0.0.1/24')
    m.reservePrimaryKey(KEY_A, new Set(['10.0.0.1']))
    const ip = m.consumePrimaryReservation(KEY_A)
    assert.ok(ip)
    assert.equal(m.consumePrimaryReservation(KEY_A), null)
  })

  it('reads primary reservation without consuming', function () {
    const m = new MeshIpReservationManager()
    m.setPrimaryCidr('10.0.0.1/24')
    const reserved = m.reservePrimaryKey(KEY_A, new Set(['10.0.0.1']))
    assert.equal(m.getPrimaryReservedIpv4ForKey(KEY_A), reserved)
    assert.equal(m.getPrimaryReservedIpv4ForKey(KEY_A), reserved)
    assert.equal(m.consumePrimaryReservation(KEY_A), reserved)
    assert.equal(m.getPrimaryReservedIpv4ForKey(KEY_A), null)
  })

  it('reserves topic peers per topic id', function () {
    const m = new MeshIpReservationManager()
    m.setTopicCidr('t1', '10.0.1.1/24')
    const used = new Set(['10.0.1.1'])
    const ip = m.reserveTopicPeer('t1', KEY_A, used)
    assert.match(ip, /^10\.0\.1\.\d+$/)
    const ip2 = m.reserveTopicPeer('t1', KEY_B, used)
    assert.notEqual(ip, ip2)
  })
})
