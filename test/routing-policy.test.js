'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const rp = require('../lib/route/routing-policy')

describe('routing-policy', function () {
  it('resolvePeerPolicy keeps interface egress when peer only patches ingress', function () {
    const iface = rp.presetPolicy('relay')
    const peer = rp.accumulatePeerPatch(null, {
      ingress: { fullTunnel: true }
    })
    const r = rp.resolvePeerPolicy(iface, peer)
    assert.equal(r.egress.relay, true)
    assert.equal(r.ingress.fullTunnel, true)
  })

  it('accumulatePeerPatch merges sides without wiping the other', function () {
    let p = rp.accumulatePeerPatch(null, { ingress: { relay: true } })
    p = rp.accumulatePeerPatch(p, { egress: { fullTunnel: true } })
    assert.equal(p.ingress.relay, true)
    assert.equal(p.egress.fullTunnel, true)
  })
})
