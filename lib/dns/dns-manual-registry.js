'use strict'

const net = require('net')
const { normalizeFqdn } = require('./dns-mesh-name')

/**
 * @typedef {{ kind: 'literal', ipv4?: string, ipv6?: string }} ManualLiteral
 * @typedef {{ kind: 'mesh', meshId: { kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string } }} ManualMesh
 * @typedef {{ kind: 'alias', target: string }} ManualAlias
 * @typedef {ManualLiteral | ManualMesh | ManualAlias} ManualEntry
 */

class DnsManualRegistry {
  constructor () {
    /** @type {Map<string, ManualEntry>} */
    this._map = new Map()
  }

  /**
   * @param {unknown} v
   * @returns {ManualEntry}
   */
  _coerceEntry (v) {
    if (!v || typeof v !== 'object') {
      throw new Error('invalid manual entry')
    }
    const o = /** @type {Record<string, unknown>} */ (v)
    if (o.kind === 'literal') {
      return this._normalizeLiteral({
        ipv4: o.ipv4,
        ipv6: o.ipv6
      })
    }
    if (o.kind === 'mesh') {
      const mid = o.meshId
      if (!mid || typeof mid !== 'object') throw new Error('invalid mesh manual entry')
      const m = /** @type {{ kind?: unknown, keyHex?: unknown, topicRef?: unknown }} */ (mid)
      if (m.kind === 'key' && typeof m.keyHex === 'string') {
        const h = String(m.keyHex).trim().toLowerCase()
        if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('invalid mesh key')
        return { kind: 'mesh', meshId: { kind: 'key', keyHex: h } }
      }
      if (m.kind === 'keyTopic' && typeof m.keyHex === 'string' && typeof m.topicRef === 'string') {
        const h = String(m.keyHex).trim().toLowerCase()
        if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('invalid mesh key')
        const t = String(m.topicRef).trim()
        if (!t || t.indexOf('.') >= 0) throw new Error('invalid topic ref')
        return { kind: 'mesh', meshId: { kind: 'keyTopic', keyHex: h, topicRef: t } }
      }
      throw new Error('invalid mesh manual entry')
    }
    if (o.kind === 'alias' && typeof o.target === 'string' && o.target.trim()) {
      return { kind: 'alias', target: normalizeFqdn(o.target) }
    }
    if (typeof o.ipv4 === 'string' || typeof o.ipv6 === 'string') {
      return this._normalizeLiteral({
        ipv4: o.ipv4,
        ipv6: o.ipv6
      })
    }
    throw new Error('invalid manual entry')
  }

  /**
   * @param {{ ipv4?: unknown, ipv6?: unknown }} rec
   * @returns {ManualLiteral}
   */
  _normalizeLiteral (rec) {
    const o = { kind: /** @type {'literal'} */ ('literal') }
    if (typeof rec.ipv4 === 'string' && rec.ipv4.trim()) {
      const ip = rec.ipv4.trim()
      if (!net.isIPv4(ip)) throw new Error('invalid IPv4')
      o.ipv4 = ip
    }
    if (typeof rec.ipv6 === 'string' && rec.ipv6.trim()) {
      const ip = rec.ipv6.trim()
      if (!net.isIPv6(ip)) throw new Error('invalid IPv6')
      o.ipv6 = ip
    }
    if (!o.ipv4 && !o.ipv6) {
      throw new Error('at least one of ipv4 or ipv6 is required')
    }
    return o
  }

  /**
   * @param {string} hostname
   * @param {ManualEntry | { ipv4?: string, ipv6?: string }} rec
   */
  set (hostname, rec) {
    const n = normalizeFqdn(hostname)
    const e = this._coerceEntry(rec)
    this._map.set(n, e)
  }

  delete (hostname) {
    return this._map.delete(normalizeFqdn(hostname))
  }

  /**
   * Raw stored entry (no resolution), for alias chains.
   * @param {string} hostname
   * @returns {ManualEntry | undefined}
   */
  getRaw (hostname) {
    return this._map.get(normalizeFqdn(hostname))
  }

  /**
   * @param {string} hostname
   * @returns {{ ipv4?: string, ipv6?: string } | null} — literals only; use session resolver for mesh/alias
   */
  lookup (hostname) {
    const e = this.getRaw(hostname)
    if (!e) return null
    if (e.kind === 'literal') {
      const o = {}
      if (e.ipv4) o.ipv4 = e.ipv4
      if (e.ipv6) o.ipv6 = e.ipv6
      return o
    }
    return null
  }

  /**
   * @returns {Array<{ hostname: string, kind: string, ipv4?: string, ipv6?: string, meshId?: object, aliasTarget?: string }>}
   */
  list () {
    const out = []
    for (const [hostname, rec] of this._map) {
      if (rec.kind === 'literal') {
        out.push({
          hostname,
          kind: 'literal',
          ipv4: rec.ipv4,
          ipv6: rec.ipv6
        })
      } else if (rec.kind === 'mesh') {
        out.push({
          hostname,
          kind: 'mesh',
          meshId: rec.meshId
        })
      } else {
        out.push({
          hostname,
          kind: 'alias',
          aliasTarget: rec.target
        })
      }
    }
    out.sort(function (a, b) {
      return a.hostname.localeCompare(b.hostname)
    })
    return out
  }
}

module.exports = { DnsManualRegistry }
