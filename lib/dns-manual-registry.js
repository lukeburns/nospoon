'use strict'

const net = require('net')
const { normalizeFqdn } = require('./dns-mesh-name')

/**
 * Static hostname → A / AAAA for the mesh DNS server (arbitrary FQDNs, not z32 mesh labels).
 */
class DnsManualRegistry {
  constructor () {
    /** @type {Map<string, { ipv4?: string, ipv6?: string }>} */
    this._map = new Map()
  }

  /**
   * @param {unknown} v
   * @returns {{ ipv4?: string, ipv6?: string }}
   */
  _normalizeEntry (v) {
    if (!v || typeof v !== 'object') return {}
    const o = {}
    if (typeof v.ipv4 === 'string' && v.ipv4.trim()) {
      if (!net.isIPv4(v.ipv4.trim())) throw new Error('invalid IPv4')
      o.ipv4 = v.ipv4.trim()
    }
    if (typeof v.ipv6 === 'string' && v.ipv6.trim()) {
      if (!net.isIPv6(v.ipv6.trim())) throw new Error('invalid IPv6')
      o.ipv6 = v.ipv6.trim()
    }
    return o
  }

  /**
   * @param {string} hostname
   * @param {{ ipv4?: string, ipv6?: string }} rec
   */
  set (hostname, rec) {
    const n = normalizeFqdn(hostname)
    const e = this._normalizeEntry(rec)
    if (!e.ipv4 && !e.ipv6) {
      throw new Error('at least one of ipv4 or ipv6 is required')
    }
    this._map.set(n, e)
  }

  delete (hostname) {
    return this._map.delete(normalizeFqdn(hostname))
  }

  /** @returns {{ ipv4?: string, ipv6?: string } | null} */
  lookup (hostname) {
    return this._map.get(normalizeFqdn(hostname)) || null
  }

  /** @returns {string | null} hostname whose ipv4 matches, or null */
  reverseLookupIpv4 (ip) {
    const target = String(ip || '').trim()
    if (!target) return null
    for (const [hostname, rec] of this._map) {
      if (rec.ipv4 === target) return hostname
    }
    return null
  }

  /** @returns {Array<{ hostname: string, ipv4?: string, ipv6?: string }>} */
  list () {
    const out = []
    for (const [hostname, rec] of this._map) {
      out.push({ hostname, ...rec })
    }
    out.sort(function (a, b) {
      return a.hostname.localeCompare(b.hostname)
    })
    return out
  }
}

module.exports = { DnsManualRegistry }
