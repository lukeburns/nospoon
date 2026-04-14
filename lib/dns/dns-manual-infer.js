'use strict'

const net = require('net')
const dns = require('dns').promises
const { normalizeFqdn, parseMeshDnsName } = require('./dns-mesh-name')
const { parse32Bytes, toHex32 } = require('../wire/key-encoding')

/**
 * @typedef {{ kind: 'literal', ipv4?: string, ipv6?: string }} InferredLiteral
 * @typedef {{ kind: 'mesh', meshId: { kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string } }} InferredMesh
 * @typedef {{ kind: 'alias', target: string }} InferredAlias
 */

/**
 * Infer manual DNS assignment from a single target string (IPv4, IPv6, mesh z32/hex/key.topic, or hostname).
 * @param {string} targetRaw
 * @returns {InferredLiteral | InferredMesh | InferredAlias}
 */
function inferManualDnsTarget (targetRaw) {
  const t = String(targetRaw).trim()
  if (!t) throw new Error('target is required')

  let ipProbe = t
  if (ipProbe.startsWith('[') && ipProbe.endsWith(']')) {
    ipProbe = ipProbe.slice(1, -1)
  }
  if (net.isIPv4(ipProbe)) return { kind: 'literal', ipv4: ipProbe }
  if (net.isIPv6(ipProbe)) return { kind: 'literal', ipv6: ipProbe }

  const tn = normalizeFqdn(t)
  const meshFromFqdn = parseMeshDnsName(tn)
  if (meshFromFqdn) return { kind: 'mesh', meshId: meshFromFqdn }

  try {
    const buf = parse32Bytes(t, 'target')
    const keyHex = toHex32(buf)
    return { kind: 'mesh', meshId: { kind: 'key', keyHex } }
  } catch (_) {}

  return { kind: 'alias', target: tn }
}

/**
 * Resolve a public or local hostname to A/AAAA literals (used when target is not mesh and not an IP).
 * @param {string} hostname — normalized FQDN or single label
 * @returns {Promise<InferredLiteral>}
 */
async function resolveHostnameToLiteral (hostname) {
  const h = normalizeFqdn(hostname)
  const ipv4 = await dns
    .resolve4(h)
    .then(function (a) {
      return a && a[0] ? String(a[0]) : null
    })
    .catch(function () {
      return null
    })
  const ipv6 = await dns
    .resolve6(h)
    .then(function (a) {
      return a && a[0] ? String(a[0]) : null
    })
    .catch(function () {
      return null
    })
  if (!ipv4 && !ipv6) {
    throw new Error(`Could not resolve hostname: ${h}`)
  }
  /** @type {InferredLiteral} */
  const out = { kind: 'literal' }
  if (ipv4) out.ipv4 = ipv4
  if (ipv6) out.ipv6 = ipv6
  return out
}

/**
 * @param {function(string): object | undefined} getRaw — normalized hostname → stored entry
 * @param {string} newAliasNorm
 * @param {string} targetNorm
 * @returns {boolean}
 */
function manualAliasWouldCycle (getRaw, newAliasNorm, targetNorm) {
  if (targetNorm === newAliasNorm) return true
  const seen = new Set()
  let hop = targetNorm
  for (let i = 0; i < 32; i++) {
    if (hop === newAliasNorm) return true
    if (seen.has(hop)) return false
    seen.add(hop)
    const raw = getRaw(hop)
    if (!raw || raw.kind !== 'alias') return false
    hop = raw.target
  }
  return true
}

module.exports = {
  inferManualDnsTarget,
  resolveHostnameToLiteral,
  manualAliasWouldCycle
}
