'use strict'

/**
 * Heuristic: IPFS CIDv1 in default multibase encoding (starts with {@code b}, lowercase RFC 4648 base32),
 * as a single DNS label (≤63). Matches names after {@link ./dns-mesh-name#normalizeFqdn} lowercasing.
 *
 * @param {string} label
 * @returns {boolean}
 */
function isIpfsCidDnsLabel (label) {
  const s = String(label || '').trim().toLowerCase()
  if (!s || s.length > 63 || s.indexOf('.') >= 0) return false
  if (!s.startsWith('b')) return false
  if (s.length < 50) return false
  return /^b[a-z2-7]+$/.test(s)
}

/**
 * @param {string} fqdn — normalized (see {@link ./dns-mesh-name#normalizeFqdn})
 * @returns {string | null} lowercase CID-shaped label
 */
function parseIpfsCidHostname (fqdn) {
  const name = String(fqdn || '').trim().toLowerCase()
  if (!name || name.indexOf('.') >= 0) return null
  return isIpfsCidDnsLabel(name) ? name : null
}

module.exports = {
  isIpfsCidDnsLabel,
  parseIpfsCidHostname
}
