'use strict'

const z32 = require('z32')

/**
 * @param {string} fqdn
 * @returns {string}
 */
function normalizeFqdn (fqdn) {
  let s = String(fqdn).trim().toLowerCase()
  if (s.endsWith('.')) s = s.slice(0, -1)
  return s
}

/**
 * @param {string} keyHex
 * @returns {string} lowercase 64 hex
 */
function assertHex64 (keyHex) {
  const h = String(keyHex).trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error('expected 64 hex characters (32-byte public key)')
  }
  return h
}

/**
 * @param {string} keyHex
 * @returns {string} single DNS label (≤63 octets)
 */
function encodeKeyLabel (keyHex) {
  const h = assertHex64(keyHex)
  const payload = z32.encode(Buffer.from(h, 'hex'))
  if (payload.length > 63) {
    throw new Error('z32 label exceeds DNS label limit (63 octets)')
  }
  return payload
}

/**
 * @param {string} label
 * @returns {string | null} 64 hex
 */
function decodePublicKeyLabel (label) {
  if (label == null) return null
  const s = String(label)
  if (!s || s.length > 63) return null
  try {
    const buf = z32.decode(s)
    if (buf.length !== 32) return null
    return buf.toString('hex')
  } catch {
    return null
  }
}

/**
 * @param {string} keyHex
 * @returns {string}
 */
function formatKeyToDnsName (keyHex) {
  return encodeKeyLabel(keyHex)
}

/**
 * @param {string} fqdn
 * @returns {string | null}
 */
function parseMeshPeerDnsName (fqdn) {
  const name = normalizeFqdn(fqdn)
  if (name.indexOf('.') >= 0) return null
  return decodePublicKeyLabel(name)
}

/**
 * @param {string} fqdn
 * @returns {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string } | null}
 */
function parseMeshDnsName (fqdn) {
  const name = normalizeFqdn(fqdn)
  const firstDot = name.indexOf('.')
  if (firstDot === -1) {
    const keyHex = decodePublicKeyLabel(name)
    return keyHex ? { kind: 'key', keyHex } : null
  }
  if (name.indexOf('.', firstDot + 1) >= 0) return null
  const labelKey = name.slice(0, firstDot)
  const topicRef = name.slice(firstDot + 1)
  if (!topicRef || topicRef.indexOf('.') >= 0) return null
  const keyHex = decodePublicKeyLabel(labelKey)
  if (!keyHex) return null
  return { kind: 'keyTopic', keyHex, topicRef }
}

/**
 * @param {string} keyHex
 * @param {string} topicRef
 * @returns {string}
 */
function formatMeshTopicDnsName (keyHex, topicRef) {
  assertHex64(keyHex)
  const t = String(topicRef || '').trim()
  if (!t) throw new Error('topicRef is required')
  if (t.indexOf('.') >= 0) throw new Error('topicRef must be one DNS label')
  return `${encodeKeyLabel(keyHex)}.${t}`
}

module.exports = {
  normalizeFqdn,
  encodeKeyLabel,
  decodePublicKeyLabel,
  formatKeyToDnsName,
  parseMeshPeerDnsName,
  parseMeshDnsName,
  formatMeshTopicDnsName,
  assertHex64
}
