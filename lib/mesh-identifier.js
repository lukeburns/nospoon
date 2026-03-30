'use strict'

/**
 * Logical mesh identity for DNS / routing (wire key-address framing still uses ed25519 only).
 *
 * @typedef {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicId: string }} MeshIdentifier
 */

function normalizeKeyHex (h) {
  const x = String(h || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(x)) throw new Error('keyHex must be 64 lowercase hex')
  return x
}

/**
 * Stable string key for Maps: `k:<hex>` or `kt:<hex>:<topicId>`.
 * @param {MeshIdentifier} id
 */
function meshIdentifierStorageKey (id) {
  if (!id || !id.kind) throw new Error('MeshIdentifier required')
  if (id.kind === 'key') {
    return `k:${normalizeKeyHex(id.keyHex)}`
  }
  if (id.kind === 'keyTopic') {
    const tid = String(id.topicId || '').trim()
    if (!tid) throw new Error('topicId required for keyTopic')
    return `kt:${normalizeKeyHex(id.keyHex)}:${tid}`
  }
  throw new Error(`unknown MeshIdentifier kind: ${id.kind}`)
}

/**
 * @param {unknown} id
 * @returns {id is MeshIdentifier}
 */
function isMeshIdentifier (id) {
  if (!id || typeof id !== 'object') return false
  const k = id.kind
  if (k === 'key') {
    return typeof id.keyHex === 'string' && /^[0-9a-f]{64}$/.test(String(id.keyHex).trim().toLowerCase())
  }
  if (k === 'keyTopic') {
    const h = typeof id.keyHex === 'string' && /^[0-9a-f]{64}$/.test(String(id.keyHex).trim().toLowerCase())
    return h && typeof id.topicId === 'string' && String(id.topicId).trim().length > 0
  }
  return false
}

module.exports = {
  meshIdentifierStorageKey,
  normalizeKeyHex,
  isMeshIdentifier
}
