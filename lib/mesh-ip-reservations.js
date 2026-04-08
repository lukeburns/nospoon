'use strict'

const { meshIdentifierStorageKey, normalizeKeyHex } = require('./mesh-identifier')
const { allocateLowestAvailableIpv4, parseSubnet } = require('./ip-subnet')

/**
 * @param {string} keyHex
 * @param {string} topicId
 */
function keyTopicStorageKey (keyHex, topicId) {
  return meshIdentifierStorageKey({
    kind: 'keyTopic',
    keyHex: normalizeKeyHex(keyHex),
    topicId: String(topicId).trim()
  })
}

/**
 * Pre-allocates IPv4 addresses for mesh identities before streams exist (DNS / UI / automation).
 * Consumed by {@link createDirectPool} and {@link startSwarmMesh} via `takeReservedPeerIp` hooks.
 */
class MeshIpReservationManager {
  constructor () {
    /** @type {string|null} */
    this._primaryCidr = null
    /** @type {Map<string, string>} meshId storage key → ipv4 */
    this._primaryReserved = new Map()
    /** @type {Map<string, string>} topic row id → cidr */
    this._topicCidr = new Map()
    /** @type {Map<string, Map<string, string>>} topicId → (storageKey → ip) */
    this._topicReserved = new Map()
  }

  /**
   * @param {string} cidr — primary (direct pool) IPv4 CIDR
   */
  setPrimaryCidr (cidr) {
    const s = String(cidr || '').trim()
    parseSubnet(s)
    this._primaryCidr = s
  }

  getPrimaryCidr () {
    return this._primaryCidr
  }

  clearPrimary () {
    this._primaryCidr = null
    this._primaryReserved.clear()
  }

  /**
   * @param {string} topicId — control-plane topic row id (UUID)
   * @param {string} cidr
   */
  setTopicCidr (topicId, cidr) {
    const id = String(topicId).trim()
    const s = String(cidr || '').trim()
    parseSubnet(s)
    this._topicCidr.set(id, s)
    if (!this._topicReserved.has(id)) this._topicReserved.set(id, new Map())
  }

  /**
   * @param {string} topicId
   */
  deleteTopic (topicId) {
    const id = String(topicId).trim()
    this._topicCidr.delete(id)
    this._topicReserved.delete(id)
  }

  getTopicCidr (topicId) {
    return this._topicCidr.get(String(topicId).trim()) || null
  }

  /**
   * Remove and return a reserved primary (`kind: 'key'`) address for `keyHex`, if any.
   * @param {string} keyHex
   * @returns {string|null}
   */
  consumePrimaryReservation (keyHex) {
    const h = normalizeKeyHex(keyHex)
    const sk = meshIdentifierStorageKey({ kind: 'key', keyHex: h })
    const ip = this._primaryReserved.get(sk)
    if (ip == null) return null
    this._primaryReserved.delete(sk)
    return ip
  }

  /**
   * @param {string} topicId
   * @param {string} keyHex
   * @returns {string|null}
   */
  consumeTopicReservation (topicId, keyHex) {
    const id = String(topicId).trim()
    const h = normalizeKeyHex(keyHex)
    const sk = keyTopicStorageKey(h, id)
    const m = this._topicReserved.get(id)
    if (!m) return null
    const ip = m.get(sk)
    if (ip == null) return null
    m.delete(sk)
    if (m.size === 0) this._topicReserved.delete(id)
    return ip
  }

  /**
   * @param {string} keyHex
   * @param {Set<string>|Iterable<string>} baseUsedIps — caller supplies live addresses in this subnet
   * @returns {string}
   */
  reservePrimaryKey (keyHex, baseUsedIps) {
    if (!this._primaryCidr) throw new Error('primary IPv4 subnet not configured')
    const h = normalizeKeyHex(keyHex)
    const sk = meshIdentifierStorageKey({ kind: 'key', keyHex: h })
    const existing = this._primaryReserved.get(sk)
    if (existing != null) return existing
    const used = new Set(baseUsedIps)
    for (const ip of this._primaryReserved.values()) used.add(ip)
    const ip = allocateLowestAvailableIpv4(this._primaryCidr, used)
    this._primaryReserved.set(sk, ip)
    return ip
  }

  /**
   * @param {string} topicId
   * @param {string} keyHex
   * @param {Set<string>|Iterable<string>} baseUsedIps
   * @returns {string}
   */
  reserveTopicPeer (topicId, keyHex, baseUsedIps) {
    const id = String(topicId).trim()
    const cidr = this._topicCidr.get(id)
    if (!cidr) throw new Error('topic subnet not registered for reservations')
    const h = normalizeKeyHex(keyHex)
    const sk = keyTopicStorageKey(h, id)
    let m = this._topicReserved.get(id)
    if (!m) {
      m = new Map()
      this._topicReserved.set(id, m)
    }
    const have = m.get(sk)
    if (have != null) return have
    const used = new Set(baseUsedIps)
    for (const ip of m.values()) used.add(ip)
    const ip = allocateLowestAvailableIpv4(cidr, used)
    m.set(sk, ip)
    return ip
  }

  /**
   * @param {string} keyHex
   * @returns {boolean}
   */
  releasePrimaryKey (keyHex) {
    const sk = meshIdentifierStorageKey({
      kind: 'key',
      keyHex: normalizeKeyHex(keyHex)
    })
    return this._primaryReserved.delete(sk)
  }

  /**
   * @param {string} topicId
   * @param {string} keyHex
   * @returns {boolean}
   */
  releaseTopicPeer (topicId, keyHex) {
    const id = String(topicId).trim()
    const sk = keyTopicStorageKey(normalizeKeyHex(keyHex), id)
    const m = this._topicReserved.get(id)
    if (!m) return false
    const ok = m.delete(sk)
    if (m.size === 0) this._topicReserved.delete(id)
    return ok
  }

  /**
   * Reverse lookup: given an IPv4, find the mesh identifier that reserved it.
   * @param {string} ip
   * @returns {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicId: string } | null}
   */
  reverseLookupIpv4 (ip) {
    const target = String(ip || '').trim()
    if (!target) return null
    for (const [sk, v] of this._primaryReserved) {
      if (v === target && sk.startsWith('k:')) {
        return { kind: 'key', keyHex: sk.slice(2) }
      }
    }
    for (const [tid, m] of this._topicReserved) {
      for (const [sk, v] of m) {
        if (v === target && sk.startsWith('kt:')) {
          const keyHex = sk.slice(3, 3 + 64)
          return { kind: 'keyTopic', keyHex, topicId: tid }
        }
      }
    }
    return null
  }

  getSnapshot () {
    const primary = []
    for (const [meshIdKey, ipv4] of this._primaryReserved) {
      primary.push({ meshIdKey, ipv4 })
    }
    const topics = {}
    for (const [tid, m] of this._topicReserved) {
      topics[tid] = [...m.entries()].map(([meshIdKey, ipv4]) => ({
        meshIdKey,
        ipv4
      }))
    }
    return {
      primaryCidr: this._primaryCidr,
      primary,
      topicSubnets: Object.fromEntries(this._topicCidr),
      topics
    }
  }

  /** Drop all topic state; clears primary subnet and primary reservations too. */
  resetAll () {
    this.clearPrimary()
    this._topicCidr.clear()
    this._topicReserved.clear()
  }
}

module.exports = {
  MeshIpReservationManager,
  keyTopicStorageKey
}
