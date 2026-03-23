const crypto = require('crypto')
const sodium = require('sodium-universal')
const hc = require('hypercore-crypto')
const b4a = require('b4a')

const NOSPOON = b4a.from('nospoon')

/** Same pattern as hypercore `caps.replicate`, but the secret is arbitrary topic bytes. */
const [NS_INITIATOR, NS_RESPONDER] = hc.namespace('nospoon/swarm-topic', 2)

/**
 * 32-byte DHT / Hyperswarm topic — not the raw topic string (hides preimage from passive DHT observers).
 * BLAKE2b over domain label + topic bytes (hypercore-crypto `hash` batch).
 */
function swarmDiscoveryKey (topicBytes) {
  const t = normalizeTopicBytes(topicBytes)
  return hc.hash([NOSPOON, t])
}

function normalizeTopicBytes (topicBytes) {
  if (Buffer.isBuffer(topicBytes)) return topicBytes
  if (typeof topicBytes === 'string') return Buffer.from(topicBytes, 'utf8')
  throw new Error('topic must be a Buffer or string')
}

/**
 * @param {boolean} isInitiator — Noise stream role (same as SecretStream)
 * @param {Buffer} topicBytes — preimage (UTF-8 bytes of the shared topic)
 * @param {Buffer} handshakeHash — from NoiseSecretStream after handshake
 */
function swarmTopicCapability (isInitiator, topicBytes, handshakeHash) {
  const t = normalizeTopicBytes(topicBytes)
  const out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(
    out,
    [isInitiator ? NS_INITIATOR : NS_RESPONDER, t],
    handshakeHash
  )
  return out
}

function timingSafeEqual (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

module.exports = {
  swarmDiscoveryKey,
  swarmTopicCapability,
  timingSafeEqual,
  normalizeTopicBytes
}
