'use strict'

const z32 = require('z32')

const HEX64 = /^[0-9a-fA-F]{64}$/

/**
 * Parse a 32-byte public key or seed from CLI / peers.json: **z32** (preferred) or **64 hex** (legacy).
 * @param {string} str
 * @param {string} label — for error messages
 * @returns {Buffer} 32 bytes
 */
function parse32Bytes (str, label) {
  const s = String(str).trim()
  if (HEX64.test(s)) {
    return Buffer.from(s, 'hex')
  }
  try {
    const buf = z32.decode(s)
    if (buf.length === 32) return buf
  } catch (_) {}
  throw new Error(
    `${label}: expected z32-encoded key (or legacy 64 hex characters)`
  )
}

function toHex32 (buf) {
  return Buffer.from(buf).toString('hex')
}

function encodeZ32 (buf) {
  return z32.encode(buf)
}

/** Short label for logs from a 64-hex key string (z32 prefix). */
function formatKeyShortFromHex (keyHex) {
  return encodeZ32(Buffer.from(keyHex, 'hex')).slice(0, 10) + '…'
}

module.exports = {
  parse32Bytes,
  toHex32,
  encodeZ32,
  formatKeyShortFromHex
}
