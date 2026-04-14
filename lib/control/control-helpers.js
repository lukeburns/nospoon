'use strict'

const crypto = require('crypto')
const { parseSubnet, intToIp } = require('../ip/ip-subnet')
const { loadOrCreatePersistedSeedHex } = require('../identity/identity')

function natSourceCidrFromDirectPool (ipv4Cidr) {
  const { network, prefix } = parseSubnet(String(ipv4Cidr || '10.0.0.1/24'))
  return `${intToIp(network)}/${prefix}`
}

function discoveryIncludedInPeerTopics (topics, discoveryBuf) {
  if (!topics || !topics.length || !discoveryBuf) return false
  const want = Buffer.isBuffer(discoveryBuf) ? discoveryBuf : Buffer.from(discoveryBuf)
  for (const t of topics) {
    const buf = Buffer.isBuffer(t) ? t : Buffer.from(t)
    if (buf.length === want.length && buf.equals(want)) return true
  }
  return false
}

function publicKeysEqual (a, b) {
  if (!a || !b) return false
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(a)
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(b)
  return ba.length === bb.length && ba.equals(bb)
}

function swarmHasLiveConnection (swarm, remotePublicKey) {
  if (!swarm || !remotePublicKey) return false
  for (const c of swarm.connections) {
    try {
      if (
        c &&
        !c.destroyed &&
        c.remotePublicKey &&
        publicKeysEqual(c.remotePublicKey, remotePublicKey)
      ) {
        return true
      }
    } catch (_) {}
  }
  return false
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string}
 */
function validateControlPrimaryCidr (value, label) {
  const s = String(value == null ? '' : value).trim()
  if (!s) throw new Error(`${label} is required`)
  try {
    parseSubnet(s)
  } catch {
    throw new Error(`${label} must be a valid IPv4 CIDR (e.g. 10.0.5.1/24)`)
  }
  return s
}

/**
 * Control-plane Noise identity: explicit `clientSeedHex`, else ephemeral random (tests), else
 * persisted seed under `~/.nospoon/identity.json` (or `NOSPOON_HOME`).
 *
 * @param {{
 *   clientSeedHex?: string | null,
 *   ephemeralClientKey?: boolean
 * }} [opts]
 * @returns {string}
 */
function resolveControlClientSeedHex (opts) {
  if (opts && opts.clientSeedHex != null && String(opts.clientSeedHex).trim()) {
    const h = String(opts.clientSeedHex).trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) {
      throw new Error('clientSeedHex must be 64 lowercase hex characters')
    }
    return h
  }
  if (opts && opts.ephemeralClientKey === true) {
    return crypto.randomBytes(32).toString('hex')
  }
  return loadOrCreatePersistedSeedHex()
}

/**
 * Whether to point the OS resolver at 127.0.0.1 while mesh DNS is on (macOS / Linux; needs root).
 * Default on; disable with `systemDnsOverride: false`, env `NOSPOON_SYSTEM_DNS=0`, or legacy `NOSPOON_DARWIN_SYSTEM_DNS=0`.
 *
 * @param {{ systemDnsOverride?: boolean, darwinSystemDns?: boolean }} opts
 * @returns {boolean}
 */
function resolveSystemDnsOverrideOpt (opts) {
  if (opts.systemDnsOverride === false) return false
  if (opts.systemDnsOverride === true) return true
  if (opts.darwinSystemDns === false) return false
  if (opts.darwinSystemDns === true) return true
  const v = process.env.NOSPOON_SYSTEM_DNS
  if (v !== undefined && String(v).trim() !== '') {
    if (/^(0|false|off|no)$/i.test(String(v).trim())) return false
    return true
  }
  const d = process.env.NOSPOON_DARWIN_SYSTEM_DNS
  if (d !== undefined && String(d).trim() !== '') {
    if (/^(0|false|off|no)$/i.test(String(d).trim())) return false
    return true
  }
  return true
}

module.exports = {
  natSourceCidrFromDirectPool,
  discoveryIncludedInPeerTopics,
  publicKeysEqual,
  swarmHasLiveConnection,
  validateControlPrimaryCidr,
  resolveControlClientSeedHex,
  resolveSystemDnsOverrideOpt
}
