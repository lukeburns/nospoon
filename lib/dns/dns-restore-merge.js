'use strict'

/**
 * @param {string} addr
 * @returns {boolean}
 */
function isLoopbackDns (addr) {
  const a = String(addr || '').trim().toLowerCase()
  return a === '127.0.0.1' || a === '0.0.0.0' || a === '::1' || a === '::'
}

/**
 * @param {string} addr
 * @returns {string}
 */
function normDnsKey (addr) {
  return String(addr || '').trim().toLowerCase()
}

/**
 * Session-latest upstream first, then pre-override OS resolvers (fallbacks), deduped.
 * Skips loopback entries from the pre-apply list (e.g. stale 127.0.0.1).
 *
 * @param {string[] | null | undefined} sessionServers — from panel forward target
 * @param {string[] | null | undefined} preApplyServers — captured before override
 * @returns {string[]}
 */
function mergeSessionDnsWithPreApply (sessionServers, preApplyServers) {
  const out = []
  const seen = new Set()
  function add (x) {
    if (x == null || typeof x !== 'string') return
    const t = x.trim()
    if (!t || isLoopbackDns(t)) return
    const k = normDnsKey(t)
    if (seen.has(k)) return
    seen.add(k)
    out.push(t)
  }
  if (Array.isArray(sessionServers)) {
    for (let i = 0; i < sessionServers.length; i++) add(sessionServers[i])
  }
  if (Array.isArray(preApplyServers)) {
    for (let j = 0; j < preApplyServers.length; j++) add(preApplyServers[j])
  }
  return out
}

/**
 * @param {string} backup — full resolv.conf text from before override
 * @returns {string[]}
 */
function parseNameserversFromResolvBackup (backup) {
  if (typeof backup !== 'string') return []
  const out = []
  const lines = backup.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*nameserver\s+(\S+)/i.exec(lines[i])
    if (m) out.push(m[1])
  }
  return out
}

module.exports = {
  mergeSessionDnsWithPreApply,
  parseNameserversFromResolvBackup,
  isLoopbackDns,
  normDnsKey
}
