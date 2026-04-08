'use strict'

/**
 * Per-platform system DNS override while nospoon listens on UDP 53 (macOS: networksetup;
 * Linux: resolvectl or /etc/resolv.conf). No-op on other platforms.
 */

function getImpl () {
  if (process.platform === 'darwin') return require('./dns-system-override-darwin')
  if (process.platform === 'linux') return require('./dns-system-override-linux')
  return {
    apply: function () {
      return { applied: false, message: null }
    },
    restore: function () {},
    isActive: function () {
      return false
    },
    getLastMessage: function () {
      return null
    }
  }
}

/**
 * @param {{ port: number, address: string }} opts
 * @returns {{ applied: boolean, message: string | null }}
 */
function apply (opts) {
  return getImpl().apply(opts)
}

function restore () {
  return getImpl().restore()
}

function isActive () {
  return getImpl().isActive()
}

function getLastMessage () {
  return getImpl().getLastMessage()
}

module.exports = {
  apply,
  restore,
  isActive,
  getLastMessage
}
