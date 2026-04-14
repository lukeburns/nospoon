'use strict'

const { execFileSync } = require('child_process')

/**
 * Best-effort flush of OS DNS caches so stale NXDOMAIN / old answers are dropped after mesh DNS starts.
 * Uses root when nospoon is run with sudo. Failures are ignored (no throw).
 */
function flushSystemDnsCache () {
  if (process.platform === 'darwin') {
    flushDarwin()
  } else if (process.platform === 'linux') {
    flushLinux()
  }
}

function tryExec (cmd, args) {
  try {
    execFileSync(cmd, args, { stdio: 'ignore' })
    return true
  } catch (_) {
    return false
  }
}

function flushDarwin () {
  tryExec('dscacheutil', ['-flushcache'])
  tryExec('killall', ['-HUP', 'mDNSResponder'])
}

function flushLinux () {
  if (tryExec('resolvectl', ['flush-caches'])) return
  if (tryExec('systemd-resolve', ['--flush-caches'])) return
  tryExec('nscd', ['-i', 'hosts'])
}

module.exports = {
  flushSystemDnsCache
}
