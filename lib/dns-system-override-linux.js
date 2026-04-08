'use strict'

const { execFileSync } = require('child_process')
const fs = require('fs')

const RESOLV_PATH = '/etc/resolv.conf'

/**
 * @type {{
 *   kind: 'resolvectl',
 *   iface: string
 * } | {
 *   kind: 'file',
 *   path: string,
 *   backup: string
 * } | null}
 */
let snapshot = null
/** @type {string | null} */
let lastMessage = null

function run (cmd, args, ignoreStderr) {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf-8',
      maxBuffer: 2 * 1024 * 1024,
      stdio: ignoreStderr ? ['ignore', 'pipe', 'ignore'] : undefined
    }).trim()
  } catch (err) {
    const msg = (err.stderr && String(err.stderr)) || err.message || String(err)
    throw new Error(`${cmd} ${args.join(' ')}: ${msg}`)
  }
}

function hasResolvectl () {
  try {
    execFileSync('resolvectl', ['--no-pager', '--version'], { stdio: 'ignore' })
    return true
  } catch (_) {
    return false
  }
}

function getDefaultRouteIface () {
  try {
    const o = run('ip', ['-4', 'route', 'show', 'default'])
    const m = o.match(/\bdev\s+(\S+)/)
    return m ? m[1] : null
  } catch (_) {
    return null
  }
}

/**
 * @param {string} iface
 * @returns {string[]}
 */
function parseDnsDomainsForLink (iface) {
  let out
  try {
    out = run('resolvectl', ['--no-pager', 'status'], true)
  } catch (_) {
    return []
  }
  const esc = iface.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(
    'Link \\d+ \\(' + esc + '\\)([\\s\\S]*?)(?=\\nLink \\d+\\(|\\nGlobal\\b|\\Z)'
  )
  const m = re.exec(out)
  const block = m ? m[1] : ''
  const dm = block.match(/DNS Domain:\s*([^\n]+)/i)
  if (!dm) return []
  return dm[1].trim().split(/\s+/).filter(Boolean)
}

function isLinuxLoopbackBind (address) {
  const a = String(address || '').trim()
  return a === '127.0.0.1' || a === '0.0.0.0' || a === '::1' || a === '::'
}

function applyResolvectl (iface) {
  try {
    run('resolvectl', ['dns', iface, '127.0.0.1'])
    const domains = parseDnsDomainsForLink(iface)
    const first = domains[0] || ''
    const rootAlready = first === '.' || first === '~.'
    if (!rootAlready) {
      const rest = domains.filter(function (d) {
        return d !== '.' && d !== '~.'
      })
      const next = ['.'].concat(rest)
      run('resolvectl', ['domain', iface].concat(next))
    }
  } catch (e) {
    try {
      run('resolvectl', ['revert', iface])
    } catch (_) {}
    throw e
  }
}

function restoreResolvectl (iface) {
  run('resolvectl', ['revert', iface])
}

function applyResolvConfFile () {
  let lstat
  try {
    lstat = fs.lstatSync(RESOLV_PATH)
  } catch (_) {
    throw new Error('no ' + RESOLV_PATH)
  }
  if (lstat.isSymbolicLink()) {
    const target = fs.readlinkSync(RESOLV_PATH)
    if (/systemd\/resolve|run\/systemd/i.test(target)) {
      throw new Error(RESOLV_PATH + ' is systemd-resolved stub; use resolvectl')
    }
  }
  const backup = fs.readFileSync(RESOLV_PATH, 'utf8')
  const searchMatch = backup.match(/^\s*search\s+(.+)$/im)
  const prevSearch = searchMatch
    ? searchMatch[1].trim().split(/\s+/).filter(Boolean)
    : []
  let searchLine = 'search .'
  if (prevSearch.length > 0) {
    if (prevSearch[0] === '.') {
      searchLine = 'search ' + prevSearch.join(' ')
    } else {
      searchLine =
        'search . ' + prevSearch.filter(function (s) { return s !== '.' }).join(' ')
    }
  }
  const body =
    'nameserver 127.0.0.1\n' +
    searchLine +
    '\n# nospoon temporary resolv.conf\n'
  fs.writeFileSync(RESOLV_PATH, body, 'utf8')
  return backup
}

/**
 * Only 127.0.0.1 — nospoon’s DNS process forwards upstream; extra resolvers would bypass it (NXDOMAIN).
 *
 * @param {{ port: number, address: string }} opts
 * @returns {{ applied: boolean, message: string | null }}
 */
function apply (opts) {
  lastMessage = null
  if (process.platform !== 'linux') {
    return { applied: false, message: null }
  }
  if (snapshot) {
    return { applied: true, message: null }
  }

  const port = Number(opts.port)
  const address = String(opts.address || '127.0.0.1').trim()
  if (port !== 53) {
    return {
      applied: false,
      message: 'system DNS override skipped: port must be 53'
    }
  }
  if (!isLinuxLoopbackBind(address)) {
    return {
      applied: false,
      message:
        'system DNS override skipped: bind to 127.0.0.1 or 0.0.0.0 (or ::1 / ::)'
    }
  }

  const iface = getDefaultRouteIface()
  if (hasResolvectl() && iface) {
    try {
      applyResolvectl(iface)
      snapshot = { kind: 'resolvectl', iface }
      lastMessage =
        'system DNS → 127.0.0.1 via resolvectl on ' + iface + ' (. in search if needed)'
      return { applied: true, message: lastMessage }
    } catch (e) {
      lastMessage = e instanceof Error ? e.message : String(e)
    }
  }

  try {
    const backup = applyResolvConfFile()
    snapshot = { kind: 'file', path: RESOLV_PATH, backup }
    lastMessage = 'system DNS → 127.0.0.1 via ' + RESOLV_PATH + ' (restore on exit)'
    return { applied: true, message: lastMessage }
  } catch (e) {
    const extra = lastMessage ? ' (' + lastMessage + ')' : ''
    lastMessage =
      (e instanceof Error ? e.message : String(e)) +
      extra +
      (iface ? '; tried iface ' + iface : '')
    return { applied: false, message: lastMessage }
  }
}

function restore () {
  lastMessage = null
  if (!snapshot) return
  const rec = snapshot
  snapshot = null
  try {
    if (rec.kind === 'resolvectl') {
      restoreResolvectl(rec.iface)
      lastMessage = 'system DNS reverted (resolvectl) on ' + rec.iface
    } else {
      fs.writeFileSync(rec.path, rec.backup, 'utf8')
      lastMessage = 'system DNS restored (' + rec.path + ')'
    }
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    console.error('dns-system-override-linux: ' + lastMessage)
  }
}

function isActive () {
  return snapshot !== null
}

function getLastMessage () {
  return lastMessage
}

module.exports = {
  apply,
  restore,
  isActive,
  getLastMessage
}
