'use strict'

const { execFileSync } = require('child_process')
const fs = require('fs')
const {
  mergeSessionDnsWithPreApply,
  parseNameserversFromResolvBackup
} = require('./dns-restore-merge')

const RESOLV_PATH = '/etc/resolv.conf'

/**
 * @type {{
 *   kind: 'resolvectl',
 *   iface: string,
 *   prevDns: string[],
 *   prevDomains: string[],
 *   domainModified: boolean
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

function getResolvectlStatus () {
  try {
    return run('resolvectl', ['--no-pager', 'status'], true)
  } catch (_) {
    return ''
  }
}

/**
 * @param {string} iface
 * @param {string} statusText
 * @returns {string}
 */
function parseLinkBlockForIface (iface, statusText) {
  const esc = iface.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(
    'Link \\d+ \\(' + esc + '\\)([\\s\\S]*?)(?=\\nLink \\d+\\(|\\nGlobal\\b|\\Z)'
  )
  const m = re.exec(statusText || '')
  return m ? m[1] : ''
}

/**
 * @param {string} iface
 * @returns {string[]}
 */
function parseDnsDomainsForLink (iface) {
  const block = parseLinkBlockForIface(iface, getResolvectlStatus())
  const dm = block.match(/DNS Domain:\s*([^\n]+)/i)
  if (!dm) return []
  return dm[1].trim().split(/\s+/).filter(Boolean)
}

/**
 * @param {string} iface
 * @returns {string[]}
 */
function parseDnsServersForLink (iface) {
  const block = parseLinkBlockForIface(iface, getResolvectlStatus())
  let dm = block.match(/DNS Servers?:\s*([^\n]+)/i)
  if (!dm) dm = block.match(/Current DNS Server:\s*([^\n]+)/i)
  if (!dm) return []
  return dm[1].trim().split(/\s+/).filter(Boolean)
}

function isLinuxLoopbackBind (address) {
  const a = String(address || '').trim()
  return a === '127.0.0.1' || a === '0.0.0.0' || a === '::1' || a === '::'
}

/**
 * @param {string} iface
 * @returns {{ prevDns: string[], prevDomains: string[], domainModified: boolean }}
 */
function applyResolvectl (iface) {
  const prevDns = parseDnsServersForLink(iface)
  const prevDomains = parseDnsDomainsForLink(iface)
  let domainModified = false
  try {
    run('resolvectl', ['dns', iface, '127.0.0.1'])
    const first = prevDomains[0] || ''
    const rootAlready = first === '.' || first === '~.'
    if (!rootAlready) {
      const rest = prevDomains.filter(function (d) {
        return d !== '.' && d !== '~.'
      })
      const next = ['.'].concat(rest)
      run('resolvectl', ['domain', iface].concat(next))
      domainModified = true
    }
  } catch (e) {
    try {
      run('resolvectl', ['revert', iface])
    } catch (_) {}
    throw e
  }
  return { prevDns, prevDomains, domainModified }
}

function restoreResolvectl (iface) {
  run('resolvectl', ['revert', iface])
}

/**
 * Replace nameserver lines in a resolv.conf backup with `dnsServers`; preserve other lines.
 * @param {string} backup
 * @param {string[]} dnsServers
 * @returns {string}
 */
function mergeResolvConfBackupWithDnsServers (backup, dnsServers) {
  if (!dnsServers || dnsServers.length === 0) return backup
  const lines = backup.split('\n')
  const out = []
  let replacedNs = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const t = line.trim()
    if (/^nameserver\s/i.test(t)) {
      if (!replacedNs) {
        for (let j = 0; j < dnsServers.length; j++) {
          out.push('nameserver ' + dnsServers[j])
        }
        replacedNs = true
      }
    } else {
      out.push(line)
    }
  }
  if (!replacedNs) {
    const head = dnsServers.map(function (s) {
      return 'nameserver ' + s
    }).join('\n')
    return head + '\n' + backup
  }
  return out.join('\n')
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
      const r = applyResolvectl(iface)
      snapshot = {
        kind: 'resolvectl',
        iface,
        prevDns: r.prevDns,
        prevDomains: r.prevDomains,
        domainModified: r.domainModified
      }
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

/**
 * @param {{ iface: string, prevDomains?: string[], domainModified?: boolean }} rec
 * @param {string[]} dnsServers
 */
function restoreResolvectlSessionUpstream (rec, dnsServers) {
  run('resolvectl', ['dns', rec.iface].concat(dnsServers))
  if (rec.domainModified) {
    const prev = rec.prevDomains || []
    if (prev.length > 0) {
      run('resolvectl', ['domain', rec.iface].concat(prev))
    } else {
      try {
        run('resolvectl', ['domain', rec.iface, '~'])
      } catch (_) {}
    }
  }
}

/**
 * @param {{ dnsServers?: string[] }} [opts] — non-empty `dnsServers` writes the session upstream instead of full revert / backup restore.
 */
function restore (opts) {
  lastMessage = null
  if (!snapshot) return
  const rec = snapshot
  snapshot = null
  const sessionUpstream =
    opts &&
    opts.dnsServers &&
    Array.isArray(opts.dnsServers) &&
    opts.dnsServers.length > 0
  try {
    if (rec.kind === 'resolvectl') {
      if (sessionUpstream) {
        const merged = mergeSessionDnsWithPreApply(
          opts.dnsServers,
          rec.prevDns || []
        )
        restoreResolvectlSessionUpstream(
          rec,
          merged.length > 0 ? merged : opts.dnsServers
        )
        lastMessage =
          'system DNS set to session upstream (resolvectl) on ' + rec.iface
      } else {
        restoreResolvectl(rec.iface)
        lastMessage = 'system DNS reverted (resolvectl) on ' + rec.iface
      }
    } else if (sessionUpstream) {
      const mergedList = mergeSessionDnsWithPreApply(
        opts.dnsServers,
        parseNameserversFromResolvBackup(rec.backup)
      )
      const merged = mergeResolvConfBackupWithDnsServers(
        rec.backup,
        mergedList.length > 0 ? mergedList : opts.dnsServers
      )
      fs.writeFileSync(rec.path, merged, 'utf8')
      lastMessage = 'system DNS restored (' + rec.path + ') with session upstream'
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
  getLastMessage,
  mergeResolvConfBackupWithDnsServers
}
