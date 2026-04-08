'use strict'

const { execFileSync } = require('child_process')
const { mergeSessionDnsWithPreApply } = require('./dns-restore-merge')

/**
 * @type {{
 *   service: string,
 *   servers: string[],
 *   searchDomainsModified: boolean,
 *   searchDomainsBefore: string[]
 * } | null}
 */
let snapshot = null
/** @type {string | null} */
let lastMessage = null

function run (cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf-8' }).trim()
  } catch (err) {
    const msg = (err.stderr && String(err.stderr)) || err.message || String(err)
    throw new Error(`${cmd} ${args.join(' ')}: ${msg}`)
  }
}

function getDefaultGateway () {
  const output = run('route', ['-n', 'get', 'default'])
  const gwMatch = output.match(/gateway:\s*(\S+)/)
  const devMatch = output.match(/interface:\s*(\S+)/)
  return {
    gateway: gwMatch ? gwMatch[1] : null,
    device: devMatch ? devMatch[1] : null
  }
}

function getNetworkServiceForDevice (device) {
  const output = run('networksetup', ['-listallhardwareports'])
  const blocks = output.split('\n\n')
  for (const block of blocks) {
    const devMatch = block.match(/Device:\s*(\S+)/)
    const svcMatch = block.match(/Hardware Port:\s*(.+)/)
    if (devMatch && svcMatch && devMatch[1] === device) {
      return svcMatch[1].trim()
    }
  }
  return null
}

function getDnsServers (service) {
  const output = run('networksetup', ['-getdnsservers', service])
  if (!output || output.includes("aren't any")) return []
  return output.split('\n').map(function (s) { return s.trim() }).filter(Boolean)
}

/**
 * @param {string} service
 * @returns {string[]}
 */
function getSearchDomains (service) {
  const output = run('networksetup', ['-getsearchdomains', service])
  if (!output) return []
  const lower = output.toLowerCase()
  if (
    lower.includes("aren't any") ||
    lower.includes('no search domains') ||
    lower.includes('none set')
  ) {
    return []
  }
  return output
    .split('\n')
    .map(function (s) { return s.trim() })
    .filter(Boolean)
    .filter(function (line) {
      return !/^search domains?:/i.test(line)
    })
}

/**
 * Prepend DNS root (`.`) to the search list so single-label names try `name.` first.
 * Skips if `.` is already first. Returns whether {@link restore} must reset search domains.
 *
 * @param {string} service
 * @returns {{ modified: boolean, before: string[] }}
 */
function applySearchRootSuffix (service) {
  let before = []
  try {
    before = getSearchDomains(service)
  } catch (_) {
    return { modified: false, before: [] }
  }
  if (before[0] === '.') {
    return { modified: false, before: [] }
  }
  const rest = before.filter(function (d) { return d !== '.' })
  const next = ['.'].concat(rest)
  try {
    run('networksetup', ['-setsearchdomains', service].concat(next))
  } catch (_) {
    return { modified: false, before: [] }
  }
  return { modified: true, before }
}

function restoreSearchDomains (service, before) {
  if (before.length === 0) {
    run('networksetup', ['-setsearchdomains', service, 'Empty'])
  } else {
    run('networksetup', ['-setsearchdomains', service].concat(before))
  }
}

function isDarwinLoopbackBind (address) {
  const a = String(address || '').trim()
  return a === '127.0.0.1' || a === '0.0.0.0' || a === '::1' || a === '::'
}

/**
 * Point the active macOS network service at this machine’s resolver (127.0.0.1) while nospoon
 * listens on UDP 53. Prepends `.` to the interface search domain list (restored in {@link restore}).
 * Only 127.0.0.1 is set — no public resolvers; nospoon’s DNS server forwards upstream itself.
 *
 * @param {{ port: number, address: string }} opts
 * @returns {{ applied: boolean, message: string | null }}
 */
function apply (opts) {
  lastMessage = null
  if (process.platform !== 'darwin') {
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
  if (!isDarwinLoopbackBind(address)) {
    return {
      applied: false,
      message:
        'system DNS override skipped: bind to 127.0.0.1 or 0.0.0.0 (or ::1 / ::)'
    }
  }

  let gw
  try {
    gw = getDefaultGateway()
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    return { applied: false, message: lastMessage }
  }
  if (!gw || !gw.device) {
    lastMessage = 'system DNS override skipped: no default interface'
    return { applied: false, message: lastMessage }
  }

  let service
  try {
    service = getNetworkServiceForDevice(gw.device)
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    return { applied: false, message: lastMessage }
  }
  if (!service) {
    lastMessage =
      'system DNS override skipped: no network service for ' + gw.device
    return { applied: false, message: lastMessage }
  }

  let previous
  try {
    previous = getDnsServers(service)
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    return { applied: false, message: lastMessage }
  }

  const newServers = ['127.0.0.1']

  try {
    run('networksetup', ['-setdnsservers', service].concat(newServers))
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    return { applied: false, message: lastMessage }
  }

  const search = applySearchRootSuffix(service)
  snapshot = {
    service,
    servers: previous,
    searchDomainsModified: search.modified,
    searchDomainsBefore: search.modified ? search.before.slice() : []
  }
  lastMessage =
    'system DNS set to 127.0.0.1 on "' + service + '"' +
    (search.modified ? '; search domains: . prepended' : '')
  return { applied: true, message: lastMessage }
}

/**
 * @param {{ dnsServers?: string[] }} [opts] — non-empty `dnsServers`: session upstream first, then pre-override resolvers (deduped), not only a single address.
 */
function restore (opts) {
  lastMessage = null
  if (!snapshot) return
  const rec = snapshot
  snapshot = null
  try {
    if (rec.searchDomainsModified) {
      try {
        restoreSearchDomains(rec.service, rec.searchDomainsBefore)
      } catch (e) {
        const m = e instanceof Error ? e.message : String(e)
        console.error('dns-system-override-darwin: search domains restore: ' + m)
      }
    }
    const session =
      opts &&
      opts.dnsServers &&
      Array.isArray(opts.dnsServers) &&
      opts.dnsServers.length > 0
        ? opts.dnsServers
        : null
    const chosen = session
      ? mergeSessionDnsWithPreApply(session, rec.servers)
      : rec.servers
    const args =
      chosen.length > 0
        ? ['-setdnsservers', rec.service].concat(chosen)
        : ['-setdnsservers', rec.service, 'Empty']
    run('networksetup', args)
    lastMessage = 'system DNS restored for "' + rec.service + '"'
  } catch (e) {
    lastMessage = e instanceof Error ? e.message : String(e)
    console.error('dns-system-override-darwin: ' + lastMessage)
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
