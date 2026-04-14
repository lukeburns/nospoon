'use strict'

const { execFile } = require('child_process')
const util = require('util')
const net = require('net')
const os = require('os')
const { ipv4ContainedInCidr, collectAssignedIpv4Addresses } = require('../ip/ip-subnet')

const execFileAsync = util.promisify(execFile)

const PRIVATE_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

/** Auto-picked loopback aliases use this range (see {@link pickAutoLoopbackAliasIpv4}). */
const AUTO_LOOPBACK_POOL_CIDR = '10.254.0.0/16'

function compareIpv4Ascending (a, b) {
  const pa = String(a).split('.').map(Number)
  const pb = String(b).split('.').map(Number)
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i]
  }
  return 0
}

function platformSupportsLoopbackAliases () {
  const p = os.platform()
  return p === 'darwin' || p === 'linux'
}

function initialSnapshot () {
  return {
    supported: platformSupportsLoopbackAliases(),
    aliases: [],
    error: null
  }
}

/**
 * Extra loopback IPv4s we allow adding/removing via the control plane (private + 127/8 except .1).
 * @param {string} ip
 */
function isAllowedLoopbackAliasIpv4 (ip) {
  if (!net.isIPv4(ip)) return false
  if (ip === '127.0.0.1') return false
  if (ip === '0.0.0.0') return false
  const o1 = parseInt(ip.split('.')[0], 10)
  if (o1 >= 224) return false
  for (const cidr of PRIVATE_CIDRS) {
    if (ipv4ContainedInCidr(ip, cidr)) return true
  }
  if (ipv4ContainedInCidr(ip, '127.0.0.0/8')) return true
  return false
}

function execErrMessage (e) {
  const parts = []
  if (e && e.stderr && String(e.stderr).trim()) parts.push(String(e.stderr).trim())
  if (e && e.stdout && String(e.stdout).trim()) parts.push(String(e.stdout).trim())
  if (e && e.message) parts.push(e.message)
  return parts.join('\n') || 'command failed'
}

async function listDarwin () {
  const { stdout } = await execFileAsync('ifconfig', ['lo0'], { maxBuffer: 1024 * 1024 })
  const ips = new Set()
  const re = /^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+/gm
  let m
  while ((m = re.exec(stdout)) !== null) {
    if (m[1] !== '127.0.0.1') ips.add(m[1])
  }
  return [...ips].sort()
}

async function listLinux () {
  const { stdout } = await execFileAsync('ip', ['-4', 'addr', 'show', 'dev', 'lo'], {
    maxBuffer: 1024 * 1024
  })
  const ips = new Set()
  const re = /^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\/\d+/gm
  let m
  while ((m = re.exec(stdout)) !== null) {
    if (m[1] !== '127.0.0.1') ips.add(m[1])
  }
  return [...ips].sort()
}

/**
 * @returns {Promise<{ supported: boolean, aliases: string[], error: string | null }>}
 */
async function probeLoopbackAliases () {
  if (!platformSupportsLoopbackAliases()) {
    return { supported: false, aliases: [], error: null }
  }
  try {
    const aliases = os.platform() === 'darwin' ? await listDarwin() : await listLinux()
    return { supported: true, aliases, error: null }
  } catch (e) {
    return { supported: true, aliases: [], error: execErrMessage(e) }
  }
}

/**
 * Prefer an existing loopback alias in {@link AUTO_LOOPBACK_POOL_CIDR} (stable across nospoon
 * restarts). Otherwise first unused address in that range vs all interfaces + loopback.
 * @param {{ excludeIps?: string[] }} [opts] — never pick these (e.g. already used for another manual hostname)
 * @returns {Promise<string>}
 */
async function pickAutoLoopbackAliasIpv4 (opts) {
  const exclude = new Set()
  if (opts && Array.isArray(opts.excludeIps)) {
    for (const x of opts.excludeIps) {
      const s = String(x || '').trim()
      if (net.isIPv4(s)) exclude.add(s)
    }
  }

  let onLo = []
  try {
    onLo = os.platform() === 'darwin' ? await listDarwin() : await listLinux()
  } catch (_) {}

  const reusePool = onLo
    .filter(function (ip) {
      return (
        ipv4ContainedInCidr(ip, AUTO_LOOPBACK_POOL_CIDR) && !exclude.has(ip)
      )
    })
    .sort(compareIpv4Ascending)
  if (reusePool.length > 0) {
    return reusePool[0]
  }

  const used = collectAssignedIpv4Addresses()
  used.add('127.0.0.1')
  for (const x of onLo) used.add(x)
  for (const x of exclude) used.add(x)
  for (let third = 0; third < 256; third++) {
    for (let fourth = 1; fourth < 255; fourth++) {
      const candidate = `10.254.${third}.${fourth}`
      if (!used.has(candidate)) return candidate
    }
  }
  throw new Error('No free IPv4 in auto pool 10.254.0.0/16')
}

/**
 * @param {string} [ipv4] — if empty, pick from 10.254.0.0/16
 * @param {{ excludeIps?: string[] }} [opts] — passed to auto-pick when {@code ipv4} is empty
 * @returns {Promise<string>} the address that was added
 */
async function addLoopbackAlias (ipv4, opts) {
  if (!platformSupportsLoopbackAliases()) {
    throw new Error('Loopback aliases are only supported on macOS and Linux')
  }
  let ip = String(ipv4 || '').trim()
  if (!ip) {
    ip = await pickAutoLoopbackAliasIpv4(opts)
  } else if (!isAllowedLoopbackAliasIpv4(ip)) {
    throw new Error(
      'IPv4 must be private (10/8, 172.16/12, 192.168/16) or in 127.0.0.0/8 (not 127.0.0.1)'
    )
  }
  try {
    const existing =
      os.platform() === 'darwin' ? await listDarwin() : await listLinux()
    if (existing.includes(ip)) return ip
  } catch (_) {}
  try {
    if (os.platform() === 'darwin') {
      await execFileAsync('ifconfig', ['lo0', 'alias', ip])
    } else {
      await execFileAsync('ip', ['addr', 'add', `${ip}/32`, 'dev', 'lo'])
    }
  } catch (e) {
    throw new Error(execErrMessage(e))
  }
  return ip
}

/**
 * @param {string} ipv4
 */
async function removeLoopbackAlias (ipv4) {
  if (!platformSupportsLoopbackAliases()) {
    throw new Error('Loopback aliases are only supported on macOS and Linux')
  }
  const ip = String(ipv4 || '').trim()
  if (!net.isIPv4(ip)) throw new Error('invalid IPv4')
  if (ip === '127.0.0.1') throw new Error('refusing to remove 127.0.0.1')
  if (!isAllowedLoopbackAliasIpv4(ip)) {
    throw new Error(
      'IPv4 must be private (10/8, 172.16/12, 192.168/16) or in 127.0.0.0/8 (not 127.0.0.1)'
    )
  }
  try {
    if (os.platform() === 'darwin') {
      await execFileAsync('ifconfig', ['lo0', '-alias', ip])
    } else {
      await execFileAsync('ip', ['addr', 'del', `${ip}/32`, 'dev', 'lo'])
    }
  } catch (e) {
    throw new Error(execErrMessage(e))
  }
}

module.exports = {
  initialSnapshot,
  platformSupportsLoopbackAliases,
  isAllowedLoopbackAliasIpv4,
  probeLoopbackAliases,
  pickAutoLoopbackAliasIpv4,
  addLoopbackAlias,
  removeLoopbackAlias,
  AUTO_LOOPBACK_POOL_CIDR
}
