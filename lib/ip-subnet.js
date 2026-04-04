const os = require('os')

function ipToInt (ip) {
  const octets = ip.split('.').map(Number)
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
}

function intToIp (x) {
  const u = x >>> 0
  return `${(u >>> 24) & 255}.${(u >>> 16) & 255}.${(u >>> 8) & 255}.${u & 255}`
}

function parseSubnet (cidr) {
  const [addr, prefixStr] = cidr.split('/')
  const prefix = parseInt(prefixStr || '24', 10)
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const hostIp = ipToInt(addr)
  const network = (hostIp & mask) >>> 0
  const broadcast = (network | ~mask) >>> 0

  return { hostIp, network, broadcast, mask, prefix }
}

/**
 * Lowest unused host in subnet (excluding network, broadcast, optional host skip, and used set).
 * @param {string} cidr
 * @param {{ initialUsed?: Set<string>, skipHost?: number }} [opts]
 */
function createPeerIpAllocator (cidr, opts = {}) {
  const { hostIp, network, broadcast } = parseSubnet(cidr)
  const used = opts.initialUsed || new Set()
  const skipHost = opts.skipHost !== false

  function allocate () {
    const net = network >>> 0
    const bc = broadcast >>> 0
    const host = hostIp >>> 0
    for (let addr = (net + 1) >>> 0; addr < bc; addr = (addr + 1) >>> 0) {
      if (skipHost && addr === host) continue
      const ip = intToIp(addr)
      if (used.has(ip)) continue
      used.add(ip)
      return ip
    }
    throw new Error('No free IPv4 address in subnet for peer alias')
  }

  function release (ip) {
    used.delete(ip)
  }

  /**
   * Take a specific host in the subnet (for pre-reserved addresses). Skips the CIDR host octet
   * when it would be the only excluded address in range (same rule as {@link #allocate}).
   * @param {string} ip
   */
  function claim (ip) {
    const ipStr = String(ip).trim()
    const addr = ipToInt(ipStr)
    const net = network >>> 0
    const bc = broadcast >>> 0
    const host = hostIp >>> 0
    if (addr <= net || addr >= bc) {
      throw new Error('claim: IP is outside subnet range')
    }
    if (skipHost && addr === host) {
      throw new Error('claim: cannot use subnet host address for peer alias')
    }
    if (used.has(ipStr)) throw new Error('claim: IP already in use')
    used.add(ipStr)
    return ipStr
  }

  return { allocate, release, claim }
}

/**
 * IPv4 addresses currently assigned on local interfaces (from Node).
 * Use this to avoid picking a TUN address that already collides on-host (e.g. two nospoon
 * processes both defaulting to 10.0.0.1/24). This does not enumerate “TUN devices” by name —
 * each process gets a new interface; the conflict is duplicate subnet / host routing.
 */
function collectAssignedIpv4Addresses () {
  const set = new Set()
  for (const infos of Object.values(os.networkInterfaces())) {
    if (!infos) continue
    for (const info of infos) {
      if (info.internal || info.family !== 'IPv4') continue
      set.add(info.address)
    }
  }
  return set
}

/**
 * First unused 10.0.n.1 in 10.0.0.0/16 (private LAN convention). Hub uses .1, default hub alias .2.
 * @param {Set<string>} assigned — host addresses to skip (e.g. from collectAssignedIpv4Addresses())
 */
function pickFreeTenDotZeroSubnet (assigned) {
  for (let n = 0; n < 256; n++) {
    const host = `10.0.${n}.1`
    if (!assigned.has(host)) {
      return { cidr: `${host}/24`, peerAlias: `10.0.${n}.2` }
    }
  }
  throw new Error('No free 10.0.x.1/24 left in 10.0.0.0/16')
}

/**
 * True if `ip` is a host address inside `cidr` (network + 1 … broadcast − 1), excluding the
 * CIDR notation host when it equals that subnet’s “.1” style anchor (same skip as peer allocators).
 * @param {string} ip
 * @param {string} cidr
 */
function ipv4InAssignableHostRange (ip, cidr) {
  const ipStr = String(ip).trim()
  const { hostIp, network, broadcast } = parseSubnet(cidr)
  const addr = ipToInt(ipStr)
  const net = network >>> 0
  const bc = broadcast >>> 0
  const host = hostIp >>> 0
  if (addr <= net || addr >= bc) return false
  if (addr === host) return false
  return true
}

/**
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
function ipv4ContainedInCidr (ip, cidr) {
  const { network, mask } = parseSubnet(cidr)
  return ((ipToInt(String(ip).trim()) & mask) >>> 0) === (network >>> 0)
}

/**
 * Lowest unused assignable host in `cidr` (excludes network, broadcast, and the CIDR host octet).
 * @param {string} cidr
 * @param {Set<string>|Iterable<string>} usedIps
 * @returns {string}
 */
function allocateLowestAvailableIpv4 (cidr, usedIps) {
  const used = usedIps instanceof Set ? usedIps : new Set(usedIps)
  const { hostIp, network, broadcast } = parseSubnet(cidr)
  const net = network >>> 0
  const bc = broadcast >>> 0
  const host = hostIp >>> 0
  for (let addr = (net + 1) >>> 0; addr < bc; addr = (addr + 1) >>> 0) {
    if (addr === host) continue
    const candidate = intToIp(addr)
    if (!used.has(candidate)) return candidate
  }
  throw new Error('No free IPv4 address in subnet')
}

module.exports = {
  ipToInt,
  intToIp,
  parseSubnet,
  createPeerIpAllocator,
  collectAssignedIpv4Addresses,
  pickFreeTenDotZeroSubnet,
  ipv4InAssignableHostRange,
  ipv4ContainedInCidr,
  allocateLowestAvailableIpv4
}
