const { execFileSync } = require('child_process')
const fs = require('fs')

const IFACE_RE = /^[a-zA-Z0-9_-]+$/
const TUNNEL_DNS = ['1.1.1.1', '8.8.8.8']

function validateInterface (name) {
  if (!IFACE_RE.test(name)) {
    throw new Error(`Invalid interface name: ${name}`)
  }
  return name
}

function run (cmd, args, opts) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf-8' }).trim()
  } catch (err) {
    const msg = err.stderr || err.message
    if (opts && opts.strict) {
      throw new Error(`${cmd} ${args.join(' ')} failed: ${msg}`)
    }
    console.error(`Command failed: ${cmd} ${args.join(' ')}`)
    console.error(msg)
    return null
  }
}

function getDefaultGateway () {
  const line = run('ip', ['route', 'show', 'default'])
  if (!line) return null

  const gwMatch = line.match(/via\s+(\S+)/)
  const devMatch = line.match(/dev\s+(\S+)/)

  return {
    gateway: gwMatch ? gwMatch[1] : null,
    device: devMatch ? devMatch[1] : null
  }
}

// Server: enable IP forwarding and NAT masquerading
function enableServerForwarding (outInterface, subnet, tunName) {
  const iface = validateInterface(outInterface || getDefaultGateway()?.device)
  if (!iface) {
    throw new Error('Cannot detect outgoing interface. Specify with --out-interface')
  }

  const tun = validateInterface(tunName || 'tun0')
  const source = subnet || '10.0.0.0/24'
  const strict = { strict: true }

  console.log(`Enabling IP forwarding and NAT on ${iface}...`)

  run('sysctl', ['-w', 'net.ipv4.ip_forward=1'], strict)
  run('iptables', ['-t', 'nat', '-A', 'POSTROUTING', '-s', source, '-o', iface, '-j', 'MASQUERADE'], strict)
  run('iptables', ['-A', 'FORWARD', '-i', tun, '-o', iface, '-j', 'ACCEPT'], strict)
  run('iptables', ['-A', 'FORWARD', '-i', iface, '-o', tun, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], strict)

  console.log('NAT enabled — clients can access the internet through this server')

  return { iface, source, tun }
}

function disableServerForwarding (natState) {
  if (!natState) return

  const { iface, source, tun } = natState
  console.log('Removing NAT rules...')
  run('iptables', ['-t', 'nat', '-D', 'POSTROUTING', '-s', source, '-o', iface, '-j', 'MASQUERADE'])
  run('iptables', ['-D', 'FORWARD', '-i', tun, '-o', iface, '-j', 'ACCEPT'])
  run('iptables', ['-D', 'FORWARD', '-i', iface, '-o', tun, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
}

// Client: route all traffic through TUN using split routes.
// Same approach as OpenVPN:
//
// 1. Save the current default gateway
// 2. Add host route for the DHT server IP via the real gateway
// 3. Add 0.0.0.0/1 and 128.0.0.0/1 via tun0
//
// The /1 routes are more specific than the default route (0.0.0.0/0),
// so they win for all traffic. But the host route (/32) is even more
// specific, so DHT traffic to the server goes direct.
//
// Kill switch: if tunnel drops, /1 routes still point to tun0 → traffic
// fails instead of leaking. The server host route stays → DHT can reconnect.
//
// Other DHT traffic (lookups to other nodes) goes through the tunnel,
// which is fine — it's just slower.
// Check if systemd-resolved is managing DNS
function hasResolvectl () {
  return run('which', ['resolvectl']) !== null
}

let savedTunName = null
let savedRemoteHosts = []
let savedGateway = null
let savedRpFilter = null
let savedResolvConf = null
let dnsMethod = null // 'resolvectl' or 'resolvconf'

function enableClientFullTunnel (remoteHost, tunName) {
  if (!remoteHost || typeof remoteHost !== 'string') {
    throw new Error('Cannot determine DHT server address for host route')
  }

  const tun = validateInterface(tunName || 'tun0')
  const strict = { strict: true }

  // Get current default gateway BEFORE we change routes
  const gw = getDefaultGateway()
  if (!gw || !gw.gateway || !gw.device) {
    throw new Error('Cannot detect default gateway')
  }

  savedTunName = tun
  savedGateway = gw

  console.log(`Routing all traffic through tunnel (server ${remoteHost} exempted via host route)`)

  // Loosen reverse path filtering
  savedRpFilter = run('sysctl', ['-n', 'net.ipv4.conf.all.rp_filter'])
  run('sysctl', ['-w', 'net.ipv4.conf.all.rp_filter=2'], strict)

  // Host route: DHT server goes via real gateway, not tunnel
  run('ip', ['route', 'add', remoteHost + '/32', 'via', gw.gateway, 'dev', gw.device], strict)
  savedRemoteHosts.push(remoteHost)

  // Split routes: cover all IPs, more specific than default 0.0.0.0/0
  run('ip', ['route', 'add', '0.0.0.0/1', 'dev', tun], strict)
  run('ip', ['route', 'add', '128.0.0.0/1', 'dev', tun], strict)

  // Switch DNS to public resolvers so queries work through the tunnel.
  // systemd-resolved: set DNS on the TUN interface (highest priority).
  // Fallback: overwrite /etc/resolv.conf directly.
  if (hasResolvectl()) {
    dnsMethod = 'resolvectl'
    run('resolvectl', ['dns', tun].concat(TUNNEL_DNS))
    run('resolvectl', ['domain', tun, '~.'])
    console.log(`DNS set via resolvectl on ${tun}: ${TUNNEL_DNS.join(', ')}`)
  } else {
    dnsMethod = 'resolvconf'
    try {
      savedResolvConf = fs.readFileSync('/etc/resolv.conf', 'utf-8')
    } catch (e) {
      savedResolvConf = null
    }
    const entries = TUNNEL_DNS.map(function (ip) { return 'nameserver ' + ip }).join('\n')
    fs.writeFileSync('/etc/resolv.conf', '# nospoon full-tunnel DNS\n' + entries + '\n')
    console.log(`DNS set via /etc/resolv.conf: ${TUNNEL_DNS.join(', ')}`)
  }

  console.log('Full tunnel active — all traffic goes through VPN (kill switch enabled)')
}

// Add a host route exemption for an additional remote host (e.g. after reconnect
// to a different relay). Called from client.js when the connection's remote
// address changes.
function addHostExemption (remoteHost) {
  if (!remoteHost || !savedGateway) return
  if (savedRemoteHosts.includes(remoteHost)) return

  const gw = savedGateway
  run('ip', ['route', 'add', remoteHost + '/32', 'via', gw.gateway, 'dev', gw.device])
  savedRemoteHosts.push(remoteHost)
  console.log(`Added host route exemption for ${remoteHost}`)
}

function disableClientFullTunnel () {
  console.log('Restoring original routes...')

  const tun = savedTunName || 'tun0'

  run('ip', ['route', 'del', '128.0.0.0/1', 'dev', tun])
  run('ip', ['route', 'del', '0.0.0.0/1', 'dev', tun])

  // Remove all host route exemptions
  if (savedGateway) {
    for (const host of savedRemoteHosts) {
      run('ip', ['route', 'del', host + '/32', 'via', savedGateway.gateway])
    }
  }

  if (savedRpFilter !== null) {
    run('sysctl', ['-w', 'net.ipv4.conf.all.rp_filter=' + savedRpFilter.trim()])
    savedRpFilter = null
  }

  // Restore DNS
  if (dnsMethod === 'resolvectl') {
    run('resolvectl', ['revert', savedTunName || 'tun0'])
    console.log('DNS restored via resolvectl')
  } else if (dnsMethod === 'resolvconf' && savedResolvConf !== null) {
    fs.writeFileSync('/etc/resolv.conf', savedResolvConf)
    console.log('DNS restored via /etc/resolv.conf')
  }
  dnsMethod = null
  savedResolvConf = null

  savedTunName = null
  savedRemoteHosts = []
  savedGateway = null
}

module.exports = {
  enableServerForwarding,
  disableServerForwarding,
  enableClientFullTunnel,
  addHostExemption,
  disableClientFullTunnel
}
