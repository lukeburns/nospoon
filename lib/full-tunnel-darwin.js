const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const IFACE_RE = /^[a-zA-Z0-9_-]+$/

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
  const output = run('route', ['-n', 'get', 'default'])
  if (!output) return null

  const gwMatch = output.match(/gateway:\s*(\S+)/)
  const devMatch = output.match(/interface:\s*(\S+)/)

  return {
    gateway: gwMatch ? gwMatch[1] : null,
    device: devMatch ? devMatch[1] : null
  }
}

// Server: enable IP forwarding and NAT via pfctl
function enableServerForwarding (outInterface, subnet, tunName) {
  const iface = validateInterface(outInterface || getDefaultGateway()?.device)
  if (!iface) {
    throw new Error('Cannot detect outgoing interface. Specify with --out-interface')
  }

  const tun = validateInterface(tunName || 'utun0')
  const source = subnet || '10.0.0.0/24'
  const strict = { strict: true }

  console.log(`Enabling IP forwarding and NAT on ${iface}...`)

  run('sysctl', ['-w', 'net.inet.ip.forwarding=1'], strict)

  // Write pf NAT rules to a temp file and load them into a named anchor
  const rules = `nat on ${iface} from ${source} to any -> (${iface})\n`
  const rulesPath = path.join(os.tmpdir(), 'nospoon-nat.conf')
  fs.writeFileSync(rulesPath, rules)

  run('pfctl', ['-a', 'nospoon', '-f', rulesPath], strict)
  run('pfctl', ['-e'], { strict: false }) // enable pf (may already be enabled)

  try { fs.unlinkSync(rulesPath) } catch (e) {}

  console.log('NAT enabled — clients can access the internet through this server')

  return { iface, source, tun }
}

function disableServerForwarding (natState) {
  if (!natState) return

  console.log('Removing NAT rules...')
  run('pfctl', ['-a', 'nospoon', '-F', 'all'])
}

// Client: route all traffic through TUN using split routes.
// Same approach as Linux — 0.0.0.0/1 + 128.0.0.0/1 + host exemption.
let savedTunName = null
let savedRemoteHosts = []
let savedGateway = null

function enableClientFullTunnel (remoteHost, tunName) {
  if (!remoteHost || typeof remoteHost !== 'string') {
    throw new Error('Cannot determine DHT server address for host route')
  }

  const tun = validateInterface(tunName || 'utun0')
  const strict = { strict: true }

  const gw = getDefaultGateway()
  if (!gw || !gw.gateway || !gw.device) {
    throw new Error('Cannot detect default gateway')
  }

  savedTunName = tun
  savedGateway = gw

  console.log(`Routing all traffic through tunnel (server ${remoteHost} exempted via host route)`)

  // Host route: DHT server goes via real gateway
  run('route', ['add', '-host', remoteHost, gw.gateway], strict)
  savedRemoteHosts.push(remoteHost)

  // Split routes via TUN
  run('route', ['add', '-net', '0.0.0.0/1', '-interface', tun], strict)
  run('route', ['add', '-net', '128.0.0.0/1', '-interface', tun], strict)

  console.log('Full tunnel active — all traffic goes through VPN (kill switch enabled)')
}

function addHostExemption (remoteHost) {
  if (!remoteHost || !savedGateway) return
  if (savedRemoteHosts.includes(remoteHost)) return

  run('route', ['add', '-host', remoteHost, savedGateway.gateway])
  savedRemoteHosts.push(remoteHost)
  console.log(`Added host route exemption for ${remoteHost}`)
}

function disableClientFullTunnel () {
  console.log('Restoring original routes...')

  const tun = savedTunName || 'utun0'

  run('route', ['delete', '-net', '128.0.0.0/1', '-interface', tun])
  run('route', ['delete', '-net', '0.0.0.0/1', '-interface', tun])

  if (savedGateway) {
    for (const host of savedRemoteHosts) {
      run('route', ['delete', '-host', host, savedGateway.gateway])
    }
  }

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
