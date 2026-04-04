#!/usr/bin/env node

const net = require('net')
const { startServer } = require('../lib/server')
const { startClient } = require('../lib/client')
const { startSwarmMesh } = require('../lib/swarm-mesh')
const { collectAssignedIpv4Addresses, pickFreeTenDotZeroSubnet } = require('../lib/ip-subnet')
const { parse32Bytes, toHex32, encodeZ32 } = require('../lib/key-encoding')

const args = process.argv.slice(2)

/** Subcommands; anything else starting with `-` is treated as flags for the default (control plane). */
const SUBCOMMANDS = new Set(['server', 'client', 'swarm', 'genkey', 'web', 'control'])

const CIDR_V4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/

/** Normalize to lowercase hex for internal use (server/client libs). */
function parsePublicKeyArg (value, label) {
  return toHex32(parse32Bytes(value, label)).toLowerCase()
}

function parseSeedArg (value, label) {
  return toHex32(parse32Bytes(value, label))
}

function validatePeerIpv4 (value, label) {
  if (!net.isIPv4(value)) {
    console.error(`Error: ${label} must be a valid IPv4 host address (e.g. 10.0.0.1)`)
    process.exit(1)
  }
  return value
}

function validateCidr (value, label) {
  if (!CIDR_V4_RE.test(value)) {
    console.error(`Error: ${label} must be in CIDR format (e.g. 10.0.0.1/24)`)
    process.exit(1)
  }
  const [ip, prefix] = value.split('/')
  const octets = ip.split('.').map(Number)
  const pfx = parseInt(prefix, 10)
  if (octets.some(function (o) { return o > 255 }) || pfx > 32) {
    console.error(`Error: ${label} has invalid IP octets or prefix length`)
    process.exit(1)
  }
  return value
}

function validateCidrV6 (value, label) {
  const parts = value.split('/')
  if (parts.length !== 2) {
    console.error(`Error: ${label} must be in CIDR format (e.g. fd00::1/64)`)
    process.exit(1)
  }
  const prefix = parseInt(parts[1], 10)
  if (!net.isIPv6(parts[0]) || isNaN(prefix) || prefix < 1 || prefix > 128) {
    console.error(`Error: ${label} must be a valid IPv6 CIDR (e.g. fd00::1/64)`)
    process.exit(1)
  }
  return value
}

function validateMtu (value) {
  const mtu = parseInt(value, 10)
  if (isNaN(mtu) || mtu < 576 || mtu > 65535) {
    console.error('Error: MTU must be between 576 and 65535')
    process.exit(1)
  }
  return mtu
}

function parseWebFlags (args) {
  const flags = { port: 80, primaryCidr: null }
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--help' || args[i] === '-h') {
      printUsage()
      process.exit(0)
    }
    if (args[i] === '--port' && args[i + 1]) {
      const p = parseInt(args[++i], 10)
      if (isNaN(p) || p < 1 || p > 65535) {
        console.error('Error: --port must be 1-65535')
        process.exit(1)
      }
      flags.port = p
    } else if (args[i] === '--host' && args[i + 1]) {
      flags.host = args[++i]
    } else if (args[i] === '--primary-cidr' && args[i + 1]) {
      flags.primaryCidr = validateCidr(args[++i], '--primary-cidr')
    } else if (args[i].startsWith('--')) {
      console.error(`Error: unknown web option: ${args[i]}`)
      process.exit(1)
    }
  }
  return flags
}

function parseFlags (args) {
  const flags = {}
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ip' && args[i + 1]) {
      flags.ip = validateCidr(args[++i], '--ip')
    } else if (args[i] === '--seed' && args[i + 1]) {
      try {
        flags.seed = parseSeedArg(args[++i], '--seed')
      } catch (e) {
        console.error('Error:', e.message)
        process.exit(1)
      }
    } else if (args[i] === '--mtu' && args[i + 1]) {
      flags.mtu = validateMtu(args[++i])
    } else if (args[i] === '--config' && args[i + 1]) {
      flags.config = args[++i]
    } else if (args[i] === '--ipv6' && args[i + 1]) {
      flags.ipv6 = validateCidrV6(args[++i], '--ipv6')
    } else if (args[i] === '--peer-ip' && args[i + 1]) {
      flags.peerIp = validatePeerIpv4(args[++i], '--peer-ip')
      flags.peerIpExplicit = true
    } else if (args[i] === '--full-tunnel') {
      flags.fullTunnel = true
    } else if (args[i] === '--out-interface' && args[i + 1]) {
      flags.outInterface = args[++i]
    }
  }
  return flags
}

/**
 * Default: first free 10.0.x.1/24 from local interface addresses (avoids clashes between
 * multiple nospoon processes on one host). Override with --ip <cidr>.
 * Server + --config: keep implicit 10.0.0.1/24 (peers.json IPs are fixed to that subnet unless --ip).
 */
function applyIpv4AutoUnlessExplicit (flags, opts) {
  const isClient = opts && opts.isClient
  if (flags.ip) return
  if (flags.config) return
  if (isClient && flags.peerIpExplicit) {
    console.error('Error: --peer-ip requires --ip (set an explicit subnet)')
    process.exit(1)
  }
  const assigned = collectAssignedIpv4Addresses()
  let picked
  try {
    picked = pickFreeTenDotZeroSubnet(assigned)
  } catch (e) {
    console.error('Error:', e.message)
    process.exit(1)
  }
  flags.ip = picked.cidr
  if (isClient) {
    flags.peerIp = picked.peerAlias
    console.log(`Auto IP: using ${flags.ip}, hub alias ${flags.peerIp}`)
  } else {
    console.log(`Auto IP: using ${flags.ip}`)
  }
}

/** Server: options first, then zero or more peer public keys (firewall + incremental aliases). */
function parseServerArgs (args) {
  const flags = {}
  let i = 0
  while (i < args.length) {
    const a = args[i]
    if (a === '--ip' && args[i + 1]) {
      flags.ip = validateCidr(args[++i], '--ip')
    } else if (a === '--seed' && args[i + 1]) {
      try {
        flags.seed = parseSeedArg(args[++i], '--seed')
      } catch (e) {
        console.error('Error:', e.message)
        process.exit(1)
      }
    } else if (a === '--mtu' && args[i + 1]) {
      flags.mtu = validateMtu(args[++i])
    } else if (a === '--config' && args[i + 1]) {
      flags.config = args[++i]
    } else if (a === '--ipv6' && args[i + 1]) {
      flags.ipv6 = validateCidrV6(args[++i], '--ipv6')
    } else if (a === '--full-tunnel') {
      flags.fullTunnel = true
    } else if (a === '--out-interface' && args[i + 1]) {
      flags.outInterface = args[++i]
    } else if (a.startsWith('--')) {
      console.error(`Error: unknown server option: ${a}`)
      process.exit(1)
    } else {
      break
    }
    i++
  }

  const seen = new Set()
  const keys = []
  while (i < args.length) {
    if (args[i].startsWith('--')) {
      console.error('Error: server options must come before peer public keys')
      process.exit(1)
    }
    let k
    try {
      k = parsePublicKeyArg(args[i], `peer key ${keys.length + 1}`)
    } catch (e) {
      console.error('Error:', e.message)
      process.exit(1)
    }
    if (seen.has(k)) {
      console.warn(`Warning: duplicate peer key ignored (${encodeZ32(Buffer.from(k, 'hex')).slice(0, 8)}…)`)
    } else {
      seen.add(k)
      keys.push(k)
    }
    i++
  }

  return { flags, keys }
}

/** Swarm: options only (topic is positional before flags). */
function parseSwarmFlags (args) {
  const flags = {}
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ip' && args[i + 1]) {
      flags.ip = validateCidr(args[++i], '--ip')
    } else if (args[i] === '--seed' && args[i + 1]) {
      try {
        flags.seed = parseSeedArg(args[++i], '--seed')
      } catch (e) {
        console.error('Error:', e.message)
        process.exit(1)
      }
    } else if (args[i] === '--mtu' && args[i + 1]) {
      flags.mtu = validateMtu(args[++i])
    } else if (args[i] === '--ipv6' && args[i + 1]) {
      flags.ipv6 = validateCidrV6(args[++i], '--ipv6')
    } else if (args[i].startsWith('--')) {
      console.error(`Error: unknown swarm option: ${args[i]}`)
      process.exit(1)
    }
  }
  return flags
}

function printUsage () {
  console.log(`
nospoon - P2P VPN over HyperDHT

Usage:
  nospoon [options]                       HTTP control plane (default): join/leave topics & direct peers
  nospoon server [options] [<key> ...]   Start a VPN server (optional peer key allowlist)
  nospoon client <key> [options]          Connect to a VPN server
  nospoon swarm <topic> [options]        Hyperswarm topic mesh (pairwise; topic = capability)
  nospoon genkey                          Generate a client seed + public key

  \`web\` / \`control\` are aliases for the default command. Use \`--help\` for this message.

Keys and seeds use z32 encoding (32-byte values). 64-character hex is still accepted.

Server options (must come before any positional keys):
  --ip <cidr>           TUN IPv4 (default: first free 10.0.x.1/24 on this host; use --ip to fix 10.0.0.1/24 etc.)
  --ipv6 <cidr>         TUN IPv6 address (e.g. fd00::1/64)
  --seed <z32|hex>      Seed for deterministic server key
  --config <path>       Path to peers.json (fixed IP per key; raw IPv4 wire). Not with positional keys.
  --mtu <num>           MTU size (default: 1400)
  --full-tunnel         Enable NAT so clients can access the internet
  --out-interface <if>  Outgoing interface for NAT (default: auto-detect)

  Positional <key> ...  Remote client public keys allowed to connect (firewall). Server auto-assigns
                          aliases .2, .3, … in the --ip subnet (key-address on IPv4 wire). Omit for open mode.

Client options:
  --ip <cidr>           TUN IPv4 (default: first free 10.0.x.1/24 and matching hub alias 10.0.x.2; use --ip to fix)
  --peer-ip <addr>      Local alias for the peer’s key (default: 10.0.x.2 with auto subnet; requires --ip if set)
  --ipv6 <cidr>         TUN IPv6 address (e.g. fd00::2/64)
  --seed <z32|hex>      Client seed (for authenticated mode)
  --mtu <num>           MTU size (default: 1400)
  --full-tunnel         Route all internet traffic through the VPN

Swarm options:
  --ip <cidr>           TUN IPv4 (default: first free 10.0.x.1/24; use --ip to fix)
  --ipv6 <cidr>         TUN IPv6 (e.g. fd00::1/64)
  --seed <z32|hex>      Deterministic swarm identity
  --mtu <num>           MTU (default: 1400)

Control plane (sudo for TUN when joining topics or peers):
  --port <num>          HTTP port (default: 80)
  --host <addr>         Bind address (default: auto loopback alias; DNS name nospoon when mesh DNS is on)
  --primary-cidr <c>    Fixed primary (direct pool) IPv4 CIDR instead of auto 10.0.x.1/24

  From the repo, \`npm run dev\` runs the control server plus Vite (see scripts/dev-web.mjs).

Examples:
  # Authenticated mode (recommended)
  nospoon genkey                        # generate client identity (z32)
  sudo nospoon server --config peers.json
  sudo nospoon client <server-z32> --seed <client-seed-z32>

  # Full tunnel (use as internet VPN)
  sudo nospoon server --full-tunnel --config peers.json
  sudo nospoon client <server-z32> --seed <seed-z32> --full-tunnel

  # Allowlist hub (only these client keys; incremental aliases like open mode)
  sudo nospoon server <client-a-z32> <client-b-z32>

  # Open mode (any client; server assigns aliases .2, .3, …)
  sudo nospoon server
  sudo nospoon client <hub-public-key-z32>

peers.json format (keys may be z32 or 64 hex):
  {
    "peers": {
      "<client-public-key>": "10.0.0.2",
      "<client-public-key>": "10.0.0.3"
    }
  }
`)
}

async function runControlPlane (webArgv) {
  const { startControlHttpServer } = require('../lib/control-http')
  const flags = parseWebFlags(webArgv)
  const opts = {
    port: flags.port,
    primaryCidr: flags.primaryCidr
  }
  if (flags.host != null) opts.host = flags.host
  const { sessions, closeHttpServer, controlPanelBaseUrl, keyLinkUrl } =
    await startControlHttpServer(opts)
  console.log('')
  console.log(`running on: ${controlPanelBaseUrl}`)
  console.log(`key link: ${keyLinkUrl}`)
  console.log('')
  let exiting = false
  function shutdown () {
    if (exiting) {
      console.log('\nForce exit.')
      process.exit(0)
    }
    exiting = true
    console.log('\nShutting down...')
    const forceTimer = setTimeout(function () {
      console.error('Shutdown timed out; forcing exit.')
      process.exit(1)
    }, 15000)
    closeHttpServer()
      .then(function () {
        return sessions.destroy()
      })
      .then(function () {
        clearTimeout(forceTimer)
        process.exit(0)
      })
      .catch(function (err) {
        clearTimeout(forceTimer)
        if (err && err.message) console.error(err.message)
        process.exit(1)
      })
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

async function main () {
  if (args[0] === '--help' || args[0] === '-h') {
    printUsage()
    process.exit(0)
  }

  const first = args[0]
  const defaultControl =
    args.length === 0 ||
    first === 'web' ||
    first === 'control' ||
    (first && first.startsWith('-') && !SUBCOMMANDS.has(first))
  if (defaultControl) {
    const webArgv =
      args.length === 0 || first === 'web' || first === 'control'
        ? args.slice(first === 'web' || first === 'control' ? 1 : 0)
        : args
    await runControlPlane(webArgv)
    return
  }

  const command = first

  if (command === 'genkey') {
    const crypto = require('crypto')
    const HyperDHT = require('hyperdht')
    const seed = crypto.randomBytes(32)
    const keyPair = HyperDHT.keyPair(seed)
    console.log('Seed (keep secret):  ', encodeZ32(seed))
    console.log('Public key (share):  ', encodeZ32(keyPair.publicKey))
    process.exit(0)
  }

  if (command === 'server') {
    const { flags, keys } = parseServerArgs(args.slice(1))
    if (flags.config && keys.length) {
      console.error('Error: do not combine --config with positional peer keys')
      process.exit(1)
    }
    flags.allowedKeys = keys
    applyIpv4AutoUnlessExplicit(flags, { isClient: false })
    await startServer(flags)
  } else if (command === 'client') {
    const key = args[1]
    if (!key) {
      console.error('Error: server public key required')
      console.error('Usage: nospoon client <server-public-key>')
      process.exit(1)
    }
    let keyHex
    try {
      keyHex = parsePublicKeyArg(key, 'public key')
    } catch (e) {
      console.error('Error:', e.message)
      process.exit(1)
    }
    const flags = parseFlags(args.slice(2))
    flags.key = keyHex
    applyIpv4AutoUnlessExplicit(flags, { isClient: true })
    await startClient(flags)
  } else if (command === 'swarm') {
    const topic = args[1]
    if (!topic || topic.startsWith('--')) {
      console.error('Error: topic string required (e.g. nospoon swarm my-lan-name)')
      process.exit(1)
    }
    const flags = parseSwarmFlags(args.slice(2))
    applyIpv4AutoUnlessExplicit(flags, { isClient: false })
    await startSwarmMesh({ topic, ...flags })
  } else {
    console.error(`Unknown command: ${command}`)
    printUsage()
    process.exit(1)
  }
}

main().catch(function (err) {
  console.error('Fatal:', err.message)
  process.exit(1)
})
