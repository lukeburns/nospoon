#!/usr/bin/env node

const net = require('net')
const { startServer } = require('../lib/server')
const { startClient } = require('../lib/client')

const args = process.argv.slice(2)
const command = args[0]

const HEX_RE = /^[0-9a-fA-F]{64}$/
const CIDR_V4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/

function validateHex64 (value, label) {
  if (!HEX_RE.test(value)) {
    console.error(`Error: ${label} must be exactly 64 hex characters`)
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

function parseFlags (args) {
  const flags = {}
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ip' && args[i + 1]) {
      flags.ip = validateCidr(args[++i], '--ip')
    } else if (args[i] === '--seed' && args[i + 1]) {
      flags.seed = validateHex64(args[++i], '--seed')
    } else if (args[i] === '--mtu' && args[i + 1]) {
      flags.mtu = validateMtu(args[++i])
    } else if (args[i] === '--config' && args[i + 1]) {
      flags.config = args[++i]
    } else if (args[i] === '--ipv6' && args[i + 1]) {
      flags.ipv6 = validateCidrV6(args[++i], '--ipv6')
    } else if (args[i] === '--full-tunnel') {
      flags.fullTunnel = true
    } else if (args[i] === '--out-interface' && args[i + 1]) {
      flags.outInterface = args[++i]
    }
  }
  return flags
}

function printUsage () {
  console.log(`
nospoon - P2P VPN over HyperDHT

Usage:
  nospoon server [options]           Start a VPN server
  nospoon client <key> [options]     Connect to a VPN server
  nospoon genkey                     Generate a client seed + public key

Server options:
  --ip <cidr>           TUN IPv4 address (default: 10.0.0.1/24)
  --ipv6 <cidr>         TUN IPv6 address (e.g. fd00::1/64)
  --seed <hex>          64-char hex seed for deterministic server key
  --config <path>       Path to peers.json for client authentication
  --mtu <num>           MTU size (default: 1400)
  --full-tunnel         Enable NAT so clients can access the internet
  --out-interface <if>  Outgoing interface for NAT (default: auto-detect)

Client options:
  --ip <cidr>           TUN IPv4 address (default: 10.0.0.2/24)
  --ipv6 <cidr>         TUN IPv6 address (e.g. fd00::2/64)
  --seed <hex>          64-char hex client seed (for authenticated mode)
  --mtu <num>           MTU size (default: 1400)
  --full-tunnel         Route all internet traffic through the VPN

Examples:
  # Authenticated mode (recommended)
  nospoon genkey                        # generate client identity
  sudo nospoon server --config peers.json
  sudo nospoon client <server-key> --seed <client-seed>

  # Full tunnel (use as internet VPN)
  sudo nospoon server --full-tunnel --config peers.json
  sudo nospoon client <server-key> --seed <seed> --full-tunnel

  # Open mode (testing only — no IP assignment, no authentication)
  sudo nospoon server
  sudo nospoon client <public-key>

peers.json format:
  {
    "peers": {
      "<client-public-key>": "10.0.0.2",
      "<client-public-key>": "10.0.0.3"
    }
  }
`)
}

async function main () {
  if (!command || command === '--help' || command === '-h') {
    printUsage()
    process.exit(0)
  }

  if (command === 'genkey') {
    const crypto = require('crypto')
    const HyperDHT = require('hyperdht')
    const seed = crypto.randomBytes(32)
    const keyPair = HyperDHT.keyPair(seed)
    console.log('Seed (keep secret):  ', seed.toString('hex'))
    console.log('Public key (share):  ', keyPair.publicKey.toString('hex'))
    process.exit(0)
  }

  if (command === 'server') {
    const flags = parseFlags(args.slice(1))
    await startServer(flags)
  } else if (command === 'client') {
    const key = args[1]
    if (!key) {
      console.error('Error: server public key required')
      console.error('Usage: nospoon client <server-public-key-hex>')
      process.exit(1)
    }
    validateHex64(key, 'public key')
    const flags = parseFlags(args.slice(2))
    flags.key = key
    await startClient(flags)
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
