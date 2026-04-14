#!/usr/bin/env node

const { parse32Bytes, toHex32, encodeZ32 } = require('../lib/wire/key-encoding')

const args = process.argv.slice(2)

/** Subcommands; anything else starting with `-` is treated as flags for the default (control plane). */
const SUBCOMMANDS = new Set(['genkey', 'web', 'control'])

const CIDR_V4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/

function parseSeedArg (value, label) {
  return toHex32(parse32Bytes(value, label))
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
    } else if (args[i] === '--seed' && args[i + 1]) {
      try {
        flags.seed = parseSeedArg(args[++i], '--seed')
      } catch (e) {
        console.error('Error:', e.message)
        process.exit(1)
      }
    } else if (args[i] === '--no-system-dns') {
      flags.noSystemDns = true
    } else if (args[i] === '--darwin-system-dns') {
      /* legacy no-op: system DNS override is on by default */
    } else if (args[i].startsWith('--')) {
      console.error(`Error: unknown web option: ${args[i]}`)
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
  nospoon genkey                          Generate a random Noise seed + public key (z32)

  \`web\` / \`control\` are aliases for the default command. Use \`--help\` for this message.

Keys and seeds use z32 encoding (32-byte values). 64-character hex is still accepted.

Control plane (sudo for TUN when joining topics or peers):
  --port <num>          HTTP port (default: 80)
  --host <addr>         Bind address (default: auto loopback alias; DNS name nospoon when mesh DNS is on)
  --primary-cidr <c>    Fixed primary (direct pool) IPv4 CIDR instead of auto 10.0.x.1/24
  --seed <z32|hex>      Control-plane Noise seed (default: load or create ~/.nospoon/identity.json)
  --no-system-dns       Do not change OS DNS / search domains (default is 127.0.0.1 while mesh DNS runs on :53)
                          (or set env NOSPOON_SYSTEM_DNS=0; legacy: NOSPOON_DARWIN_SYSTEM_DNS=0)

  From the repo, \`npm run dev\` runs the control server plus Vite (see scripts/dev-web.mjs).

Examples:
  nospoon genkey
  sudo nospoon --port 8080
`)
}

async function runControlPlane (webArgv) {
  const { startControlHttpServer } = require('../lib/control/control-http')
  const flags = parseWebFlags(webArgv)
  const opts = {
    port: flags.port,
    primaryCidr: flags.primaryCidr
  }
  if (flags.host != null) opts.host = flags.host
  if (flags.seed != null) opts.clientSeedHex = flags.seed
  if (flags.noSystemDns) opts.systemDnsOverride = false
  const { sessions, closeHttpServer, controlPanelRunningOnDisplay, keyLinkDisplay } =
    await startControlHttpServer(opts)
  console.log('')
  console.log(`running on: ${controlPanelRunningOnDisplay}`)
  console.log(`key link: ${keyLinkDisplay}`)
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

  console.error(`Unknown command: ${command}`)
  printUsage()
  process.exit(1)
}

main().catch(function (err) {
  console.error('Fatal:', err.message)
  process.exit(1)
})
