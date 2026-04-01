#!/usr/bin/env node
/**
 * Run `nospoon web` on --port and Vite (HMR) on port+1, with /api proxied to the control server.
 *
 * HTTP binds before TUN: the control server listens first, then brings up Hyperswarm + primary TUN.
 * Starts Vite only after the control port accepts connections (avoids ECONNREFUSED races).
 * Use sudo if utun/TUN creation requires it.
 *
 * Flags: --port / -p, --host / --address (bind for both nospoon web and Vite; default 127.0.0.1).
 * For --host 0.0.0.0 the proxy and readiness probe use 127.0.0.1 (same machine).
 *
 * Same TCP port for both is not practical with two separate processes; serving HMR from the
 * control server would require Vite middleware mode inside Node (possible, larger refactor).
 */
import { spawn } from 'node:child_process'
import net from 'node:net'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const cli = join(root, 'bin', 'cli.js')
const viteBin = join(root, 'node_modules', 'vite', 'bin', 'vite.js')

/** Hostname to open in browser / proxy target when control binds all interfaces. */
function connectHost (bindHost) {
  const h = String(bindHost || '').trim()
  if (h === '0.0.0.0' || h === '::') return '127.0.0.1'
  return h
}

function parseDevArgs (argv) {
  let port = 8790
  let host = '127.0.0.1'
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--port' || a === '-p') {
      const v = parseInt(argv[++i], 10)
      if (!Number.isFinite(v) || v < 1 || v > 65535) {
        console.error('dev: --port must be 1–65535')
        process.exit(1)
      }
      port = v
    } else if (a.startsWith('--port=')) {
      const v = parseInt(a.slice('--port='.length), 10)
      if (!Number.isFinite(v) || v < 1 || v > 65535) {
        console.error('dev: --port must be 1–65535')
        process.exit(1)
      }
      port = v
    } else if (a === '--host' || a === '--address') {
      const v = argv[++i]
      if (v == null || v === '' || v.startsWith('-')) {
        console.error('dev: --host / --address requires a value')
        process.exit(1)
      }
      host = v
    } else if (a.startsWith('--host=')) {
      host = a.slice('--host='.length)
    } else if (a.startsWith('--address=')) {
      host = a.slice('--address='.length)
    }
  }
  host = String(host).trim()
  if (!host) {
    console.error('dev: empty --host / --address')
    process.exit(1)
  }
  if (port >= 65535) {
    console.error('dev: --port must be at most 65534 (need port+1 for Vite)')
    process.exit(1)
  }
  return { port, host }
}

function waitForListen (port, probeHost, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs
  return new Promise((resolve, reject) => {
    function attempt () {
      const s = net.connect({ port, host: probeHost }, () => {
        s.end()
        resolve()
      })
      s.on('error', () => {
        s.destroy()
        if (Date.now() >= deadline) {
          reject(
            new Error(
              `dev: timed out waiting for ${probeHost}:${port} (did nospoon web fail to bind?)`
            )
          )
        } else {
          setTimeout(attempt, 50)
        }
      })
    }
    attempt()
  })
}

const { port, host } = parseDevArgs(process.argv)
const vitePort = port + 1
const probeHost = connectHost(host)
const displayUrlHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host

process.env.NOSPOON_WEB_PROXY_TARGET = `http://${probeHost}:${port}`
process.env.NOSPOON_WEB_VITE_PORT = String(vitePort)
process.env.NOSPOON_WEB_VITE_HOST = host

const children = []

function shutdown () {
  for (const c of children) {
    try {
      if (c.pid) c.kill('SIGTERM')
    } catch (_) {}
  }
}

process.on('SIGINT', () => {
  shutdown()
  process.exit(0)
})
process.on('SIGTERM', () => {
  shutdown()
  process.exit(0)
})

console.log('')
console.log(`nospoon web (API + bundled UI)  http://${displayUrlHost}:${port}/`)
if (host === '0.0.0.0' || host === '::') {
  console.log('  (listening on all interfaces; use the URL above from this machine)')
}
console.log(`Vite (hot reload)               http://${displayUrlHost}:${vitePort}/`)
console.log('  (use sudo if TUN creation fails; HTTP is up before primary interface finishes starting)')
console.log('')

const nospoon = spawn(process.execPath, [cli, 'web', '--host', host, '--port', String(port)], {
  cwd: root,
  stdio: 'inherit',
  env: process.env
})
children.push(nospoon)

function onChildExit (name, code, signal) {
  if (signal) {
    console.error(`dev: ${name} exited (${signal})`)
  } else if (code !== 0 && code !== null) {
    console.error(`dev: ${name} exited with code ${code}`)
  }
  shutdown()
  process.exit(code ?? 1)
}

let rejectEarlyExit
const nospoonExitBeforeListen = new Promise((_, reject) => {
  rejectEarlyExit = reject
})
function onEarlyNospoonExit (code, signal) {
  rejectEarlyExit(
    new Error(
      `nospoon web exited before listening (code ${code ?? 'null'}, signal ${signal ?? 'null'})`
    )
  )
}
nospoon.once('exit', onEarlyNospoonExit)

try {
  await Promise.race([waitForListen(port, probeHost), nospoonExitBeforeListen])
} catch (e) {
  console.error(e.message || e)
  shutdown()
  process.exit(1)
} finally {
  nospoon.removeListener('exit', onEarlyNospoonExit)
}

const vite = spawn(process.execPath, [viteBin, '--config', 'web/vite.config.mjs'], {
  cwd: root,
  stdio: 'inherit',
  env: process.env
})
children.push(vite)

nospoon.on('exit', (code, signal) => onChildExit('nospoon web', code, signal))
vite.on('exit', (code, signal) => onChildExit('vite', code, signal))
