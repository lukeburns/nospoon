'use strict'

const fs = require('fs')
const path = require('path')
const { ProxyAgent } = require('undici')

const root = path.join(__dirname, '..')
const srcDir = path.join(root, 'node_modules', 'v86', 'build')
const destDir = path.join(root, 'lib', 'v86')
const guestDir = path.join(destDir, 'guest')
const freebsdDir = path.join(guestDir, 'freebsd')

/** Same as copy.sh FreeBSD profile / web/v86-hello-demo.mjs */
const FREEBSD_DISK_BYTES = 2147483648
const FREEBSD_CHUNK = 1048576
const FREEBSD_CHUNK_COUNT = FREEBSD_DISK_BYTES / FREEBSD_CHUNK
/** Override to mirror (trailing slash optional): `FREEBSD_CHUNK_BASE=https://internal/freebsd/` */
const FREEBSD_CHUNK_BASE = String(
  process.env.FREEBSD_CHUNK_BASE || 'https://i.copy.sh/freebsd/'
).replace(/\/?$/, '/')
const FREEBSD_STATE_URL =
  process.env.FREEBSD_STATE_URL || 'https://i.copy.sh/freebsd_state-v2.bin.zst'
const FREEBSD_STATE_FILE = 'freebsd_state-v2.bin.zst'

/** Node’s global fetch does not use HTTPS_PROXY; wire Undici when set. */
let _proxyDispatcher = null
function fetchInit () {
  const proxy = (
    process.env.HTTPS_PROXY ||
    process.env.HTTP_PROXY ||
    process.env.https_proxy ||
    process.env.http_proxy ||
    ''
  ).trim()
  if (!proxy) return { redirect: 'follow' }
  if (!_proxyDispatcher) _proxyDispatcher = new ProxyAgent(proxy)
  return { redirect: 'follow', dispatcher: _proxyDispatcher }
}

function describeFetchError (err, url) {
  const parts = []
  let c = err
  let depth = 0
  while (c && depth < 8) {
    if (c.message) parts.push(c.message)
    c = c.cause
    depth++
  }
  if (!parts.length) parts.push(String(err))
  return parts.join(' — ') + ' (' + url + ')'
}

/** Fetched at build/install time so the browser loads guest firmware from the control panel (no cross-origin fetch). */
const GUEST_URLS = [
  {
    url: 'https://copy.sh/v86/bios/seabios.bin',
    file: 'seabios.bin',
    minBytes: 1
  },
  {
    url: 'https://copy.sh/v86/bios/vgabios.bin',
    file: 'vgabios.bin',
    minBytes: 1
  }
]

function argvHasFlag (name) {
  return process.argv.indexOf(name) !== -1
}

async function fetchToFile (url, dest, label) {
  const maxAttempts = Number(process.env.COPY_V86_FETCH_ATTEMPTS || 5) || 5
  const init = fetchInit()
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, init)
      if (!res.ok) {
        if (res.status >= 500 && attempt < maxAttempts) {
          await new Promise(function (r) {
            setTimeout(r, Math.min(8000, 400 * Math.pow(2, attempt - 1)))
          })
          continue
        }
        throw new Error(`${label}: HTTP ${res.status}`)
      }
      const buf = Buffer.from(await res.arrayBuffer())
      fs.mkdirSync(path.dirname(dest), { recursive: true })
      fs.writeFileSync(dest, buf)
      return buf.length
    } catch (e) {
      if (attempt < maxAttempts) {
        await new Promise(function (r) {
          setTimeout(r, Math.min(8000, 400 * Math.pow(2, attempt - 1)))
        })
        continue
      }
      throw new Error(describeFetchError(e, url))
    }
  }
}

function writeFreebsdMeta () {
  const statePath = path.join(guestDir, FREEBSD_STATE_FILE)
  let stateZstBytes = 0
  if (fs.existsSync(statePath)) {
    stateZstBytes = fs.statSync(statePath).size
  }
  let diskChunkFiles = 0
  if (fs.existsSync(freebsdDir)) {
    diskChunkFiles = fs
      .readdirSync(freebsdDir)
      .filter(function (f) {
        return /^\d+-\d+\.img$/.test(f)
      }).length
  }
  const meta = {
    stateZstBytes,
    diskBytes: FREEBSD_DISK_BYTES,
    chunkSize: FREEBSD_CHUNK,
    chunkCount: FREEBSD_CHUNK_COUNT,
    diskChunksPresent: diskChunkFiles === FREEBSD_CHUNK_COUNT,
    statePresent: stateZstBytes > 0
  }
  fs.writeFileSync(
    path.join(guestDir, 'freebsd-meta.json'),
    JSON.stringify(meta, null, 2) + '\n'
  )
}

async function ensureFreebsdStateZst () {
  const dest = path.join(guestDir, FREEBSD_STATE_FILE)
  if (fs.existsSync(dest)) {
    const st = fs.statSync(dest)
    if (st.size > 1_000_000) return
    try {
      fs.unlinkSync(dest)
    } catch (_) {}
  }
  const n = await fetchToFile(FREEBSD_STATE_URL, dest, FREEBSD_STATE_FILE)
  console.log('copy-v86-assets: wrote', path.relative(root, dest), `(${n} bytes)`)
}

async function ensureFreebsdDiskChunks () {
  fs.mkdirSync(freebsdDir, { recursive: true })
  const concurrency = 8
  let next = 0

  async function downloadOne (idx) {
    const byteStart = idx * FREEBSD_CHUNK
    const byteEnd = byteStart + FREEBSD_CHUNK
    const name = byteStart + '-' + byteEnd + '.img'
    const dest = path.join(freebsdDir, name)
    if (fs.existsSync(dest)) {
      const st = fs.statSync(dest)
      if (st.size >= FREEBSD_CHUNK) return
      try {
        fs.unlinkSync(dest)
      } catch (_) {}
    }
    const url = FREEBSD_CHUNK_BASE + name
    const n = await fetchToFile(url, dest, name)
    if (n < FREEBSD_CHUNK) {
      throw new Error(`${name}: short file (${n} < ${FREEBSD_CHUNK})`)
    }
  }

  async function worker () {
    while (true) {
      const idx = next++
      if (idx >= FREEBSD_CHUNK_COUNT) return
      await downloadOne(idx)
    }
  }

  await Promise.all(
    Array.from({ length: concurrency }, function () {
      return worker()
    })
  )
  console.log(
    'copy-v86-assets: FreeBSD disk chunks',
    FREEBSD_CHUNK_COUNT,
    '×',
    FREEBSD_CHUNK,
    'bytes in',
    path.relative(root, freebsdDir)
  )
}

async function ensureGuestAssets () {
  fs.mkdirSync(guestDir, { recursive: true })
  for (const { url, file, minBytes } of GUEST_URLS) {
    const dest = path.join(guestDir, file)
    if (fs.existsSync(dest)) {
      const st = fs.statSync(dest)
      if (st.size >= minBytes) continue
      try {
        fs.unlinkSync(dest)
      } catch (_) {}
    }
    try {
      const res = await fetch(url, fetchInit())
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }
      const buf = Buffer.from(await res.arrayBuffer())
      if (buf.length < minBytes) {
        throw new Error(`short file (${buf.length} < ${minBytes})`)
      }
      fs.writeFileSync(dest, buf)
      console.log('copy-v86-assets: wrote', path.relative(root, dest), `(${buf.length} bytes)`)
    } catch (e) {
      console.warn(
        'copy-v86-assets: guest file',
        file,
        '—',
        e && e.message ? e.message : e,
        '(v86 hello demo will 503 until this succeeds with network)'
      )
    }
  }
}

async function main () {
  if (!fs.existsSync(path.join(srcDir, 'libv86.mjs'))) {
    console.warn(
      'copy-v86-assets: node_modules/v86 missing; run npm install'
    )
    return
  }

  fs.mkdirSync(destDir, { recursive: true })
  fs.copyFileSync(
    path.join(srcDir, 'libv86.mjs'),
    path.join(destDir, 'libv86.mjs')
  )
  fs.copyFileSync(path.join(srcDir, 'v86.wasm'), path.join(destDir, 'v86.wasm'))
  fs.copyFileSync(
    path.join(root, 'web', 'v86-hello-demo.mjs'),
    path.join(destDir, 'hello-demo.mjs')
  )

  await ensureGuestAssets()

  const fetchDisk =
    argvHasFlag('--freebsd-disk') || process.env.FETCH_FREEBSD_DISK === '1'

  try {
    await ensureFreebsdStateZst()
  } catch (e) {
    console.warn(
      'copy-v86-assets: FreeBSD saved state —',
      e && e.message ? e.message : e,
      '(cold boot will fail until: npm run fetch-freebsd-disk or network retry)'
    )
  }

  if (fetchDisk) {
    try {
      await ensureFreebsdDiskChunks()
    } catch (e) {
      console.warn(
        'copy-v86-assets: FreeBSD disk chunks —',
        e && e.message ? e.message : e
      )
      console.warn(
        'copy-v86-assets: hints — HTTPS_PROXY for corporate egress; mirror chunks and set FREEBSD_CHUNK_BASE; IPv6 issues: NODE_OPTIONS=--dns-result-order=ipv4first'
      )
      process.exitCode = 1
    }
  } else {
    console.log(
      'copy-v86-assets: skipping FreeBSD disk chunks (2 GiB). To download: npm run fetch-freebsd-disk'
    )
  }

  writeFreebsdMeta()
}

main().catch(function (e) {
  console.warn('copy-v86-assets:', e)
  process.exitCode = 1
})
