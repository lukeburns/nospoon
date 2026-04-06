'use strict'

const fs = require('fs')
const path = require('path')

const root = path.join(__dirname, '..')
const srcDir = path.join(root, 'node_modules', 'v86', 'build')
const destDir = path.join(root, 'lib', 'v86')
const guestDir = path.join(destDir, 'guest')
const freebsdDir = path.join(guestDir, 'freebsd')

/** Same as copy.sh FreeBSD profile / web/v86-hello-demo.mjs */
const FREEBSD_DISK_BYTES = 2147483648
const FREEBSD_CHUNK = 1048576
const FREEBSD_CHUNK_COUNT = FREEBSD_DISK_BYTES / FREEBSD_CHUNK
const FREEBSD_CHUNK_BASE = 'https://i.copy.sh/freebsd/'
const FREEBSD_STATE_URL = 'https://i.copy.sh/freebsd_state-v2.bin.zst'
const FREEBSD_STATE_FILE = 'freebsd_state-v2.bin.zst'

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
  const res = await fetch(url, { redirect: 'follow' })
  if (!res.ok) {
    throw new Error(`${label}: HTTP ${res.status}`)
  }
  const buf = Buffer.from(await res.arrayBuffer())
  fs.mkdirSync(path.dirname(dest), { recursive: true })
  fs.writeFileSync(dest, buf)
  return buf.length
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
      const res = await fetch(url, { redirect: 'follow' })
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
