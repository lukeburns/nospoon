#!/usr/bin/env node
/**
 * Populate {@link ../assets/v86} with libv86 + wasm from npm, BIOS from copy.sh, optional FreeBSD disk.
 * Guest layout matches copy.sh FreeBSD chunk names (`guest/freebsd/<start>-<end>.img`).
 *
 * Usage:
 *   node scripts/vendor-v86.mjs
 *   node scripts/vendor-v86.mjs --freebsd-disk
 *   FETCH_FREEBSD_DISK=1 node scripts/vendor-v86.mjs
 */
import {
  existsSync,
  mkdirSync,
  copyFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  unlinkSync
} from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const destDir = join(root, 'assets', 'v86')
const srcDir = join(root, 'node_modules', 'v86', 'build')
const guestDir = join(destDir, 'guest')
const freebsdDir = join(guestDir, 'freebsd')

const FREEBSD_DISK_BYTES = 2147483648
const FREEBSD_CHUNK = 1048576
const FREEBSD_CHUNK_COUNT = FREEBSD_DISK_BYTES / FREEBSD_CHUNK
const FREEBSD_CHUNK_BASE = String(
  process.env.FREEBSD_CHUNK_BASE || 'https://i.copy.sh/freebsd/'
).replace(/\/?$/, '/')
const FREEBSD_STATE_URL =
  process.env.FREEBSD_STATE_URL || 'https://i.copy.sh/freebsd_state-v2.bin.zst'
const FREEBSD_STATE_FILE = 'freebsd_state-v2.bin.zst'

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
  return process.argv.includes(name)
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

async function fetchToFile (url, dest, label) {
  const maxAttempts = Number(process.env.COPY_V86_FETCH_ATTEMPTS || 5) || 5
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, { redirect: 'follow' })
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
      mkdirSync(dirname(dest), { recursive: true })
      writeFileSync(dest, buf)
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
  const statePath = join(guestDir, FREEBSD_STATE_FILE)
  let stateZstBytes = 0
  if (existsSync(statePath)) {
    stateZstBytes = statSync(statePath).size
  }
  let diskChunkFiles = 0
  if (existsSync(freebsdDir)) {
    diskChunkFiles = readdirSync(freebsdDir).filter(function (f) {
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
  writeFileSync(
    join(guestDir, 'freebsd-meta.json'),
    JSON.stringify(meta, null, 2) + '\n'
  )
}

async function ensureGuestAssets () {
  mkdirSync(guestDir, { recursive: true })
  for (const { url, file, minBytes } of GUEST_URLS) {
    const dest = join(guestDir, file)
    if (existsSync(dest)) {
      const st = statSync(dest)
      if (st.size >= minBytes) continue
      try {
        unlinkSync(dest)
      } catch (_) {}
    }
    try {
      const res = await fetch(url, { redirect: 'follow' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const buf = Buffer.from(await res.arrayBuffer())
      if (buf.length < minBytes) {
        throw new Error(`short file (${buf.length} < ${minBytes})`)
      }
      writeFileSync(dest, buf)
      console.log('vendor-v86: wrote', file, `(${buf.length} bytes)`)
    } catch (e) {
      console.warn(
        'vendor-v86: guest file',
        file,
        '—',
        e && e.message ? e.message : e
      )
    }
  }
}

async function ensureFreebsdStateZst () {
  const dest = join(guestDir, FREEBSD_STATE_FILE)
  if (existsSync(dest)) {
    const st = statSync(dest)
    if (st.size > 1_000_000) return
    try {
      unlinkSync(dest)
    } catch (_) {}
  }
  const n = await fetchToFile(FREEBSD_STATE_URL, dest, FREEBSD_STATE_FILE)
  console.log('vendor-v86: wrote', FREEBSD_STATE_FILE, `(${n} bytes)`)
}

async function ensureFreebsdDiskChunks () {
  mkdirSync(freebsdDir, { recursive: true })
  const concurrency = 8
  let next = 0

  async function downloadOne (idx) {
    const byteStart = idx * FREEBSD_CHUNK
    const byteEnd = byteStart + FREEBSD_CHUNK
    const name = byteStart + '-' + byteEnd + '.img'
    const dest = join(freebsdDir, name)
    if (existsSync(dest)) {
      const st = statSync(dest)
      if (st.size >= FREEBSD_CHUNK) return
      try {
        unlinkSync(dest)
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
    'vendor-v86: FreeBSD disk chunks',
    FREEBSD_CHUNK_COUNT,
    '×',
    FREEBSD_CHUNK,
    'bytes in',
    freebsdDir
  )
}

async function main () {
  if (!existsSync(join(srcDir, 'libv86.mjs'))) {
    console.error('vendor-v86: node_modules/v86 missing — run npm install in examples/v86')
    process.exitCode = 1
    return
  }

  mkdirSync(destDir, { recursive: true })
  copyFileSync(join(srcDir, 'libv86.mjs'), join(destDir, 'libv86.mjs'))
  copyFileSync(join(srcDir, 'v86.wasm'), join(destDir, 'v86.wasm'))
  console.log('vendor-v86: copied libv86.mjs + v86.wasm from npm package')

  await ensureGuestAssets()

  try {
    await ensureFreebsdStateZst()
  } catch (e) {
    console.warn(
      'vendor-v86: FreeBSD saved state zst —',
      e && e.message ? e.message : e,
      '(optional; cold boot uses disk chunks)'
    )
  }

  const fetchDisk =
    argvHasFlag('--freebsd-disk') || process.env.FETCH_FREEBSD_DISK === '1'

  if (fetchDisk) {
    try {
      await ensureFreebsdDiskChunks()
    } catch (e) {
      console.warn('vendor-v86: FreeBSD disk chunks —', e && e.message ? e.message : e)
      process.exitCode = 1
    }
  } else {
    console.log(
      'vendor-v86: skipping FreeBSD disk chunks (~2 GiB). Run: node scripts/vendor-v86.mjs --freebsd-disk'
    )
  }

  writeFreebsdMeta()
  console.log('vendor-v86: wrote guest/freebsd-meta.json →', join(guestDir, 'freebsd-meta.json'))
}

main().catch(function (e) {
  console.error('vendor-v86:', e)
  process.exitCode = 1
})
