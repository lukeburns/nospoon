'use strict'

/**
 * Dedicated Node worker thread: runs embedded Helia + UnixFS so libp2p / blockstore work
 * does not block the control-plane event loop.
 */

const fs = require('fs')
const path = require('path')
const { parentPort, workerData } = require('worker_threads')

/**
 * @param {string} dirAbs
 * @param {string} fileAbs
 * @returns {boolean}
 */
function pathWithinResolvedDir (dirAbs, fileAbs) {
  const d = path.resolve(dirAbs)
  const f = path.resolve(fileAbs)
  if (f === d) return false
  const rel = path.relative(d, f)
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel)
}

/** @type {Awaited<ReturnType<typeof import('./ipfs-resolve-content').createHeliaBackend>> | null} */
let backend = null

/** @type {Map<number, AbortController>} */
const abortById = new Map()

/**
 * @param {object} msg
 */
async function handleResolveContent (msg) {
  const id = msg.id
  const ac = new AbortController()
  abortById.set(id, ac)
  try {
    const out = await backend.resolveContent({
      cidStr: msg.cidStr,
      pathname: msg.pathname,
      method: msg.method,
      signal: ac.signal
    })
    parentPort.postMessage({
      id,
      type: 'resolveStart',
      status: out.status,
      headers: out.headers || {}
    })
    if (out.body != null && typeof out.body[Symbol.asyncIterator] === 'function') {
      for await (const chunk of out.body) {
        parentPort.postMessage({
          id,
          type: 'resolveChunk',
          buf: Buffer.from(chunk)
        })
      }
    } else if (out.body != null) {
      parentPort.postMessage({
        id,
        type: 'resolveChunk',
        buf: Buffer.from(out.body)
      })
    }
    parentPort.postMessage({ id, type: 'resolveDone' })
  } catch (e) {
    if (e && e.name === 'AbortError') {
      parentPort.postMessage({ id, type: 'resolveAbort' })
    } else {
      parentPort.postMessage({
        id,
        type: 'resolveError',
        message: e && e.message ? e.message : String(e)
      })
    }
  } finally {
    abortById.delete(id)
  }
}

/**
 * @param {object} msg
 */
async function handleRpc (msg) {
  const id = msg.id
  try {
    let result
    switch (msg.method) {
      case 'listPins':
        result = await backend.listPins()
        break
      case 'unpin':
        await backend.unpin(msg.cidStr)
        result = null
        break
      case 'addFileFromPath': {
        const rawPath = String(msg.absPath || '').trim()
        const base = path.basename(rawPath)
        if (!/^nospoon-ipfs-add-[0-9a-f]{32}\.bin$/.test(base)) {
          throw new Error('invalid upload temp path')
        }
        if (!fs.existsSync(rawPath)) {
          throw new Error('upload temp file missing')
        }
        /** @type {import('fs').ReadStream | null} */
        let rs = null
        try {
          rs = fs.createReadStream(rawPath, { highWaterMark: 1024 * 1024 })
          async function * chunks () {
            try {
              for await (const c of rs) {
                yield c
              }
            } finally {
              try {
                rs.destroy()
              } catch (_) {}
            }
          }
          result = await backend.addFile({
            filename: msg.filename,
            content: chunks()
          })
        } finally {
          try {
            fs.unlinkSync(rawPath)
          } catch (_) {}
        }
        break
      }
      case 'addDirectoryFromPaths': {
        const uploadRoot = String(msg.uploadRoot || '').trim()
        const dirBase = path.basename(uploadRoot)
        if (!/^nospoon-ipfs-dir-[0-9a-f]{32}$/.test(dirBase)) {
          throw new Error('invalid upload temp directory')
        }
        if (!fs.existsSync(uploadRoot) || !fs.statSync(uploadRoot).isDirectory()) {
          throw new Error('upload temp directory missing')
        }
        const rows = msg.entries
        if (!Array.isArray(rows) || rows.length === 0) {
          throw new Error('no files in directory upload')
        }
        const rootResolved = path.resolve(uploadRoot)
        /** @type {Array<{ path: string, absPath: string }>} */
        const full = []
        for (const row of rows) {
          const part = String(row.part || '').trim()
          if (!/^part-[0-9]{8}\.bin$/.test(part)) {
            throw new Error('invalid upload part name')
          }
          const absPath = path.resolve(uploadRoot, part)
          if (!pathWithinResolvedDir(rootResolved, absPath)) {
            throw new Error('invalid upload path')
          }
          full.push({
            path: String(row.path || '').trim(),
            absPath
          })
        }
        try {
          result = await backend.addDirectoryFromPaths(full)
        } finally {
          try {
            fs.rmSync(uploadRoot, { recursive: true, force: true })
          } catch (_) {}
        }
        break
      }
      case 'libp2pStatus':
        result = await backend.libp2pStatus()
        break
      case 'mergeMeshHeliaPeer':
        await backend.mergeMeshHeliaPeer({
          meshIpv4: msg.meshIpv4,
          peerIdStr: msg.peerIdStr,
          port: msg.port
        })
        result = null
        break
      default:
        throw new Error('unknown rpc: ' + msg.method)
    }
    parentPort.postMessage({ id, ok: true, result })
  } catch (e) {
    parentPort.postMessage({
      id,
      ok: false,
      error: e && e.message ? e.message : String(e)
    })
  }
}

parentPort.on('message', function (msg) {
  if (!msg || typeof msg !== 'object') return
  if (msg.op === 'stop') {
    void (async function () {
      try {
        if (backend) await backend.stop()
      } catch (_) {}
      parentPort.postMessage({ op: 'stopped' })
      process.exit(0)
    })()
    return
  }
  if (!backend) return
  if (msg.op === 'abortResolve') {
    const ac = abortById.get(msg.id)
    if (ac) ac.abort()
    return
  }
  if (msg.op === 'resolveContent') {
    void handleResolveContent(msg)
    return
  }
  if (msg.op === 'rpc') {
    void handleRpc(msg)
    return
  }
})

;(async function boot () {
  try {
    const dir = workerData && workerData.dataDir
    if (!dir || String(dir).trim() === '') {
      throw new Error('workerData.dataDir is required')
    }
    const heliaOpts =
      workerData &&
      workerData.helia != null &&
      typeof workerData.helia === 'object'
        ? workerData.helia
        : {}
    const { createHeliaBackend } = require('./ipfs-resolve-content')
    backend = await createHeliaBackend(String(dir).trim(), heliaOpts)
    parentPort.postMessage({
      op: 'ready',
      heliaLibp2p: await backend.libp2pStatus()
    })
  } catch (e) {
    parentPort.postMessage({
      op: 'init_err',
      error: e && e.message ? e.message : String(e)
    })
    process.exit(1)
  }
})()
