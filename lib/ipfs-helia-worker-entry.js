'use strict'

/**
 * Dedicated Node worker thread: runs embedded Helia + UnixFS so libp2p / blockstore work
 * does not block the control-plane event loop.
 */

const { parentPort, workerData } = require('worker_threads')

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
      case 'addFile':
        result = await backend.addFile({
          filename: msg.filename,
          content: msg.content
        })
        break
      case 'addDirectory':
        result = await backend.addDirectory(msg.entries)
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
    const { createHeliaBackend } = require('./ipfs-resolve-content')
    backend = await createHeliaBackend(String(dir).trim())
    parentPort.postMessage({ op: 'ready' })
  } catch (e) {
    parentPort.postMessage({
      op: 'init_err',
      error: e && e.message ? e.message : String(e)
    })
    process.exit(1)
  }
})()
