'use strict'

const path = require('path')
const { Worker } = require('worker_threads')

class ResolvePump {
  /**
   * @param {number} id
   */
  constructor (id) {
    this.id = id
    /** @type {Buffer[]} */
    this._q = []
    /** @type {Array<(v: { value?: Buffer, done: boolean, error?: Error }) => void>} */
    this._wait = []
    this._done = false
    /** @type {Error | null} */
    this._err = null
    /** @type {((v: { status: number, headers: Record<string, string> }) => void) | null} */
    this._onStart = null
    /** @type {((e: Error) => void) | null} */
    this._onStartErr = null
  }

  /**
   * @param {{ status: number, headers: Record<string, string> }} m
   */
  start (m) {
    if (this._onStart) this._onStart(m)
  }

  /**
   * @param {Buffer} buf
   */
  chunk (buf) {
    const b = Buffer.from(buf)
    if (this._wait.length) {
      this._wait.shift()({ value: b, done: false })
    } else {
      this._q.push(b)
    }
  }

  finish () {
    this._done = true
    while (this._wait.length) {
      this._wait.shift()({ done: true })
    }
  }

  /**
   * @param {Error} e
   */
  fail (e) {
    this._err = e
    if (this._onStartErr) {
      this._onStartErr(e)
      this._onStartErr = null
      this._onStart = null
    }
    while (this._wait.length) {
      this._wait.shift()({ done: true, error: e })
    }
  }

  /**
   * @returns {Promise<{ status: number, headers: Record<string, string>, body?: AsyncIterable<Uint8Array> }>}
   */
  promise () {
    const self = this
    return new Promise(function (resolve, reject) {
      self._onStart = function (m) {
        self._onStart = null
        self._onStartErr = null
        resolve({
          status: m.status,
          headers: m.headers,
          body: self._iter()
        })
      }
      self._onStartErr = reject
    })
  }

  async * _iter () {
    const self = this
    while (true) {
      if (self._q.length) {
        yield self._q.shift()
        continue
      }
      if (self._done) break
      if (self._err) throw self._err
      const n = await new Promise(function (res) {
        self._wait.push(res)
      })
      if (n.error) throw n.error
      if (n.done) break
      if (n.value) yield n.value
    }
  }
}

/**
 * Same surface as {@link import('./ipfs-resolve-content').createHeliaBackend}; Helia runs in a worker thread.
 *
 * @param {string} dataDir
 * @param {{ dhtClientMode?: boolean, extraListenIpv4?: string[], swarmListenIpv4?: string | null }} [heliaOpts] forwarded to `createHeliaBackend` in the worker
 * @param {{ onBootProgress?: function(string): void }} [callbacks]
 * @returns {Promise<{ stop: function(): Promise<void>, resolveContent: function(object): Promise<object>, listPins: function(): Promise<Array<{ cid: string, filename: string | null }>>, listSeeds: function(): Promise<Array<{ cid: string, filename: string | null }>>, unpin: function(string): Promise<void>, unseed: function(string): Promise<void>, addFileFromPath: function(object): Promise<string>, addDirectoryFromPaths: function(object): Promise<{ cid: string, filename: string }>, libp2pStatus: function(): Promise<object>, initialHeliaLibp2p: object | null, helia: null }>}
 */
async function createHeliaWorkerBackend (dataDir, heliaOpts, callbacks) {
  const dir = String(dataDir || '').trim()
  if (!dir) throw new Error('helia dataDir is required')

  const heliaWorkerOpts =
    heliaOpts != null && typeof heliaOpts === 'object' ? heliaOpts : {}
  const cb =
    callbacks != null && typeof callbacks === 'object' ? callbacks : {}
  const onBootProgress =
    typeof cb.onBootProgress === 'function' ? cb.onBootProgress : null

  const worker = new Worker(path.join(__dirname, 'ipfs-helia-worker-entry.js'), {
    workerData: { dataDir: dir, helia: heliaWorkerOpts }
  })

  /** @type {{ peerId: string, multiaddrs: string[], connections: number } | null} */
  let heliaLibp2pAtReady = null

  await new Promise(function (resolve, reject) {
    let settled = false
    function onMsg (m) {
      if (!m || typeof m !== 'object' || settled) return
      if (m.op === 'boot_progress') {
        if (onBootProgress) {
          try {
            onBootProgress(String(m.stage || ''))
          } catch (_) {}
        }
        return
      }
      if (m.op === 'ready') {
        if (m.heliaLibp2p != null && typeof m.heliaLibp2p === 'object') {
          heliaLibp2pAtReady = m.heliaLibp2p
        }
        settled = true
        worker.removeListener('message', onMsg)
        worker.removeListener('exit', onExit)
        resolve(undefined)
      } else if (m.op === 'init_err') {
        settled = true
        worker.removeListener('message', onMsg)
        worker.removeListener('exit', onExit)
        reject(new Error(m.error || 'Helia worker init failed'))
      }
    }
    function onExit (code) {
      if (settled) return
      settled = true
      worker.removeListener('message', onMsg)
      reject(new Error('Helia worker exited during init: ' + String(code)))
    }
    worker.on('message', onMsg)
    worker.once('exit', onExit)
    worker.once('error', function (err) {
      if (settled) return
      settled = true
      worker.removeListener('message', onMsg)
      worker.removeListener('exit', onExit)
      reject(err)
    })
  })

  /** @type {Map<number, ResolvePump>} */
  const pumps = new Map()
  /** @type {Map<number, { resolve: function(any): void, reject: function(Error): void }>} */
  const rpcPending = new Map()
  let seq = 0

  function nextId () {
    seq += 1
    return seq
  }

  worker.on('message', function (m) {
    if (!m || typeof m !== 'object') return
    if (m.op === 'ready' || m.op === 'init_err' || m.op === 'stopped') return

    if (m.type === 'resolveStart') {
      const p = pumps.get(m.id)
      if (p) p.start({ status: m.status, headers: m.headers })
      return
    }
    if (m.type === 'resolveChunk') {
      const p = pumps.get(m.id)
      if (p) p.chunk(m.buf)
      return
    }
    if (m.type === 'resolveDone') {
      const p = pumps.get(m.id)
      if (p) {
        p.finish()
        pumps.delete(m.id)
      }
      return
    }
    if (m.type === 'resolveAbort') {
      const p = pumps.get(m.id)
      if (p) {
        const err = new Error('Aborted')
        err.name = 'AbortError'
        p.fail(err)
        pumps.delete(m.id)
      }
      return
    }
    if (m.type === 'resolveError') {
      const p = pumps.get(m.id)
      if (p) {
        p.fail(new Error(m.message || 'resolve error'))
        pumps.delete(m.id)
      }
      return
    }

    if (m.id != null && rpcPending.has(m.id)) {
      const row = rpcPending.get(m.id)
      rpcPending.delete(m.id)
      if (m.ok) row.resolve(m.result)
      else row.reject(new Error(m.error || 'rpc error'))
    }
  })

  worker.on('error', function (err) {
    for (const p of pumps.values()) {
      p.fail(err)
    }
    pumps.clear()
    for (const row of rpcPending.values()) {
      row.reject(err)
    }
    rpcPending.clear()
  })

  function rpc (method, payload) {
    const id = nextId()
    return new Promise(function (resolve, reject) {
      rpcPending.set(id, { resolve, reject })
      try {
        worker.postMessage({ op: 'rpc', id, method, ...payload })
      } catch (e) {
        rpcPending.delete(id)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  return {
    helia: null,
    initialHeliaLibp2p: heliaLibp2pAtReady,
    libp2pStatus: function () {
      return rpc('libp2pStatus', {})
    },
    meshHeliaDialStatus: function () {
      return rpc('meshHeliaDialStatus', {})
    },
    stop: function () {
      return new Promise(function (resolve) {
        const t = setTimeout(function () {
          try {
            worker.terminate()
          } catch (_) {}
          resolve(undefined)
        }, 15000)
        t.unref()
        worker.once('exit', function () {
          clearTimeout(t)
          worker.removeListener('message', onStopped)
          resolve(undefined)
        })
        function onStopped (m) {
          if (m && m.op === 'stopped') {
            worker.removeListener('message', onStopped)
          }
        }
        worker.on('message', onStopped)
        try {
          worker.postMessage({ op: 'stop' })
        } catch (_) {
          clearTimeout(t)
          worker.removeListener('message', onStopped)
          try {
            worker.terminate()
          } catch (_) {}
          resolve(undefined)
        }
      })
    },
    resolveContent: function (o) {
      const id = nextId()
      const pump = new ResolvePump(id)
      pumps.set(id, pump)
      const onAbort = function () {
        try {
          worker.postMessage({ op: 'abortResolve', id })
        } catch (_) {}
      }
      if (o.signal) {
        if (o.signal.aborted) onAbort()
        else o.signal.addEventListener('abort', onAbort, { once: true })
      }
      try {
        worker.postMessage({
          op: 'resolveContent',
          id,
          cidStr: o.cidStr,
          pathname: o.pathname,
          method: o.method
        })
      } catch (e) {
        pumps.delete(id)
        return Promise.reject(e instanceof Error ? e : new Error(String(e)))
      }
      return pump.promise().catch(function (e) {
        pumps.delete(id)
        throw e
      })
    },
    listPins: function () {
      return rpc('listPins', {})
    },
    listSeeds: function () {
      return rpc('listPins', {})
    },
    unpin: function (cidStr) {
      return rpc('unpin', { cidStr: String(cidStr || '').trim() })
    },
    unseed: function (cidStr) {
      return rpc('unpin', { cidStr: String(cidStr || '').trim() })
    },
    addFileFromPath: function (opts) {
      return rpc('addFileFromPath', {
        filename: opts.filename,
        absPath: opts.absPath
      })
    },
    addDirectoryFromPaths: function (opts) {
      return rpc('addDirectoryFromPaths', {
        uploadRoot: opts.uploadRoot,
        entries: opts.entries
      })
    },
    mergeMeshHeliaPeer: function (o) {
      return rpc('mergeMeshHeliaPeer', {
        meshIpv4: o.meshIpv4,
        peerIdStr: o.peerIdStr,
        port: o.port
      })
    }
  }
}

module.exports = {
  createHeliaWorkerBackend
}
