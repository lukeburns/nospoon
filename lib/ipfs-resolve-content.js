'use strict'

/**
 * `blockstore-fs` implements `get` as `async function` returning a Uint8Array; Helia's
 * IdentityBlockstore uses `yield*` on `child.get` and expects an async iterable. Wrap
 * so pinning (DAG walk) works with the FS backend.
 * @param {object} raw FsBlockstore instance
 */
function fsBlockstoreForHelia (raw) {
  return {
    open: raw.open.bind(raw),
    close: raw.close.bind(raw),
    put: raw.put.bind(raw),
    putMany: raw.putMany.bind(raw),
    get: async function * (key, options) {
      const buf = await raw.get(key, options)
      yield buf
    },
    getMany: raw.getMany.bind(raw),
    delete: raw.delete.bind(raw),
    deleteMany: raw.deleteMany.bind(raw),
    has: raw.has.bind(raw),
    getAll: raw.getAll.bind(raw)
  }
}

/**
 * @param {string} pathLike
 * @returns {string}
 */
function escapeHtml (s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * @param {string} dirUnixPath directory path under the root CID (no leading slash)
 * @param {string} name entry name
 */
function unixPathJoin (dirUnixPath, name) {
  const d = String(dirUnixPath || '').trim()
  return d ? `${d}/${name}` : name
}

/**
 * @param {string} dirUnixPath
 * @param {string} name
 */
function hrefPathForDirEntry (dirUnixPath, name) {
  const parts = String(dirUnixPath || '')
    .split('/')
    .filter(Boolean)
    .map(encodeURIComponent)
  parts.push(encodeURIComponent(name))
  return '/' + parts.join('/')
}

/**
 * @param {import('@helia/unixfs').UnixFS} ufs
 * @param {import('multiformats/cid').CID} cid
 * @param {string} dirUnixPath
 * @param {AbortSignal} signal
 * @returns {Promise<Array<{ name: string, type: string }>>}
 */
async function listUnixfsDir (ufs, cid, dirUnixPath, signal) {
  /** @type {Array<{ name: string, type: string }>} */
  const out = []
  const opts = { signal }
  if (dirUnixPath) opts.path = dirUnixPath
  for await (const ent of ufs.ls(cid, opts)) {
    out.push({ name: ent.name, type: ent.type })
  }
  out.sort(function (a, b) {
    return a.name.localeCompare(b.name)
  })
  return out
}

function contentTypeForPath (pathLike) {
  const p = String(pathLike || '').toLowerCase()
  if (p.endsWith('.html') || p.endsWith('.htm')) return 'text/html; charset=utf-8'
  if (p.endsWith('.css')) return 'text/css; charset=utf-8'
  if (p.endsWith('.js') || p.endsWith('.mjs')) return 'text/javascript; charset=utf-8'
  if (p.endsWith('.json')) return 'application/json; charset=utf-8'
  if (p.endsWith('.png')) return 'image/png'
  if (p.endsWith('.jpg') || p.endsWith('.jpeg')) return 'image/jpeg'
  if (p.endsWith('.gif')) return 'image/gif'
  if (p.endsWith('.svg')) return 'image/svg+xml'
  if (p.endsWith('.webp')) return 'image/webp'
  if (p.endsWith('.woff2')) return 'font/woff2'
  if (p.endsWith('.woff')) return 'font/woff'
  if (p.endsWith('.txt')) return 'text/plain; charset=utf-8'
  if (p.endsWith('.wasm')) return 'application/wasm'
  return 'application/octet-stream'
}

/**
 * @param {import('@helia/unixfs').UnixFS} ufs
 * @param {{ cidStr: string, pathname: string, method: string, signal: AbortSignal }} opts
 */
async function resolveWithHeliaUnixfs (ufs, opts) {
  const { CID } = await import('multiformats/cid')
  const cid = CID.parse(opts.cidStr)
  const pathname = opts.pathname === '/' ? '' : opts.pathname.slice(1)
  const signal = opts.signal

  try {
    let st = await ufs.stat(cid, { path: pathname || undefined, signal })
    let unixPath = pathname

    if (st.type === 'directory') {
      const dirPath = pathname
      let resolved = false
      for (const idx of ['index.html', 'index.htm']) {
        const indexFull = unixPathJoin(dirPath, idx)
        try {
          const stIdx = await ufs.stat(cid, { path: indexFull, signal })
          if (stIdx.type === 'file' || stIdx.type === 'raw') {
            st = stIdx
            unixPath = indexFull
            resolved = true
            break
          }
        } catch (_) {}
      }
      if (!resolved) {
        const entries = await listUnixfsDir(ufs, cid, dirPath, signal)
        const files = entries.filter(function (e) {
          return e.type === 'file' || e.type === 'raw'
        })
        const dirs = entries.filter(function (e) {
          return e.type === 'directory'
        })
        if (files.length === 1 && dirs.length === 0) {
          unixPath = unixPathJoin(dirPath, files[0].name)
          st = await ufs.stat(cid, { path: unixPath, signal })
          resolved = st.type === 'file' || st.type === 'raw'
        }
        if (!resolved) {
          const title = 'Index of /' + (dirPath ? escapeHtml(dirPath) + '/' : '')
          const rows = entries
            .map(function (e) {
              const label = e.type === 'directory' ? `${e.name}/` : e.name
              const href = hrefPathForDirEntry(dirPath, e.name)
              return `<li><a href="${href}">${escapeHtml(label)}</a></li>`
            })
            .join('\n')
          const html =
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' +
            title +
            '</title></head><body><h1>' +
            title +
            `</h1><ul>\n${rows || '<li><em>(empty)</em></li>'}\n</ul></body></html>`
          if (opts.method === 'HEAD') {
            return {
              status: 200,
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            }
          }
          return {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
            body: Buffer.from(html, 'utf8')
          }
        }
      }
    }

    if (st.type !== 'file' && st.type !== 'raw') {
      return {
        status: 404,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        body: Buffer.from('not found\n')
      }
    }

    const ct = contentTypeForPath('/' + (unixPath || ''))
    if (opts.method === 'HEAD') {
      return { status: 200, headers: { 'Content-Type': ct } }
    }

    async function * bodyIter () {
      for await (const u of ufs.cat(cid, { path: unixPath || undefined, signal })) {
        yield u
      }
    }

    return { status: 200, headers: { 'Content-Type': ct }, body: bodyIter() }
  } catch (e) {
    if (e && e.name === 'AbortError') throw e
    return {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: Buffer.from('not found\n')
    }
  }
}

/**
 * @param {string} baseUrl
 * @param {{ cidStr: string, pathname: string, method: string, signal: AbortSignal }} opts
 */
async function resolveViaExternalGateway (baseUrl, opts) {
  const trimmed = String(baseUrl || '').trim()
  const u = new URL(trimmed.endsWith('/') ? trimmed : trimmed + '/')
  const sub = opts.pathname === '/' ? '' : opts.pathname
  const rel = 'ipfs/' + opts.cidStr + sub
  const target = new URL(rel, u)

  const res = await fetch(target, {
    method: opts.method === 'HEAD' ? 'HEAD' : 'GET',
    signal: opts.signal,
    redirect: 'follow'
  })

  /** @type {Record<string, string>} */
  const headers = {}
  res.headers.forEach(function (v, k) {
    const kl = k.toLowerCase()
    if (
      kl === 'connection' ||
      kl === 'keep-alive' ||
      kl === 'transfer-encoding'
    ) {
      return
    }
    headers[k] = v
  })

  if (opts.method === 'HEAD' || res.status === 304) {
    return { status: res.status, headers, body: undefined }
  }

  if (!res.ok) {
    const t = await res.text().catch(function () {
      return ''
    })
    return {
      status: res.status,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: Buffer.from(t || 'error\n')
    }
  }

  if (!res.body) {
    return { status: res.status, headers, body: Buffer.alloc(0) }
  }

  async function * webBody () {
    const reader = res.body.getReader()
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        if (value && value.length) yield Buffer.from(value)
      }
    } finally {
      reader.releaseLock()
    }
  }

  return { status: res.status, headers, body: webBody() }
}

/**
 * @param {string} dataDir
 * @returns {Promise<{ helia: import('helia').Helia, stop: function(): Promise<void>, resolveContent: function(o: object): Promise<object> }>}
 */
async function createHeliaBackend (dataDir) {
  const { createHelia } = await import('helia')
  const { unixfs } = await import('@helia/unixfs')
  const { FsBlockstore } = await import('blockstore-fs')
  const { FsDatastore } = await import('datastore-fs')
  const fs = require('fs')
  const path = require('path')

  const dir = String(dataDir || '').trim()
  if (!dir) throw new Error('helia dataDir is required')
  fs.mkdirSync(dir, { recursive: true })
  const blockstore = fsBlockstoreForHelia(new FsBlockstore(path.join(dir, 'blocks')))
  /** Pins + libp2p keys live here; default Helia uses MemoryDatastore so seeds vanished each restart. */
  const datastore = new FsDatastore(path.join(dir, 'datastore'))
  const helia = await createHelia({ blockstore, datastore })
  const ufs = unixfs(helia)
  const { CID } = await import('multiformats/cid')

  /**
   * @returns {Promise<Array<{ cid: string, filename: string | null }>>}
   */
  async function listRootPins () {
    /** @type {Array<{ cid: string, filename: string | null }>} */
    const out = []
    for await (const pin of helia.pins.ls()) {
      const meta = pin.metadata || {}
      const filename = typeof meta.filename === 'string' ? meta.filename : null
      out.push({ cid: pin.cid.toString(), filename })
    }
    out.sort(function (a, b) {
      return a.cid.localeCompare(b.cid)
    })
    return out
  }

  async function unpinRoot (cidStr) {
    const cid = CID.parse(String(cidStr || '').trim())
    for await (const _ of helia.pins.rm(cid)) {
      // drain
    }
    await helia.gc()
  }

  return {
    helia,
    stop: function () {
      return helia.stop()
    },
    resolveContent: function (o) {
      return resolveWithHeliaUnixfs(ufs, o)
    },
    /** Root pins (legacy name). */
    listSeeds: listRootPins,
    /** Same as listSeeds; control-http listIpfsPins expects this name. */
    listPins: listRootPins,
    unseed: unpinRoot,
    unpin: unpinRoot,
    /**
     * @param {{ filename: string, content: Buffer | Uint8Array }} opts
     * @returns {Promise<string>} CID string (v1 base32 by default)
     */
    addFile: async function (opts) {
      const name = String(opts.filename || 'upload')
        .replace(/[/\\]/g, '_')
        .trim() || 'upload'
      const buf = opts.content
      const u8 = buf instanceof Uint8Array ? buf : Buffer.from(buf)
      const cid = await ufs.addFile({
        path: name,
        content: u8
      })
      try {
        for await (const _ of helia.pins.add(cid, {
          metadata: { filename: name }
        })) {
          // recursive pin entire DAG; drain generator
        }
      } catch (e) {
        if (e && e.name === 'AlreadyPinnedError') {
          await helia.pins.setMetadata(cid, { filename: name })
        } else {
          throw e
        }
      }
      return cid.toString()
    }
  }
}

module.exports = {
  contentTypeForPath,
  resolveWithHeliaUnixfs,
  resolveViaExternalGateway,
  createHeliaBackend
}
