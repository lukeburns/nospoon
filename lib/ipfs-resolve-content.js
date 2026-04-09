'use strict'

const net = require('net')
const os = require('os')

/**
 * `blockstore-fs` implements `get` as `async function` returning a Uint8Array; Helia's
 * IdentityBlockstore uses `yield*` on `child.get` and expects an async iterable. Wrap
 * so pinning (DAG walk) works with the FS backend.
 * @param {object} raw FsBlockstore instance
 */
/**
 * @param {string} s
 * @returns {'relay' | 'local' | 'public'}
 */
function classifyHeliaMultiaddr (s) {
  const str = String(s || '')
  if (str.indexOf('/p2p-circuit') !== -1) return 'relay'
  if (str.indexOf('/ip4/127.') !== -1) return 'local'
  if (str.indexOf('/ip6/::1') !== -1) return 'local'
  if (str.indexOf('/ip6/fe80:') !== -1) return 'local'
  if (/^\/ip6\/fd[0-9a-f]{2}:/i.test(str)) return 'local'
  const m4 = str.match(/^\/ip4\/(\d+)\.(\d+)\./)
  if (m4) {
    const a = parseInt(m4[1], 10)
    const b = parseInt(m4[2], 10)
    if (a === 10) return 'local'
    if (a === 192 && b === 168) return 'local'
    if (a === 172 && b >= 16 && b <= 31) return 'local'
  }
  return 'public'
}

/**
 * @param {string[]} addrStrings
 * @returns {{ relay: string[], local: string[], public: string[] }}
 */
function bucketHeliaMultiaddrs (addrStrings) {
  /** @type {string[]} */
  const relay = []
  /** @type {string[]} */
  const local = []
  /** @type {string[]} */
  const publicAddrs = []
  const seen = new Set()
  for (let i = 0; i < addrStrings.length; i++) {
    const s = String(addrStrings[i])
    if (seen.has(s)) continue
    seen.add(s)
    const k = classifyHeliaMultiaddr(s)
    if (k === 'relay') relay.push(s)
    else if (k === 'local') local.push(s)
    else publicAddrs.push(s)
  }
  return { relay, local, public: publicAddrs }
}

/**
 * Live libp2p diagnostics (async: peer store walk).
 * `connections` is open sessions to *remote* peers only — not the same as listen multiaddrs.
 * `meshHeliaConnHints` pairs each open connection’s libp2p PeerId with a parsed `/ip4/…` from
 * `remoteAddr` when present (mesh TCP/QUIC), so the control plane can attribute inbound dials to Hyperswarm rows.
 * `multiaddrs` are **verified** dial addresses only; NAT-mapped public QUIC may appear under
 * `addressDetails` before AutoNAT/UPnP confirmation, or in `listenMultiaddrs` as configured listeners.
 *
 * @param {import('helia').Helia} helia
 * @param {{ dhtClientMode?: boolean, upnpAutoConfirmAddress?: boolean, announceNoCircuit?: boolean } | undefined} snapMeta
 * @returns {Promise<object>}
 */
async function libp2pStatusSnapshot (helia, snapMeta) {
  const meta = snapMeta || {}
  const lp = helia.libp2p
  const peerId = lp.peerId.toString()
  const multiaddrs = lp.getMultiaddrs().map(function (m) {
    return m.toString()
  })
  const connections = lp.getConnections().length
  let dialQueued = 0
  let dialActive = 0
  try {
    const q = lp.getDialQueue()
    for (let i = 0; i < q.length; i++) {
      const s = q[i].status
      if (s === 'queued') dialQueued++
      else if (s === 'active') dialActive++
    }
  } catch (_) {}
  let peerStorePeers = 0
  try {
    const peers = await lp.peerStore.all()
    peerStorePeers = peers.length
  } catch (_) {}
  /** @type {string[]} */
  const listenMultiaddrs = []
  /** @type {Array<{ multiaddr: string, verified: boolean, type: string }>} */
  const addressDetails = []
  try {
    const am = lp.components && lp.components.addressManager
    if (am != null && typeof am.getListenAddrs === 'function') {
      listenMultiaddrs.push(
        ...am.getListenAddrs().map(function (m) {
          return m.toString()
        })
      )
    }
    if (am != null && typeof am.getAddressesWithMetadata === 'function') {
      for (const row of am.getAddressesWithMetadata()) {
        addressDetails.push({
          multiaddr: row.multiaddr.toString(),
          verified: Boolean(row.verified),
          type: typeof row.type === 'string' ? row.type : 'unknown'
        })
      }
    }
  } catch (_) {}
  const nodeMajor = parseInt(
    String(process.versions.node).split('.')[0] || '0',
    10
  )
  const addressBuckets = bucketHeliaMultiaddrs(multiaddrs)
  /** @type {Set<string>} */
  const connectedRemotePeerIds = new Set()
  /** @type {Array<{ peerId: string, remoteIp4: string | null }>} */
  const meshHeliaConnHints = []
  try {
    const conns = lp.getConnections()
    for (let i = 0; i < conns.length; i++) {
      const c = conns[i]
      if (c == null || c.remotePeer == null) continue
      const rid = c.remotePeer.toString()
      connectedRemotePeerIds.add(rid)
      let ip4 = null
      try {
        const ra = c.remoteAddr
        if (ra != null && typeof ra.toString === 'function') {
          const sm = ra.toString().match(/^\/ip4\/([^/]+)/)
          if (sm && net.isIPv4(sm[1])) ip4 = sm[1]
        }
      } catch (_) {}
      meshHeliaConnHints.push({ peerId: rid, remoteIp4: ip4 })
    }
  } catch (_) {}
  return {
    peerId,
    multiaddrs,
    addressBuckets,
    listenMultiaddrs,
    addressDetails,
    connections,
    dialQueued,
    dialActive,
    peerStorePeers,
    connectedRemotePeerIds: [...connectedRemotePeerIds].sort(),
    meshHeliaConnHints,
    dhtClientMode: meta.dhtClientMode === true,
    upnpAutoConfirmAddress: meta.upnpAutoConfirmAddress === true,
    announceNoCircuit: meta.announceNoCircuit === true,
    nodeMajor
  }
}

/**
 * Publish provider records for a pinned root (DHT + delegated routers). Failures are logged only.
 * @param {import('helia').Helia} helia
 * @param {import('multiformats/cid').CID} cid
 */
async function announceProvideRoot (helia, cid) {
  try {
    await helia.routing.provide(cid)
  } catch (e) {
    const msg = e && e.message ? e.message : String(e)
    console.warn('[nospoon helia] routing.provide failed for ' + cid + ': ' + msg)
  }
}

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
 * Relative UnixFS path for `unixfs.addAll` (no leading slash, no `..`).
 * @param {string} p
 * @returns {string}
 */
function normalizeUnixfsRelPath (p) {
  const s = String(p || '')
    .replace(/\\/g, '/')
    .trim()
  if (!s || s.includes('\0')) throw new Error('invalid path')
  if (s.startsWith('/')) throw new Error('invalid path')
  const parts = []
  for (const seg of s.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') throw new Error('invalid path')
    parts.push(seg)
  }
  if (!parts.length) throw new Error('invalid path')
  return parts.join('/')
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

/**
 * When the request path is `/` but the DAG root is a single file (e.g. only
 * `index.html` in the import), we have no filename in the URL — guess HTML so
 * browsers render instead of downloading as application/octet-stream.
 * @param {Buffer | Uint8Array} buf
 */
function looksLikeHtmlPrefix (buf) {
  const raw = Buffer.from(buf)
  const n = Math.min(raw.length, 512)
  if (n === 0) return false
  let s = raw.toString('utf8', 0, n)
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1)
  s = s.trimStart()
  return /^<!DOCTYPE html/i.test(s) || /^<html[\s>]/i.test(s)
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

    let ct = contentTypeForPath('/' + (unixPath || ''))
    const sniffRootFile =
      ct === 'application/octet-stream' && !unixPath

    if (sniffRootFile && opts.method === 'HEAD') {
      for await (const u of ufs.cat(cid, { path: undefined, signal })) {
        if (looksLikeHtmlPrefix(u)) {
          ct = 'text/html; charset=utf-8'
        }
        break
      }
      return { status: 200, headers: { 'Content-Type': ct } }
    }

    if (opts.method === 'HEAD') {
      return { status: 200, headers: { 'Content-Type': ct } }
    }

    if (!sniffRootFile) {
      async function * bodyIterSimple () {
        for await (const u of ufs.cat(cid, { path: unixPath || undefined, signal })) {
          yield u
        }
      }
      return { status: 200, headers: { 'Content-Type': ct }, body: bodyIterSimple() }
    }

    const catIt = ufs.cat(cid, { path: undefined, signal })
    const iter = catIt[Symbol.asyncIterator]()
    const first = await iter.next()
    if (first.done) {
      return {
        status: 200,
        headers: { 'Content-Type': ct },
        body: (async function * () {})()
      }
    }
    const firstBuf = Buffer.from(first.value)
    if (looksLikeHtmlPrefix(firstBuf)) {
      ct = 'text/html; charset=utf-8'
    }

    async function * bodyIterSniffed () {
      yield firstBuf
      while (true) {
        const n = await iter.next()
        if (n.done) break
        yield Buffer.from(n.value)
      }
    }

    return { status: 200, headers: { 'Content-Type': ct }, body: bodyIterSniffed() }
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
 * Fixed TCP + QUIC-UDP swarm port (4011 avoids Kubo Desktop’s 4001).
 * WebSocket uses `/tcp/0/ws` (ephemeral): it cannot share the same TCP port as plain `/tcp`.
 */
const DEFAULT_HELIA_SWARM_PORT = 4011

/**
 * @returns {number}
 */
function nospoonHeliaSwarmPort () {
  const raw = process.env.NOSPOON_HELIA_SWARM_PORT
  if (raw != null && String(raw).trim() !== '') {
    const p = parseInt(String(raw).trim(), 10)
    if (p >= 1 && p <= 65535) return p
  }
  return DEFAULT_HELIA_SWARM_PORT
}

/**
 * @param {string} name
 * @param {boolean} defaultValue
 * @returns {boolean}
 */
function nospoonHeliaEnvBool (name, defaultValue) {
  const v = process.env[name]
  if (v == null || String(v).trim() === '') return defaultValue
  const s = String(v).trim().toLowerCase()
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false
  return defaultValue
}

/**
 * Optional extra announced addresses (comma-separated), e.g. a known public `/ip4/…/udp/…/quic-v1`.
 * @returns {string[]}
 */
function nospoonHeliaAppendAnnounceFromEnv () {
  const raw = process.env.NOSPOON_HELIA_APPEND_ANNOUNCE
  if (raw == null || String(raw).trim() === '') return []
  return String(raw)
    .split(',')
    .map(function (s) {
      return s.trim()
    })
    .filter(Boolean)
}

/**
 * Extra IPv4 listen addresses for Helia TCP/QUIC (comma-separated), merged with
 * {@link createHeliaBackend} `extraListenIpv4`. Only used when the primary v4 bind is not `0.0.0.0`.
 * @returns {string[]}
 */
function nospoonHeliaExtraListenIpv4FromEnv () {
  const raw = process.env.NOSPOON_HELIA_EXTRA_LISTEN_IPV4
  if (raw == null || String(raw).trim() === '') return []
  return String(raw)
    .split(',')
    .map(function (s) {
      return s.trim()
    })
    .filter(function (s) {
      return net.isIPv4(s)
    })
}

/**
 * @param {unknown} fromOpts
 * @param {string[]} fromEnv
 * @returns {string[]}
 */
function mergeExtraListenIpv4 (fromOpts, fromEnv) {
  const seen = new Set()
  /** @type {string[]} */
  const out = []
  const add = function (ip) {
    const s = String(ip || '').trim()
    if (!net.isIPv4(s) || seen.has(s)) return
    seen.add(s)
    out.push(s)
  }
  if (Array.isArray(fromOpts)) {
    for (let i = 0; i < fromOpts.length; i++) {
      add(fromOpts[i])
    }
  }
  for (let i = 0; i < fromEnv.length; i++) {
    add(fromEnv[i])
  }
  return out
}

/**
 * IPv4 for fixed-port TCP/QUIC listeners. Binding `0.0.0.0` makes libp2p expand to every non-loopback IPv4
 * (including mesh/TUN), which breaks UPnP `map` for hosts the router does not NAT.
 * `auto` / `lan` uses the IPv4 on the default-route interface (`default-gateway`).
 * @returns {Promise<string | null>} host or null for `/ip4/0.0.0.0/…`
 */
async function nospoonHeliaSwarmIpv4ListenHost () {
  const manual = process.env.NOSPOON_HELIA_BIND_IPV4
  if (manual != null && String(manual).trim() !== '') {
    const ip = String(manual).trim()
    return net.isIPv4(ip) ? ip : null
  }
  const mode = String(process.env.NOSPOON_HELIA_SWARM_BIND || 'auto')
    .trim()
    .toLowerCase()
  if (
    mode === 'wildcard' ||
    mode === 'all' ||
    mode === '0' ||
    mode === '0.0.0.0'
  ) {
    return null
  }
  try {
    const { gateway4sync } = await import('default-gateway')
    const r = gateway4sync()
    if (r == null || r.int == null || String(r.int).trim() === '') {
      return null
    }
    const row = os.networkInterfaces()[r.int]
    if (!Array.isArray(row)) return null
    for (let i = 0; i < row.length; i++) {
      const a = row[i]
      const fam = a.family
      const isV4 = fam === 'IPv4' || fam === 4
      if (isV4 && !a.internal && net.isIPv4(a.address)) {
        return a.address
      }
    }
  } catch (_) {}
  return null
}

/**
 * UPnP SSDP plus NAT-PMP on the default IPv4 gateway (same combo Kubo uses). Custom client is required
 * because `@libp2p/upnp-nat` only wires `upnpNat()` by default.
 * @param {string} description
 */
async function createNospoonHeliaPortMappingClient (description) {
  const { upnpNat, pmpNat } = await import('@achingbrain/nat-port-mapper')
  const upnp = upnpNat({ description })
  /** @type {import('@achingbrain/nat-port-mapper').Gateway | null} */
  let pmpGateway = null
  const pmpOn = nospoonHeliaEnvBool('NOSPOON_HELIA_NAT_PMP', true)
  return {
    async * findGateways (options) {
      // NAT-PMP first: it targets the default-route gateway immediately. UPnP SSDP keeps
      // `upnp.findGateways()` open until the search signal aborts (~5s+ initially), so yielding
      // PMP only after that loop delayed port mapping and matched “no public” reports.
      if (pmpOn) {
        try {
          const { gateway4sync } = await import('default-gateway')
          const r = gateway4sync()
          if (r != null && r.gateway != null && String(r.gateway).trim() !== '') {
            if (pmpGateway == null) {
              pmpGateway = pmpNat(String(r.gateway).trim(), { description })
            }
            yield pmpGateway
          }
        } catch (_) {}
      }
      for await (const g of upnp.findGateways(options)) {
        yield g
      }
    },
    getGateway (descriptor, options) {
      return upnp.getGateway(descriptor, options)
    }
  }
}

/**
 * libp2p init merged by Helia: fixed listen ports (NAT/UPnP + AutoNAT can map like Kubo), QUIC when available,
 * DHT mode (see kad-dht clientMode), and UPnP behaviour aligned with reachable public addrs.
 * @param {number} port
 * @param {{ dhtClientMode?: boolean, upnpAutoConfirmAddress?: boolean, appendAnnounce?: string[], announceNoCircuit?: boolean, webrtc?: boolean, extraListenIpv4?: string[], disableUpnp?: boolean, swarmListenIpv4?: string | null }} [opts]
 * `swarmListenIpv4`: when set (including `null` for wildcard), skips re-resolving in the worker — use the control plane’s default-route IPv4 so LAN peers reach libp2p even when not on a spoon TUN.
 * @returns {Promise<{ addresses: object, transports: unknown[], services: object }>}
 */
async function nospoonHeliaLibp2pOptions (port, opts) {
  const o = opts || {}
  const disableUpnp = o.disableUpnp === true
  const dhtClientMode = o.dhtClientMode === true
  /**
   * `@libp2p/webrtc` uses `node-datachannel`, which can abort the process with an
   * uncaught Napi::Error (TSFN failure on native threads during teardown).
   * On Linux: `std::runtime_error: Failed to call JavaScript callback`.
   * On macOS + Node >=24: empty `Napi::Error` abort from the same TSFN path.
   * Default off; set `NOSPOON_HELIA_WEBRTC=1` to enable Helia WebRTC listeners.
   */
  const defaultWebrtc = false
  const useHeliaWebRTC =
    typeof o.webrtc === 'boolean'
      ? o.webrtc
      : nospoonHeliaEnvBool('NOSPOON_HELIA_WEBRTC', defaultWebrtc)
  const announceNoCircuit =
    typeof o.announceNoCircuit === 'boolean'
      ? o.announceNoCircuit
      : nospoonHeliaEnvBool('NOSPOON_HELIA_ANNOUNCE_NO_CIRCUIT', false)
  const upnpAutoConfirm =
    typeof o.upnpAutoConfirmAddress === 'boolean'
      ? o.upnpAutoConfirmAddress
      : nospoonHeliaEnvBool('NOSPOON_HELIA_UPNP_AUTO_CONFIRM', true)
  /** @type {string[]} */
  let appendAnnounce = Array.isArray(o.appendAnnounce) ? o.appendAnnounce : []
  if (appendAnnounce.length === 0) {
    appendAnnounce = nospoonHeliaAppendAnnounceFromEnv()
  }

  const { libp2pDefaults } = await import('helia')
  const { kadDHT } = await import('@libp2p/kad-dht')
  const { uPnPNAT } = await import('@libp2p/upnp-nat')
  const { ipnsSelector } = await import('ipns/selector')
  const { ipnsValidator } = await import('ipns/validator')
  const portMapDesc = 'nospoon helia'
  const base = libp2pDefaults()
  const transports = base.transports.slice()
  const services = { ...base.services }
  /**
   * Helia default kad-dht uses clientMode: true and only switches to server when it sees a
   * non-private, non-relay self-address. We default to server mode (toggle + env in createHeliaBackend).
   */
  services.dht = kadDHT({
    validators: { ipns: ipnsValidator },
    selectors: { ipns: ipnsSelector },
    clientMode: dhtClientMode
  })
  /**
   * Default `autoConfirmAddress: false` keeps UPnP-mapped public ports unverified until AutoNAT runs, so
   * `getMultiaddrs()` may omit the same `/ip4/…/udp/…/quic-v1` line Kubo shows. Enabling confirmation
   * (default here) matches typical home-node discoverability; set NOSPOON_HELIA_UPNP_AUTO_CONFIRM=0 to disable.
   * Skip building the NAT port-mapper client when UPnP is off (SSDP can block or collide on :1900).
   */
  if (!disableUpnp) {
    const portMappingClient = await createNospoonHeliaPortMappingClient(portMapDesc)
    services.upnp = uPnPNAT({
      autoConfirmAddress: upnpAutoConfirm,
      portMappingClient,
      portMappingDescription: portMapDesc
    })
  } else {
    delete services.upnp
  }

  let v4host
  if (o != null && Object.prototype.hasOwnProperty.call(o, 'swarmListenIpv4')) {
    const sl = o.swarmListenIpv4
    if (sl === null) {
      v4host = null
    } else if (typeof sl === 'string' && net.isIPv4(String(sl).trim())) {
      v4host = String(sl).trim()
    } else {
      v4host = await nospoonHeliaSwarmIpv4ListenHost()
    }
  } else {
    v4host = await nospoonHeliaSwarmIpv4ListenHost()
  }
  const v4tcpQuicHost = v4host != null ? v4host : '0.0.0.0'
  const listen = [
    `/ip4/${v4tcpQuicHost}/tcp/${port}`,
    `/ip6/::/tcp/${port}`,
    '/ip4/0.0.0.0/tcp/0/ws',
    '/ip6/::/tcp/0/ws'
  ]

  const nodeMajor = parseInt(
    String(process.versions.node).split('.')[0] || '0',
    10
  )
  let heliaQuicInserted = false
  if (nodeMajor >= 22) {
    try {
      const { quic } = await import('@chainsafe/libp2p-quic')
      listen.push(
        `/ip4/${v4tcpQuicHost}/udp/${port}/quic-v1`,
        `/ip6/::/udp/${port}/quic-v1`
      )
      transports.splice(2, 0, quic())
      heliaQuicInserted = true
    } catch (e) {
      console.warn(
        '[nospoon helia] QUIC not available (need Node 22+ and a supported platform):',
        e && e.message ? e.message : String(e)
      )
    }
  }

  /**
   * Helia’s `libp2pDefaults()` transport order (before QUIC splice): circuit, tcp, webRTC, webRTCDirect, webSockets.
   * After inserting QUIC at index 2, WebRTC entries shift by +1.
   */
  if (!useHeliaWebRTC) {
    const webRtcIdx = heliaQuicInserted ? 3 : 2
    const webRtcDirectIdx = heliaQuicInserted ? 4 : 3
    transports.splice(webRtcDirectIdx, 1)
    transports.splice(webRtcIdx, 1)
    // if (os.platform() === 'linux') {
    //   console.warn(
    //     '[nospoon helia] WebRTC disabled on Linux (node-datachannel crash workaround). ' +
    //       'Set NOSPOON_HELIA_WEBRTC=1 to enable.'
    //   )
    // }
  } else {
    listen.push(
      '/ip4/0.0.0.0/udp/0/webrtc-direct',
      '/ip6/::/udp/0/webrtc-direct'
    )
  }

  /**
   * When the primary TCP bind is a single WAN/LAN IP (`NOSPOON_HELIA_SWARM_BIND=auto`), mesh TUN
   * addresses (10.x) are not covered — only `/tcp/0/ws` on 0.0.0.0 shows up there with ephemeral ports.
   * Add explicit `/ip4/<mesh>/tcp/<port>` (+ QUIC) so mesh peers can dial the fixed swarm port.
   */
  const extraListenV4 = mergeExtraListenIpv4(
    o.extraListenIpv4,
    nospoonHeliaExtraListenIpv4FromEnv()
  )
  if (v4tcpQuicHost !== '0.0.0.0' && extraListenV4.length > 0) {
    for (let i = 0; i < extraListenV4.length; i++) {
      const ip = extraListenV4[i]
      if (ip === v4tcpQuicHost) continue
      listen.push(`/ip4/${ip}/tcp/${port}`)
      if (heliaQuicInserted) {
        listen.push(`/ip4/${ip}/udp/${port}/quic-v1`)
      }
    }
  }

  listen.push('/p2p-circuit')

  /** @type {{ listen: string[], appendAnnounce?: string[], announceFilter?: function(Array): Array }} */
  const addresses = { listen }
  if (appendAnnounce.length > 0) {
    addresses.appendAnnounce = appendAnnounce
  }
  /**
   * Relay-circuit addrs (…/p2p/<relay>/p2p-circuit/p2p/<self>) dial via a public relay (e.g. bootstrap
   * infra on 104.x), not your WAN IP. Kubo’s /ip4/76…/udp/12634/… lines are **direct** NAT. Omitting
   * circuit addrs from announcements can align DHT records with “direct only” when you have UPnP or
   * NOSPOON_HELIA_APPEND_ANNOUNCE set — risky if you have no public direct path.
   */
  if (announceNoCircuit) {
    addresses.announceFilter = function (addrs) {
      return addrs.filter(function (ma) {
        return ma.toString().indexOf('/p2p-circuit') === -1
      })
    }
  }

  return {
    addresses,
    transports,
    services
  }
}

/**
 * @param {string} dataDir
 * @param {{
 *   dhtClientMode?: boolean,
 *   upnpAutoConfirmAddress?: boolean,
 *   appendAnnounce?: string[],
 *   announceNoCircuit?: boolean,
 *   webrtc?: boolean,
 *   extraListenIpv4?: string[],
 *   swarmListenIpv4?: string | null,
 *   swarmPort?: number,
 *   disableUpnp?: boolean
 * }} [heliaOpts] — `dhtClientMode` from control UI when set; otherwise `NOSPOON_HELIA_DHT_CLIENT_MODE`. UPnP and append-announce default from env. WebRTC defaults off on Linux (`NOSPOON_HELIA_WEBRTC`). `swarmListenIpv4` optional explicit primary TCP/QUIC bind (from default-route interface); `null` means wildcard. `extraListenIpv4` adds spoon/topic TUN addresses when the primary v4 bind is not wildcard. `swarmPort` overrides fixed TCP/QUIC listen port (default: `nospoonHeliaSwarmPort()` / env `NOSPOON_HELIA_SWARM_PORT`). `disableUpnp` skips `@libp2p/upnp-nat` (avoids SSDP port 1900 when another Helia is running).
 * @returns {Promise<{ helia: import('helia').Helia, stop: function(): Promise<void>, resolveContent: function(o: object): Promise<object> }>}
 */
async function createHeliaBackend (dataDir, heliaOpts) {
  const opts = heliaOpts && typeof heliaOpts === 'object' ? heliaOpts : {}
  const dhtClientMode =
    typeof opts.dhtClientMode === 'boolean'
      ? opts.dhtClientMode
      : nospoonHeliaEnvBool('NOSPOON_HELIA_DHT_CLIENT_MODE', false)
  const upnpAutoConfirmAddress =
    typeof opts.upnpAutoConfirmAddress === 'boolean'
      ? opts.upnpAutoConfirmAddress
      : nospoonHeliaEnvBool('NOSPOON_HELIA_UPNP_AUTO_CONFIRM', true)
  const announceNoCircuit =
    typeof opts.announceNoCircuit === 'boolean'
      ? opts.announceNoCircuit
      : nospoonHeliaEnvBool('NOSPOON_HELIA_ANNOUNCE_NO_CIRCUIT', false)
  const webrtcOpt =
    typeof opts.webrtc === 'boolean' ? opts.webrtc : undefined
  const swarmPortOverride =
    typeof opts.swarmPort === 'number' &&
    opts.swarmPort >= 1 &&
    opts.swarmPort <= 65535
      ? opts.swarmPort
      : null
  const statusMeta = {
    dhtClientMode,
    upnpAutoConfirmAddress,
    announceNoCircuit,
    webrtc: webrtcOpt
  }

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
  const libp2p = await nospoonHeliaLibp2pOptions(
    swarmPortOverride != null ? swarmPortOverride : nospoonHeliaSwarmPort(),
    {
      dhtClientMode,
      upnpAutoConfirmAddress,
      announceNoCircuit,
      appendAnnounce: Array.isArray(opts.appendAnnounce) ? opts.appendAnnounce : undefined,
      webrtc: webrtcOpt,
      extraListenIpv4: Array.isArray(opts.extraListenIpv4)
        ? opts.extraListenIpv4
        : undefined,
      disableUpnp: opts.disableUpnp === true,
      swarmListenIpv4: Object.prototype.hasOwnProperty.call(opts, 'swarmListenIpv4')
        ? opts.swarmListenIpv4
        : undefined
    }
  )
  const helia = await createHelia({ blockstore, datastore, libp2p })
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
    try {
      await helia.routing.cancelReprovide(cid)
    } catch (_) {}
    // Do not await gc here: a full blockstore walk can take a long time and blocks the control
    // panel + CID gateway on the same Helia instance. Reclaim blocks in the background.
    const h = helia
    setTimeout(function () {
      h.gc().catch(function () {})
    }, 100)
  }

  /**
   * Re-announce pinned roots on a timer so provider records stay fresh (similar idea to Kubo reprovide),
   * without any user-facing IPFS/libp2p configuration.
   */
  const REPROVIDE_INTERVAL_MS = 45 * 60 * 1000
  /** @type {ReturnType<typeof setInterval> | null} */
  let reprovideTimer = null
  /** @type {ReturnType<typeof setTimeout> | null} */
  let reprovideOnAddrDebounce = null

  async function reprovideAllPinnedRoots () {
    try {
      for await (const pin of helia.pins.ls()) {
        await announceProvideRoot(helia, pin.cid)
      }
    } catch (e) {
      console.warn(
        '[nospoon helia] reprovide sweep failed:',
        e && e.message ? e.message : String(e)
      )
    }
  }

  reprovideTimer = setInterval(function () {
    void reprovideAllPinnedRoots()
  }, REPROVIDE_INTERVAL_MS)
  if (typeof reprovideTimer.unref === 'function') reprovideTimer.unref()
  setTimeout(function () {
    void reprovideAllPinnedRoots()
  }, 20_000)

  function scheduleReprovideAfterAddrChange () {
    if (reprovideOnAddrDebounce != null) {
      clearTimeout(reprovideOnAddrDebounce)
    }
    reprovideOnAddrDebounce = setTimeout(function () {
      reprovideOnAddrDebounce = null
      void reprovideAllPinnedRoots()
    }, 3000)
    if (
      reprovideOnAddrDebounce != null &&
      typeof reprovideOnAddrDebounce.unref === 'function'
    ) {
      reprovideOnAddrDebounce.unref()
    }
  }
  helia.libp2p.addEventListener('self:peer:update', scheduleReprovideAfterAddrChange)

  /**
   * Dialing by PeerId loads *all* peer-store addrs; libp2p stops after {@code maxPeerAddrsToDial} (~25) failures.
   * We dial **only** `/ip4/<mesh>/tcp|udp/<port>` with **no** `/p2p/<PeerId>` so the secure handshake
   * supplies the remote PeerId (see libp2p upgrader: “dial a multiaddr without a peer id”).
   * Re-try on a timer until connected.
   */
  const MESH_HELIA_REDIAL_MS = 25 * 1000
  const MESH_HELIA_DIAL_TIMEOUT_MS = 35 * 1000

  /** @type {Map<string, { mas: import('@multiformats/multiaddr').Multiaddr[], learnedPeerId: string | null, dialInFlight: boolean, lastDialError: string | null }>} */
  const meshHeliaDialByTarget = new Map()
  /** @type {ReturnType<typeof setInterval> | null} */
  let meshHeliaDialTimer = null

  function meshHeliaDialSignalOptions () {
    try {
      if (
        typeof AbortSignal !== 'undefined' &&
        typeof AbortSignal.timeout === 'function'
      ) {
        return { signal: AbortSignal.timeout(MESH_HELIA_DIAL_TIMEOUT_MS) }
      }
    } catch (_) {}
    return {}
  }

  /**
   * @param {{ mas: import('@multiformats/multiaddr').Multiaddr[], learnedPeerId: string | null, dialInFlight: boolean, lastDialError: string | null }} row
   */
  async function tryDialMeshHeliaTarget (row) {
    const lp = helia.libp2p
    if (row.dialInFlight) return
    if (row.learnedPeerId) {
      try {
        const { peerIdFromString } = await import('@libp2p/peer-id')
        const pid = peerIdFromString(row.learnedPeerId)
        if (lp.getConnections(pid).length > 0) return
      } catch (_) {
        row.learnedPeerId = null
      }
    }
    if (!row.mas.length) return
    row.dialInFlight = true
    try {
      const conn = await lp.dial(row.mas.slice(), meshHeliaDialSignalOptions())
      if (conn != null && conn.remotePeer != null) {
        const rid = conn.remotePeer.toString()
        if (rid === lp.peerId.toString()) return
        row.learnedPeerId = rid
        row.lastDialError = null
      }
    } catch (e) {
      const msg = e && e.message ? String(e.message) : String(e)
      row.lastDialError = msg.length > 240 ? msg.slice(0, 237) + '…' : msg
    } finally {
      row.dialInFlight = false
    }
  }

  function ensureMeshHeliaDialTicker () {
    if (meshHeliaDialTimer != null) return
    meshHeliaDialTimer = setInterval(function () {
      for (const row of meshHeliaDialByTarget.values()) {
        void tryDialMeshHeliaTarget(row)
      }
    }, MESH_HELIA_REDIAL_MS)
    if (typeof meshHeliaDialTimer.unref === 'function') {
      meshHeliaDialTimer.unref()
    }
  }

  /**
   * Register mesh IPv4 + libp2p swarm port and dial Helia without a known PeerId (handshake discovers it).
   * Optional {@code peerIdStr} is ignored for dialing; kept for API compatibility with callers.
   * @param {{ meshIpv4: string, peerIdStr?: string, port?: number }} o
   * @returns {Promise<void>}
   */
  async function mergeMeshHeliaPeer (o) {
    const ip = String(o.meshIpv4 || '').trim()
    if (!net.isIPv4(ip)) return
    const p =
      o.port != null && Number.isFinite(Number(o.port))
        ? Number(o.port)
        : nospoonHeliaSwarmPort()
    if (p !== (p | 0) || p < 1 || p > 65535) return
    const { multiaddr } = await import('@multiformats/multiaddr')
    /** @type {import('@multiformats/multiaddr').Multiaddr[]} */
    const mas = []
    try {
      mas.push(multiaddr(`/ip4/${ip}/tcp/${p}`))
    } catch (_) {
      return
    }
    const nodeMajor = parseInt(
      String(process.versions.node).split('.')[0] || '0',
      10
    )
    if (nodeMajor >= 22) {
      try {
        mas.push(multiaddr(`/ip4/${ip}/udp/${p}/quic-v1`))
      } catch (_) {}
    }
    const targetKey = `${ip}:${p}`
    const prev = meshHeliaDialByTarget.get(targetKey)
    meshHeliaDialByTarget.set(targetKey, {
      mas: mas.slice(),
      learnedPeerId: prev != null ? prev.learnedPeerId : null,
      lastDialError: prev != null ? prev.lastDialError : null,
      dialInFlight: false
    })
    ensureMeshHeliaDialTicker()
    const row = meshHeliaDialByTarget.get(targetKey)
    if (row != null) await tryDialMeshHeliaTarget(row)
  }

  /**
   * Snapshot of mesh Helia dial targets (for control UI: map mesh IP → learned libp2p PeerId).
   * @returns {{ targets: Array<{ targetKey: string, meshIpv4: string, port: number, learnedPeerId: string | null, dialInFlight: boolean, lastDialError: string | null }> }}
   */
  function meshHeliaDialStatus () {
    /** @type {Array<{ targetKey: string, meshIpv4: string, port: number, learnedPeerId: string | null, dialInFlight: boolean, lastDialError: string | null }>} */
    const targets = []
    for (const [targetKey, row] of meshHeliaDialByTarget) {
      const i = targetKey.lastIndexOf(':')
      if (i <= 0) continue
      const meshIpv4 = targetKey.slice(0, i)
      const port = parseInt(targetKey.slice(i + 1), 10)
      if (
        !net.isIPv4(meshIpv4) ||
        port !== (port | 0) ||
        port < 1 ||
        port > 65535
      ) {
        continue
      }
      targets.push({
        targetKey,
        meshIpv4,
        port,
        learnedPeerId: row.learnedPeerId,
        dialInFlight: Boolean(row.dialInFlight),
        lastDialError:
          row.lastDialError != null && String(row.lastDialError).trim() !== ''
            ? String(row.lastDialError)
            : null
      })
    }
    return { targets }
  }

  return {
    helia,
    stop: function () {
      if (reprovideTimer != null) {
        clearInterval(reprovideTimer)
        reprovideTimer = null
      }
      if (meshHeliaDialTimer != null) {
        clearInterval(meshHeliaDialTimer)
        meshHeliaDialTimer = null
      }
      meshHeliaDialByTarget.clear()
      if (reprovideOnAddrDebounce != null) {
        clearTimeout(reprovideOnAddrDebounce)
        reprovideOnAddrDebounce = null
      }
      try {
        helia.libp2p.removeEventListener(
          'self:peer:update',
          scheduleReprovideAfterAddrChange
        )
      } catch (_) {}
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
     * @param {{ filename: string, content: Buffer | Uint8Array | AsyncIterable<Uint8Array> }} opts
     * @returns {Promise<string>} CID string (v1 base32 by default)
     */
    addFile: async function (opts) {
      const name = String(opts.filename || 'upload')
        .replace(/[/\\]/g, '_')
        .trim() || 'upload'
      const raw = opts.content
      const content =
        raw != null &&
        typeof raw === 'object' &&
        typeof raw[Symbol.asyncIterator] === 'function'
          ? raw
          : raw instanceof Uint8Array
            ? raw
            : Buffer.from(raw)
      const cid = await ufs.addFile({
        path: name,
        content
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
      await announceProvideRoot(helia, cid)
      return cid.toString()
    },
    /**
     * Import a directory tree via unixfs.addAll from on-disk temp files (streamed per file).
     * Caller removes the temp directory after RPC returns; streams are consumed during import.
     * @param {Array<{ path: string, absPath: string }>} entries
     * @returns {Promise<{ cid: string, filename: string }>}
     */
    addDirectoryFromPaths: async function (entries) {
      if (!Array.isArray(entries) || entries.length === 0) {
        throw new Error('no files in directory upload')
      }
      const seen = new Set()
      /** @type {Array<{ path: string, content: AsyncIterable<Uint8Array> }>} */
      const normalized = []
      for (const e of entries) {
        const unixPath = normalizeUnixfsRelPath(e.path)
        if (seen.has(unixPath)) throw new Error('duplicate path: ' + unixPath)
        seen.add(unixPath)
        const absPath = String(e.absPath || '').trim()
        if (!absPath || !fs.existsSync(absPath)) {
          throw new Error('missing temp file for path: ' + unixPath)
        }
        const st = fs.statSync(absPath)
        if (!st.isFile()) throw new Error('invalid temp file for path: ' + unixPath)
        let rs = null
        rs = fs.createReadStream(absPath, { highWaterMark: 1024 * 1024 })
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
        normalized.push({ path: unixPath, content: chunks() })
      }
      let last
      for await (const imp of ufs.addAll(normalized)) {
        last = imp
      }
      if (!last || !last.cid) throw new Error('unixfs import failed')
      const rootCid = last.cid
      const rootPath = String(last.path || 'directory')
      const displayName = rootPath.endsWith('/') ? rootPath : rootPath + '/'
      try {
        for await (const _ of helia.pins.add(rootCid, {
          metadata: { filename: displayName }
        })) {
          // drain
        }
      } catch (e) {
        if (e && e.name === 'AlreadyPinnedError') {
          await helia.pins.setMetadata(rootCid, { filename: displayName })
        } else {
          throw e
        }
      }
      await announceProvideRoot(helia, rootCid)
      return { cid: rootCid.toString(), filename: displayName }
    },
    /**
     * libp2p identity, listen addresses, and swarm diagnostics (for control UI / debugging).
     * @returns {Promise<object>}
     */
    libp2pStatus: function () {
      return libp2pStatusSnapshot(helia, statusMeta)
    },
    meshHeliaDialStatus,
    mergeMeshHeliaPeer
  }
}

module.exports = {
  contentTypeForPath,
  resolveWithHeliaUnixfs,
  resolveViaExternalGateway,
  createHeliaBackend,
  nospoonHeliaSwarmPort,
  nospoonHeliaSwarmIpv4ListenHost,
  normalizeUnixfsRelPath
}
