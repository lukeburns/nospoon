/**
 * Browser-side WebSocket client for the browser-net TCP middleman (`browser-net-middleware.js`).
 *
 * Uses a **shared hub per WebSocket URL** so `BrowserNetServer` and `browserNetConnect` share one socket.
 */

/** Must match `BIN_TAG` in the mesh proxy */
export const BIN_TAG = 0x01

/** @type {Map<string, ReturnType<typeof createHubState>>} */
const hubs = new Map()

/**
 * @param {string} url
 */
function createHubState (url) {
  const state = {
    url,
    ws: null,
    _opening: null,
    streams: new Map(),
    activeServer: null,
    connectPending: new Map(),
    ridHandlers: new Map()
  }

  state.onMessage = function (ev) {
    if (typeof ev.data === 'string') {
      let j
      try {
        j = JSON.parse(ev.data)
      } catch {
        return
      }
      if (!j || typeof j !== 'object') return

      const rid = j.rid != null ? String(j.rid) : null
      if (rid && state.ridHandlers.has(rid)) {
        const fn = state.ridHandlers.get(rid)
        state.ridHandlers.delete(rid)
        fn(j)
        return
      }

      if (j.op === 'accept' && j.stream != null && j.local && j.remote) {
        const server = state.activeServer
        if (!server || !server._listening) return
        const sock = new BrowserNetSocket(state.ws, j.stream, {
          localAddress: j.local.ip,
          localPort: j.local.port,
          remoteAddress: j.remote.ip,
          remotePort: j.remote.port
        })
        state.streams.set(j.stream >>> 0, sock)
        server._mySockets.add(sock)
        server.dispatchEvent(new CustomEvent('connection', { detail: sock }))
        return
      }
      if (j.op === 'connected' && j.rid != null && j.stream != null && j.local && j.remote) {
        const pending = state.connectPending.get(String(j.rid))
        if (!pending) return
        state.connectPending.delete(String(j.rid))
        const sock = new BrowserNetSocket(state.ws, j.stream, {
          localAddress: j.local.ip,
          localPort: j.local.port,
          remoteAddress: j.remote.ip,
          remotePort: j.remote.port
        })
        state.streams.set(j.stream >>> 0, sock)
        pending.resolve(sock)
        return
      }
      if (j.op === 'connect_err' && j.rid != null) {
        const pending = state.connectPending.get(String(j.rid))
        if (!pending) return
        state.connectPending.delete(String(j.rid))
        pending.reject(new Error(j.error || 'connect_err'))
        return
      }
      if (j.op === 'end' && j.stream != null) {
        const sid = j.stream >>> 0
        const sock = state.streams.get(sid)
        if (sock) {
          state.streams.delete(sid)
          sock._pushEnd()
        }
        return
      }
      return
    }
    const ab = ev.data
    if (!(ab instanceof ArrayBuffer) || ab.byteLength < 5) return
    const u8 = new Uint8Array(ab)
    if (u8[0] !== BIN_TAG) return
    const sid = new DataView(ab).getUint32(1, false)
    const sock = state.streams.get(sid)
    if (sock) sock._pushData(u8.subarray(5))
  }

  state.ensureOpen = function () {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) return Promise.resolve()
    if (state._opening) return state._opening
    state._opening = new Promise((resolve, reject) => {
      const ws = new WebSocket(state.url)
      ws.binaryType = 'arraybuffer'
      ws.addEventListener('message', state.onMessage)
      ws.addEventListener('open', function () {
        try {
          ws.send(JSON.stringify({ op: 'hello', v: 1 }))
        } catch (_) {}
        state.ws = ws
        state._opening = null
        resolve()
      })
      ws.addEventListener('error', function () {
        state._opening = null
        reject(new Error('WebSocket error'))
      })
    })
    return state._opening
  }

  state.maybeTeardown = function () {
    if (state.streams.size > 0 || state.connectPending.size > 0) return
    if (state.activeServer && state.activeServer._listening) return
    if (state.ws) {
      try {
        state.ws.removeEventListener('message', state.onMessage)
      } catch (_) {}
      try {
        state.ws.close()
      } catch (_) {}
      state.ws = null
    }
    hubs.delete(state.url)
  }

  return state
}

function getOrCreateHub (url) {
  if (!hubs.has(url)) {
    hubs.set(url, createHubState(url))
  }
  return hubs.get(url)
}

let _browserNetProxyWsOverride = null

/**
 * @param {{ hostname: string, port?: number, pathname?: string, secure?: boolean } | null | undefined} opts
 */
export function setBrowserNetProxy (opts) {
  if (opts == null) {
    _browserNetProxyWsOverride = null
    return
  }
  const hostname = opts.hostname != null ? String(opts.hostname).trim() : ''
  if (!hostname) {
    _browserNetProxyWsOverride = null
    return
  }
  _browserNetProxyWsOverride = {
    hostname,
    port: opts.port != null ? Number(opts.port) : undefined,
    pathname:
      opts.pathname != null && String(opts.pathname).trim() !== ''
        ? String(opts.pathname).trim()
        : '/api/browser-net',
    secure: opts.secure === true
  }
}

export function getBrowserNetProxyOverride () {
  return _browserNetProxyWsOverride
}

/**
 * @param {Location | string} loc
 * @returns {string}
 */
export function defaultBrowserNetWsUrl (loc) {
  const o = _browserNetProxyWsOverride
  if (o && o.hostname) {
    const path =
      o.pathname && o.pathname.startsWith('/') ? o.pathname : '/api/browser-net'
    const secure = o.secure === true
    const proto = secure ? 'wss' : 'ws'
    const defaultPort = secure ? 443 : 80
    const portNum = o.port
    const p =
      portNum != null &&
      Number.isFinite(portNum) &&
      Number(portNum) !== defaultPort &&
      Number(portNum) > 0
        ? `:${portNum}`
        : ''
    const hn = o.hostname
    const hostPart =
      hn.includes(':') && !/^\[[^\]]+\]$/.test(hn) && !/^\d+\.\d+\.\d+\.\d+$/.test(hn)
        ? `[${hn}]`
        : hn
    return `${proto}://${hostPart}${p}${path}`
  }
  const u = typeof loc === 'string' ? new URL(loc) : new URL(loc.href)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  u.pathname = '/api/browser-net'
  u.search = ''
  u.hash = ''
  return u.href
}

export class BrowserNetSocket extends EventTarget {
  /**
   * @param {WebSocket} ws
   * @param {number} streamId
   * @param {{ localAddress: string, localPort: number, remoteAddress: string, remotePort: number }} addr
   */
  constructor (ws, streamId, addr) {
    super()
    this._ws = ws
    this._streamId = streamId >>> 0
    this._ended = false
    this.localAddress = addr.localAddress
    this.localPort = addr.localPort
    this.remoteAddress = addr.remoteAddress
    this.remotePort = addr.remotePort
  }

  /**
   * @param {string} type
   * @param {EventListenerOrEventListenerObject} fn
   * @returns {this}
   */
  on (type, fn) {
    this.addEventListener(type, fn)
    return this
  }

  /**
   * @param {string | Uint8Array | ArrayBuffer} chunk
   * @param {string} [_enc]
   * @param {function(): void} [cb]
   * @returns {boolean}
   */
  write (chunk, _enc, cb) {
    if (this._ended) return false
    let buf
    if (typeof chunk === 'string') {
      buf = new TextEncoder().encode(chunk)
    } else if (chunk instanceof ArrayBuffer) {
      buf = new Uint8Array(chunk)
    } else if (ArrayBuffer.isView(chunk)) {
      buf = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)
    } else {
      throw new TypeError('BrowserNetSocket.write: expected string or buffer')
    }
    const out = new Uint8Array(5 + buf.length)
    out[0] = BIN_TAG
    new DataView(out.buffer).setUint32(1, this._streamId, false)
    out.set(buf, 5)
    this._ws.send(out.buffer)
    if (typeof _enc === 'function') queueMicrotask(() => _enc())
    else if (typeof cb === 'function') queueMicrotask(() => cb())
    return true
  }

  /**
   * @param {string | Uint8Array | ArrayBuffer} [chunk]
   * @param {string} [_enc]
   * @param {function(): void} [cb]
   */
  end (chunk, _enc, cb) {
    if (!this._ended) {
      if (chunk != null) this.write(chunk, typeof _enc === 'function' ? undefined : _enc)
      try {
        this._ws.send(JSON.stringify({ op: 'end', stream: this._streamId }))
      } catch (_) {}
      this._ended = true
      this.dispatchEvent(new Event('end'))
      this.dispatchEvent(new Event('close'))
    }
    if (typeof _enc === 'function') queueMicrotask(() => _enc())
    else if (typeof cb === 'function') queueMicrotask(() => cb())
  }

  /** @param {Uint8Array} u8 */
  _pushData (u8) {
    if (this._ended) return
    this.dispatchEvent(new MessageEvent('data', { data: u8 }))
  }

  _pushEnd () {
    if (this._ended) return
    this._ended = true
    this.dispatchEvent(new Event('end'))
    this.dispatchEvent(new Event('close'))
  }
}

export class BrowserNetServer extends EventTarget {
  /**
   * @param {{ url?: string, location?: Location }} [opts]
   */
  constructor (opts = {}) {
    super()
    if (typeof location === 'undefined' && !opts.url) {
      throw new Error('BrowserNetServer: pass opts.url outside a window')
    }
    this._url =
      opts.url ||
      defaultBrowserNetWsUrl(opts.location || /** @type {Location} */ (location))
    this._hub = getOrCreateHub(this._url)
    this._listening = false
    /** @type {{ port: number, host?: string } | null} */
    this._bind = null
    /** @type {Set<BrowserNetSocket>} */
    this._mySockets = new Set()
  }

  on (type, fn) {
    this.addEventListener(type, fn)
    return this
  }

  /**
   * @returns {Promise<void>}
   */
  _ensureWs () {
    return this._hub.ensureOpen()
  }

  /**
   * @param {number | { port: number, host?: string }} portOrOpts
   * @param {string | function(): void} [hostOrCb]
   * @param {function(): void} [cb]
   * @returns {Promise<void>}
   */
  async listen (portOrOpts, hostOrCb, cb) {
    let port
    let host
    let callback
    if (typeof portOrOpts === 'object' && portOrOpts !== null) {
      port = Number(portOrOpts.port)
      host = portOrOpts.host
      callback = typeof hostOrCb === 'function' ? hostOrCb : undefined
    } else {
      port = Number(portOrOpts)
      if (typeof hostOrCb === 'string') host = hostOrCb
      else if (typeof hostOrCb === 'function') callback = hostOrCb
      if (typeof cb === 'function') callback = cb
    }
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      throw new Error('listen: invalid port')
    }
    await this._ensureWs()
    const ws = this._hub.ws
    if (!ws) throw new Error('WebSocket closed')
    this._hub.activeServer = this
    const rid = `l-${Date.now()}-${Math.random().toString(16).slice(2)}`
    const self = this
    const hub = this._hub
    return new Promise((resolve, reject) => {
      hub.ridHandlers.set(rid, function (j) {
        if (j.op === 'listen_ok') {
          self._listening = true
          self._bind = host != null ? { port, host } : { port }
          resolve()
          if (callback) queueMicrotask(callback)
        } else if (j.op === 'listen_err') {
          reject(new Error(j.error || 'listen_err'))
        } else {
          reject(new Error('unexpected listen reply'))
        }
      })
      const body = { op: 'listen', port, rid }
      if (host != null) body.host = host
      try {
        ws.send(JSON.stringify(body))
      } catch (e) {
        hub.ridHandlers.delete(rid)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /**
   * @param {function(): void} [cb]
   */
  close (cb) {
    for (const s of this._mySockets) {
      try {
        s.end()
      } catch (_) {}
      this._hub.streams.delete(s._streamId)
    }
    this._mySockets.clear()
    const ws = this._hub.ws
    if (ws && ws.readyState === WebSocket.OPEN && this._listening && this._bind) {
      const rid = `u-${Date.now()}`
      const hub = this._hub
      hub.ridHandlers.set(rid, function () {
        hub.maybeTeardown()
      })
      try {
        const msg = { op: 'unlisten', port: this._bind.port, rid }
        if (this._bind.host != null) msg.host = this._bind.host
        ws.send(JSON.stringify(msg))
      } catch (_) {
        hub.ridHandlers.delete(rid)
      }
    }
    if (this._hub.activeServer === this) {
      this._hub.activeServer = null
    }
    this._listening = false
    this._bind = null
    this._hub.maybeTeardown()
    if (cb) queueMicrotask(cb)
  }
}

/**
 * @param {{
 *   port: number,
 *   host: string,
 *   localHost?: string,
 *   url?: string,
 *   location?: Location
 * }} opts
 * @returns {Promise<BrowserNetSocket>}
 */
export function browserNetConnect (opts) {
  const port = Number(opts.port)
  const host = opts.host != null ? String(opts.host).trim() : ''
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    return Promise.reject(new Error('connect: invalid port'))
  }
  if (!host) {
    return Promise.reject(new Error('connect: host required'))
  }
  const url =
    opts.url ||
    (typeof location !== 'undefined'
      ? defaultBrowserNetWsUrl(opts.location || location)
      : '')
  if (!url) {
    return Promise.reject(new Error('connect: pass opts.url outside a window'))
  }
  const hub = getOrCreateHub(url)
  const rid = `c-${Date.now()}-${Math.random().toString(16).slice(2)}`
  return hub.ensureOpen().then(function () {
    const ws = hub.ws
    if (!ws) return Promise.reject(new Error('WebSocket closed'))
    return new Promise(function (resolve, reject) {
      hub.connectPending.set(rid, { resolve, reject })
      try {
        ws.send(
          JSON.stringify({
            op: 'connect',
            host,
            port,
            rid,
            localHost: opts.localHost
          })
        )
      } catch (e) {
        hub.connectPending.delete(rid)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  })
}
