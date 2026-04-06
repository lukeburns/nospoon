/**
 * Minimal browser-side `net`-style API over the control-plane `/api/browser-net` WebSocket
 * (server: Node {@link ./browser-net-middleware.js} or nospoon’s `lib/browser-net-proxy.js` adapter).
 *
 * Uses {@link EventTarget}; {@link #on} is a small convenience alias for {@link EventTarget#addEventListener}.
 *
 * ## `net` polyfill
 * Call {@link setBrowserNetProxy} for the WebSocket bridge (`hostname` / `port` of the control server),
 * then use {@link BrowserNetServer} / {@link BrowserNetSocket} or the Node-shaped shim in `shims/net.js`.
 * Outbound mesh `connect` and full API parity are still to do.
 */

/** Must match `BIN_TAG` in the mesh proxy */
export const BIN_TAG = 0x01

/**
 * Where to open the WebSocket (control plane). Same idea as net-browserify’s `net.setProxy`.
 * @type {{ hostname: string, port?: number, pathname?: string, secure?: boolean } | null}
 */
let _browserNetProxyWsOverride = null

/**
 * @param {{ hostname: string, port?: number, pathname?: string, secure?: boolean } | null | undefined} opts — pass `null` to clear
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

/** @returns {typeof _browserNetProxyWsOverride} */
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
    /** @type {WebSocket | null} */
    this._ws = null
    /** @type {Map<number, BrowserNetSocket>} */
    this._sockets = new Map()
    this._listening = false
    /** @type {{ port: number, host?: string } | null} */
    this._bind = null
    this._messageBound = this._onWsMessage.bind(this)
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
   * @returns {Promise<void>}
   */
  _ensureWs () {
    if (this._ws && this._ws.readyState === WebSocket.OPEN) return Promise.resolve()
    if (this._ws && this._ws.readyState === WebSocket.CONNECTING) {
      return new Promise((resolve, reject) => {
        const ws = this._ws
        if (!ws) return reject(new Error('closed'))
        ws.addEventListener('open', () => resolve(), { once: true })
        ws.addEventListener('error', () => reject(new Error('WebSocket error')), {
          once: true
        })
      })
    }
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this._url)
      ws.binaryType = 'arraybuffer'
      this._ws = ws
      ws.addEventListener('message', this._messageBound)
      ws.addEventListener('open', function () {
        try {
          ws.send(JSON.stringify({ op: 'hello', v: 1 }))
        } catch (_) {}
        resolve()
      })
      ws.addEventListener('error', function () {
        reject(new Error('WebSocket error'))
      })
    })
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
    const ws = this._ws
    if (!ws) throw new Error('WebSocket closed')
    const rid = `l-${Date.now()}-${Math.random().toString(16).slice(2)}`
    const self = this
    return new Promise((resolve, reject) => {
      const onMsg = (ev) => {
        if (typeof ev.data !== 'string') return
        let j
        try {
          j = JSON.parse(ev.data)
        } catch {
          return
        }
        if (j.rid !== rid) return
        ws.removeEventListener('message', onMsg)
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
      }
      ws.addEventListener('message', onMsg)
      const body = { op: 'listen', port, rid }
      if (host != null) body.host = host
      try {
        ws.send(JSON.stringify(body))
      } catch (e) {
        ws.removeEventListener('message', onMsg)
        reject(e instanceof Error ? e : new Error(String(e)))
      }
    })
  }

  /**
   * @param {MessageEvent} ev
   */
  _onWsMessage (ev) {
    if (typeof ev.data === 'string') {
      let j
      try {
        j = JSON.parse(ev.data)
      } catch {
        return
      }
      if (j.op === 'accept' && j.stream != null && j.local && j.remote) {
        const sock = new BrowserNetSocket(this._ws, j.stream, {
          localAddress: j.local.ip,
          localPort: j.local.port,
          remoteAddress: j.remote.ip,
          remotePort: j.remote.port
        })
        this._sockets.set(j.stream >>> 0, sock)
        this.dispatchEvent(
          new CustomEvent('connection', { detail: sock })
        )
      }
      if (j.op === 'end' && j.stream != null) {
        const sid = j.stream >>> 0
        const sock = this._sockets.get(sid)
        if (sock) {
          this._sockets.delete(sid)
          sock._pushEnd()
        }
      }
      return
    }
    const ab = ev.data
    if (!(ab instanceof ArrayBuffer) || ab.byteLength < 5) return
    const u8 = new Uint8Array(ab)
    if (u8[0] !== BIN_TAG) return
    const sid = new DataView(ab).getUint32(1, false)
    const sock = this._sockets.get(sid)
    if (sock) sock._pushData(u8.subarray(5))
  }

  /**
   * @param {function(): void} [cb]
   */
  close (cb) {
    for (const s of this._sockets.values()) {
      try {
        s.end()
      } catch (_) {}
    }
    this._sockets.clear()
    const ws = this._ws
    if (ws && ws.readyState === WebSocket.OPEN && this._listening && this._bind) {
      try {
        const rid = `u-${Date.now()}`
        const msg = { op: 'unlisten', port: this._bind.port, rid }
        if (this._bind.host != null) msg.host = this._bind.host
        ws.send(JSON.stringify(msg))
      } catch (_) {}
    }
    this._listening = false
    this._bind = null
    if (ws) {
      try {
        ws.removeEventListener('message', this._messageBound)
      } catch (_) {}
      try {
        ws.close()
      } catch (_) {}
    }
    this._ws = null
    if (cb) queueMicrotask(cb)
  }
}
