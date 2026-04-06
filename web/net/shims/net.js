'use strict'

/**
 * Browser **`net` module** for bundled apps (esbuild + Node polyfills). Import as `net-browser`,
 * `net-browser/net`, or alias bare `net` → this file.
 *
 * **Setup:** {@link setBrowserNetProxy}({ hostname, port?, pathname?, secure? }) so the WebSocket
 * targets your control plane (default pathname `/api/browser-net`).
 *
 * **Node-shaped API**
 * - {@link createServer} / {@link Server} — `listen(port[, host][, cb])`, emit `'connection'` with a {@link Socket}
 * - {@link Socket} — `stream.Duplex`; `remoteAddress`, `remotePort`, `localAddress`, `localPort`;
 *   `setEncoding`, `setTimeout` / `setNoDelay` / `setKeepAlive` (mostly no-ops)
 * - {@link createConnection} / {@link connect} — Node argument shapes; buffers writes until the
 *   WebSocket `connect` handshake completes, then emits `'connect'`
 * - {@link defaultBrowserNetWsUrl} — derive WS URL from `location` when not using `setBrowserNetProxy`
 *
 * **Lower-level:** `browser-net-client` exports `BrowserNetServer`, `BrowserNetSocket`, `browserNetConnect`.
 */

import { Duplex } from 'stream'
import { EventEmitter } from 'events'
import { StringDecoder } from 'string_decoder'
import {
  BrowserNetServer,
  BrowserNetSocket,
  browserNetConnect,
  setBrowserNetProxy,
  defaultBrowserNetWsUrl,
  getBrowserNetProxyOverride
} from '../lib/browser-net-client.js'

export { setBrowserNetProxy, defaultBrowserNetWsUrl, getBrowserNetProxyOverride }

/**
 * @param {import('../lib/browser-net-client.js').BrowserNetSocket} inner
 */
export class Socket extends Duplex {
  /**
   * @param {import('../lib/browser-net-client.js').BrowserNetSocket} inner
   */
  constructor (inner) {
    super({ allowHalfOpen: false })
    /** @private */
    this._inner = inner
    /** @private @type {string | null} */
    this._encoding = null
    /** @private @type {StringDecoder | null} */
    this._decoder = null

    this.remoteAddress = inner.remoteAddress
    this.remotePort = inner.remotePort
    this.localAddress = inner.localAddress
    this.localPort = inner.localPort

    const onData = (ev) => {
      const u8 = ev.data
      if (!u8 || this.destroyed) return
      if (this._encoding && this._decoder) {
        const s = this._decoder.write(Buffer.from(u8))
        if (s) this.push(s)
      } else {
        this.push(Buffer.from(u8))
      }
    }
    const onEnd = () => {
      if (this._decoder) {
        const tail = this._decoder.end()
        if (tail) this.push(tail)
      }
      this.push(null)
    }
    const onClose = () => {
      if (!this.destroyed) this.destroy()
    }

    inner.addEventListener('data', onData)
    inner.addEventListener('end', onEnd)
    inner.addEventListener('close', onClose)

    this.once('close', () => {
      inner.removeEventListener('data', onData)
      inner.removeEventListener('end', onEnd)
      inner.removeEventListener('close', onClose)
    })
  }

  /**
   * Readable data is {@link Duplex#push}ed from the inner socket’s `data` events (no underlying pull).
   * Required by the browser `stream` polyfill; matches Node’s push-based {@code net.Socket}.
   * @param {number} [_size]
   */
  _read (_size) {}

  /** @param {BufferEncoding} encoding */
  setEncoding (encoding) {
    this._encoding = encoding || null
    this._decoder = encoding ? new StringDecoder(encoding) : null
    return this
  }

  setTimeout (msecs, callback) {
    if (typeof callback === 'function') {
      setTimeout(callback, Number(msecs) || 0)
    }
    return this
  }

  setNoDelay () {
    return this
  }

  setKeepAlive () {
    return this
  }

  /**
   * @param {Buffer | string | Uint8Array} chunk
   * @param {BufferEncoding} [encoding]
   * @param {(err?: Error) => void} callback
   */
  _write (chunk, encoding, callback) {
    try {
      this._inner.write(chunk, encoding, callback)
    } catch (err) {
      callback(/** @type {Error} */ (err))
    }
  }

  /**
   * @param {(err?: Error) => void} callback
   */
  _final (callback) {
    try {
      this._inner.end()
    } catch (_) {}
    queueMicrotask(() => callback())
  }

  /**
   * @param {Error} [err]
   * @param {(err?: Error) => void} callback
   */
  _destroy (err, callback) {
    try {
      this._inner.end()
    } catch (_) {}
    callback(err)
  }
}

/**
 * Outbound TCP client: wraps {@link browserNetConnect} in a Node-shaped `Duplex` with `connecting`
 * and buffered writes until the mesh middleman completes the handshake.
 */
class ConnectingSocket extends Duplex {
  /**
   * @param {{ port: number, host: string, localHost?: string, url?: string, location?: Location }} opts
   */
  constructor (opts) {
    super({ allowHalfOpen: false })
    this.connecting = true
    this.remoteAddress = undefined
    this.remotePort = undefined
    this.localAddress = undefined
    this.localPort = undefined
    /** @private @type {string | null} */
    this._pendingEncoding = null
    /** @private @type {Socket | null} */
    this._wrapped = null
    /** @private */
    this._pendingWrites = []
    /** @private @type {((err?: Error) => void) | null} */
    this._pendingFinal = null

    const self = this
    browserNetConnect({
      port: opts.port,
      host: opts.host,
      localHost: opts.localHost,
      url: opts.url,
      location: opts.location
    }).then(
      function (inner) {
        if (self.destroyed) {
          try {
            inner.end()
          } catch (_) {}
          return
        }
        self._attach(inner)
      },
      function (err) {
        self.connecting = false
        const e = err instanceof Error ? err : new Error(String(err))
        for (const row of self._pendingWrites) {
          const cbWrite = row[2]
          if (typeof cbWrite === 'function') queueMicrotask(() => cbWrite(e))
        }
        self._pendingWrites = []
        if (self._pendingFinal != null) {
          const f = self._pendingFinal
          self._pendingFinal = null
          queueMicrotask(() => f(e))
        }
        queueMicrotask(function () {
          self.emit('error', e)
          self.destroy(e)
        })
      }
    )
  }

  /** @param {import('../lib/browser-net-client.js').BrowserNetSocket} inner */
  _attach (inner) {
    const wrapped = new Socket(inner)
    this._wrapped = wrapped
    this.remoteAddress = wrapped.remoteAddress
    this.remotePort = wrapped.remotePort
    this.localAddress = wrapped.localAddress
    this.localPort = wrapped.localPort

    if (this._pendingEncoding != null) {
      wrapped.setEncoding(this._pendingEncoding)
      this._pendingEncoding = null
    }

    const onData = (chunk) => {
      if (!this.destroyed) this.push(chunk)
    }
    const onEnd = () => {
      if (!this.destroyed) this.push(null)
    }
    const onClose = () => {
      if (!this.destroyed) this.destroy()
    }
    wrapped.on('data', onData)
    wrapped.on('end', onEnd)
    wrapped.on('close', onClose)
    this.once('close', () => {
      wrapped.removeListener('data', onData)
      wrapped.removeListener('end', onEnd)
      wrapped.removeListener('close', onClose)
    })

    for (const row of this._pendingWrites) {
      wrapped.write(row[0], row[1], row[2])
    }
    this._pendingWrites = []
    if (this._pendingFinal != null) {
      const f = this._pendingFinal
      this._pendingFinal = null
      wrapped.end(() => queueMicrotask(() => f()))
    }

    this.connecting = false
    queueMicrotask(() => this.emit('connect'))
  }

  /**
   * Readable side is fed by forwarding the wrapped {@link Socket}’s `data` events via {@link Duplex#push}.
   * @param {number} [_size]
   */
  _read (_size) {}

  /** @param {BufferEncoding} encoding */
  setEncoding (encoding) {
    if (this._wrapped) {
      this._wrapped.setEncoding(encoding)
    } else {
      this._pendingEncoding = encoding || null
    }
    return this
  }

  setTimeout (msecs, callback) {
    if (this._wrapped) return this._wrapped.setTimeout(msecs, callback)
    if (typeof callback === 'function') {
      setTimeout(callback, Number(msecs) || 0)
    }
    return this
  }

  setNoDelay () {
    return this
  }

  setKeepAlive () {
    return this
  }

  /**
   * @param {Buffer | string | Uint8Array} chunk
   * @param {BufferEncoding} [encoding]
   * @param {(err?: Error) => void} callback
   */
  _write (chunk, encoding, callback) {
    if (this._wrapped) {
      return this._wrapped.write(chunk, encoding, callback)
    }
    this._pendingWrites.push([chunk, encoding, callback])
  }

  /**
   * @param {(err?: Error) => void} callback
   */
  _final (callback) {
    if (this._wrapped) {
      this._wrapped.end(() => queueMicrotask(() => callback()))
      return
    }
    this._pendingFinal = callback
  }

  /**
   * @param {Error} [err]
   * @param {(err?: Error) => void} callback
   */
  _destroy (err, callback) {
    if (this._wrapped) {
      try {
        this._wrapped.destroy(err)
      } catch (_) {}
    } else {
      const e = err || new Error('Socket closed before connect')
      for (const row of this._pendingWrites) {
        const cbWrite = row[2]
        if (typeof cbWrite === 'function') queueMicrotask(() => cbWrite(e))
      }
      this._pendingWrites = []
      if (this._pendingFinal != null) {
        const f = this._pendingFinal
        this._pendingFinal = null
        queueMicrotask(() => f(e))
      }
    }
    callback(err)
  }
}

/**
 * @param {number | object} portOrOpts
 * @param {string | function(): void} [hostOrCb]
 * @param {function(): void} [cb]
 * @returns {{ port: number, host: string, localHost?: string, url?: string, location?: Location, cb?: function(): void }}
 */
function normalizeConnectArgs (portOrOpts, hostOrCb, cb) {
  if (portOrOpts != null && typeof portOrOpts === 'object' && !Array.isArray(portOrOpts)) {
    const o = portOrOpts
    if (o.path != null) {
      throw new Error('net: IPC path connections are not supported in the browser shim')
    }
    if (o.port == null) {
      throw new TypeError('connect options must include port')
    }
    return {
      port: Number(o.port),
      host: o.host != null ? String(o.host) : '127.0.0.1',
      localHost: o.localAddress != null ? String(o.localAddress) : undefined,
      url: o.url,
      location: o.location,
      cb: typeof hostOrCb === 'function' ? hostOrCb : undefined
    }
  }
  const port = Number(portOrOpts)
  let host = '127.0.0.1'
  let callback
  if (typeof hostOrCb === 'string') {
    host = hostOrCb
    callback = typeof cb === 'function' ? cb : undefined
  } else {
    callback = typeof hostOrCb === 'function' ? hostOrCb : undefined
  }
  return { port, host, cb: callback }
}

export class Server extends EventEmitter {
  /**
   * @param {object | function(import('net').Socket): void} [optionsOrListener]
   * @param {function(import('net').Socket): void} [connectionListener]
   */
  constructor (optionsOrListener, connectionListener) {
    super()
    let opts = {}
    let cb = connectionListener
    if (typeof optionsOrListener === 'function') {
      cb = optionsOrListener
    } else if (optionsOrListener != null && typeof optionsOrListener === 'object') {
      opts = optionsOrListener
    }
    /** @private @type {import('../lib/browser-net-client.js').BrowserNetServer} */
    this._inner = new BrowserNetServer(opts)
    /** @private */
    this._listening = false
    /** @private @type {number | null} */
    this._port = null
    /** @private @type {string | undefined} */
    this._host = undefined

    if (typeof cb === 'function') this.on('connection', cb)

    this._inner.addEventListener('connection', (ev) => {
      const innerSock = /** @type {import('../lib/browser-net-client.js').BrowserNetSocket} */ (
        ev.detail
      )
      const sock = new Socket(innerSock)
      this.emit('connection', sock)
    })
  }

  /**
   * @param {number | { port: number, host?: string, exclusive?: boolean }} portOrOpts
   * @param {string | function(): void} [hostOrCb]
   * @param {function(): void} [cb]
   * @returns {Promise<void>}
   */
  listen (portOrOpts, hostOrCb, cb) {
    let port
    let host
    if (typeof portOrOpts === 'object' && portOrOpts !== null) {
      port = Number(portOrOpts.port)
      host = portOrOpts.host
    } else {
      port = Number(portOrOpts)
      if (typeof hostOrCb === 'string') host = hostOrCb
    }
    this._port = port
    this._host = host

    return this._inner.listen(portOrOpts, hostOrCb, cb).then(() => {
      this._listening = true
      this.emit('listening')
    })
  }

  address () {
    if (!this._listening || this._port == null) return null
    const address =
      typeof this._host === 'string' && this._host.length ? this._host : '0.0.0.0'
    return { port: this._port, family: 'IPv4', address }
  }

  /**
   * @param {function(): void} [cb]
   */
  close (cb) {
    this._inner.close(() => {
      this._listening = false
      this.emit('close')
      if (typeof cb === 'function') cb()
    })
  }

  get listening () {
    return this._listening
  }
}

/**
 * @param {object | function(import('net').Socket): void} [optionsOrListener]
 * @param {function(import('net').Socket): void} [connectionListener]
 * @returns {Server}
 */
export function createServer (optionsOrListener, connectionListener) {
  return new Server(optionsOrListener, connectionListener)
}

/**
 * @param {number | object} portOrOpts
 * @param {string | function(): void} [hostOrCb]
 * @param {function(): void} [cb]
 * @returns {ConnectingSocket}
 */
export function createConnection (portOrOpts, hostOrCb, cb) {
  const args = normalizeConnectArgs(portOrOpts, hostOrCb, cb)
  if (!Number.isFinite(args.port) || args.port < 1 || args.port > 65535) {
    throw new RangeError('port must be a valid TCP port (1-65535)')
  }
  const { cb: connectCb, ...connOpts } = args
  const sock = new ConnectingSocket(connOpts)
  if (typeof connectCb === 'function') sock.once('connect', connectCb)
  return sock
}

export function connect (portOrOpts, hostOrCb, cb) {
  return createConnection(portOrOpts, hostOrCb, cb)
}

/** @deprecated Use Socket */
export const Stream = Socket

const net = {
  createServer,
  createConnection,
  connect,
  Server,
  Socket,
  Stream,
  setBrowserNetProxy,
  defaultBrowserNetWsUrl,
  getBrowserNetProxyOverride
}

export default net
