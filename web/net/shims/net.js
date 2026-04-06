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
 * - {@link defaultBrowserNetWsUrl} — derive WS URL from `location` when not using `setBrowserNetProxy`
 *
 * **Not implemented:** {@link createConnection} / {@link connect} (needs middleware `connect` op).
 *
 * **Lower-level:** `browser-net-client` exports `BrowserNetServer`, `BrowserNetSocket`, same helpers.
 */

import { Duplex } from 'stream'
import { EventEmitter } from 'events'
import { StringDecoder } from 'string_decoder'
import {
  BrowserNetServer,
  BrowserNetSocket,
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

export function createConnection () {
  throw new Error(
    'net.createConnection is not implemented yet (needs proxy `connect` op + outbound SYN)'
  )
}

export const connect = createConnection

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
