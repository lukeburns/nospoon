'use strict'

const http = require('http')

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer'
])

/**
 * Minimal HTTP server on a dedicated local IPv4. Public URL is only `GET /<z32-or-key.topic>`,
 * forwarded to the control plane as `GET /api/whois/<same>`.
 * @param {{ bindAddress: string, port?: number, controlPort: number, onError?: (e: Error) => void }} opts
 */
function createWhoisAuthProxy (opts) {
  const bindAddress = String(opts.bindAddress || '').trim()
  const port = opts.port != null ? Number(opts.port) : 80
  const controlPort = Number(opts.controlPort)
  const onError = typeof opts.onError === 'function' ? opts.onError : function () {}

  if (!bindAddress) throw new Error('whois auth proxy: bindAddress is required')
  if (Number.isNaN(controlPort) || controlPort < 1) {
    throw new Error('whois auth proxy: controlPort is required')
  }

  /** @type {import('http').Server | null} */
  let server = null

  function copyHeaders (req) {
    /** @type {Record<string, string | string[] | undefined>} */
    const out = {}
    for (const key of Object.keys(req.headers)) {
      if (HOP_BY_HOP.has(key.toLowerCase())) continue
      const v = req.headers[key]
      if (v !== undefined) out[key] = v
    }
    out.host = `127.0.0.1:${controlPort}`
    return out
  }

  function onRequest (req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, {
        Allow: 'GET, HEAD',
        'Content-Type': 'text/plain; charset=utf-8'
      })
      res.end('method not allowed\n')
      return
    }

    const raw = req.url || '/'
    let pathname = '/'
    try {
      pathname = new URL(raw, 'http://127.0.0.1').pathname
    } catch (_) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('bad request\n')
      return
    }

    const segments = pathname.replace(/\/$/, '').split('/').filter(Boolean)
    let upstreamPath
    if (segments.length === 0) {
      upstreamPath = '/api/whois/'
    } else if (segments.length === 1) {
      let tail
      try {
        tail = decodeURIComponent(segments[0])
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('bad request\n')
        return
      }
      if (!tail) {
        res.writeHead(404)
        res.end()
        return
      }
      upstreamPath = '/api/whois/' + encodeURIComponent(tail)
    } else {
      res.writeHead(404)
      res.end()
      return
    }
    const upstreamMethod = req.method === 'HEAD' ? 'GET' : req.method
    const headers = copyHeaders(req)

    const p = http.request(
      {
        hostname: '127.0.0.1',
        port: controlPort,
        path: upstreamPath,
        method: upstreamMethod,
        headers
      },
      function (up) {
        if (req.method === 'HEAD') {
          res.writeHead(up.statusCode || 502, up.headers)
          up.resume()
          up.on('end', function () {
            res.end()
          })
          return
        }
        res.writeHead(up.statusCode || 502, up.headers)
        up.pipe(res)
      }
    )

    p.on('error', function (err) {
      onError(err instanceof Error ? err : new Error(String(err)))
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('bad gateway\n')
      } else {
        res.destroy()
      }
    })

    req.on('aborted', function () {
      p.destroy()
    })

    req.pipe(p)
  }

  return {
    /**
     * @returns {Promise<{ port: number }>}
     */
    start () {
      return new Promise(function (resolve, reject) {
        server = http.createServer(onRequest)
        function onListenErr (err) {
          server.removeListener('error', onListenErr)
          server = null
          reject(err)
        }
        server.once('error', onListenErr)
        server.listen(port, bindAddress, function () {
          if (!server) return
          server.removeListener('error', onListenErr)
          server.on('error', function (err) {
            onError(err)
          })
          const addr = server.address()
          const listenPort =
            addr && typeof addr === 'object' ? addr.port : port
          resolve({ port: listenPort })
        })
      })
    },
    /**
     * @returns {Promise<void>}
     */
    stop () {
      return new Promise(function (resolve) {
        if (!server) return resolve()
        const s = server
        server = null
        s.close(function () {
          resolve()
        })
      })
    }
  }
}

module.exports = { createWhoisAuthProxy }
