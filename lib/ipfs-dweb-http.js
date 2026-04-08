'use strict'

const http = require('http')
const { parseIpfsCidHostname } = require('./ipfs-cid-dns')

const MAX_PATH_LEN = 4096

/**
 * Minimal HTTP server on a dedicated loopback IPv4: resolve {@code Host} as a CID string,
 * serve UnixFS paths under that root via {@code resolveContent}.
 *
 * @param {{ bindAddress: string, port?: number, resolveContent: function({ cidStr: string, pathname: string, method: string, signal: AbortSignal }): Promise<{ status: number, headers?: Record<string, string | number | string[]>, body?: Buffer | Uint8Array | AsyncIterable<Uint8Array> }> }} opts
 */
function createIpfsDwebHttpServer (opts) {
  const bindAddress = String(opts.bindAddress || '').trim()
  const port = opts.port != null ? Number(opts.port) : 80
  const resolveContent = opts.resolveContent
  const mintAuthCookie = typeof opts.mintAuthCookie === 'function' ? opts.mintAuthCookie : null
  if (!bindAddress) throw new Error('ipfs dweb http: bindAddress is required')
  if (typeof resolveContent !== 'function') {
    throw new Error('ipfs dweb http: resolveContent is required')
  }

  /** @type {import('http').Server | null} */
  let server = null

  function safePathname (pathname) {
    const p = String(pathname || '/')
    if (p.length > MAX_PATH_LEN) return null
    const dec = decodeURIComponent(p.split('?')[0] || '/')
    const segs = dec.split('/').filter(Boolean)
    for (const seg of segs) {
      if (seg === '..' || seg === '.') return null
    }
    if (!dec.startsWith('/')) return null
    return dec
  }

  async function onRequest (req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('method not allowed\n')
      return
    }

    const hostHeader = String(req.headers.host || '').split(':')[0].trim().toLowerCase()
    const cidStr = parseIpfsCidHostname(hostHeader)
    if (!cidStr) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('host is not a CID\n')
      return
    }

    let pathname = '/'
    try {
      pathname = new URL(req.url || '/', 'http://' + hostHeader).pathname
    } catch (_) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('bad request\n')
      return
    }
    const safe = safePathname(pathname)
    if (safe == null) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('bad path\n')
      return
    }

    const ac = new AbortController()
    const t = setTimeout(function () {
      ac.abort()
    }, 120000)
    req.on('close', function () {
      ac.abort()
    })

    try {
      const out = await resolveContent({
        cidStr,
        pathname: safe,
        method: req.method,
        signal: ac.signal
      })
      clearTimeout(t)
      const headers = { ...out.headers }
      if (mintAuthCookie) {
        headers['Set-Cookie'] = mintAuthCookie(cidStr)
      }
      if (out.body == null && req.method === 'GET') {
        res.writeHead(out.status || 500, headers)
        res.end()
        return
      }
      if (req.method === 'HEAD') {
        res.writeHead(out.status || 200, headers)
        res.end()
        return
      }
      const body = out.body
      if (body && typeof body[Symbol.asyncIterator] === 'function') {
        res.writeHead(out.status || 200, headers)
        try {
          for await (const chunk of body) {
            if (!res.write(chunk)) {
              await new Promise(function (r) {
                res.once('drain', r)
              })
            }
          }
          res.end()
        } catch (e) {
          if (e && e.name === 'AbortError') {
            if (!res.writableEnded) {
              try {
                res.end()
              } catch (_) {}
            }
            return
          }
          if (!res.writableEnded) {
            try {
              res.destroy()
            } catch (_) {}
          }
        }
        return
      }
      const buf = body ? Buffer.from(body) : Buffer.alloc(0)
      if (!headers['content-length'] && !headers['Content-Length']) {
        headers['Content-Length'] = String(buf.length)
      }
      res.writeHead(out.status || 200, headers)
      res.end(buf)
    } catch (e) {
      clearTimeout(t)
      if (e && e.name === 'AbortError') {
        if (!res.headersSent) {
          res.writeHead(504, { 'Content-Type': 'text/plain; charset=utf-8' })
        }
        res.end('timeout\n')
        return
      }
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' })
      }
      res.end('bad gateway\n')
    }
  }

  return {
    start () {
      return new Promise(function (resolve, reject) {
        if (server) {
          resolve({ port, address: bindAddress })
          return
        }
        const s = http.createServer(onRequest)
        s.once('error', reject)
        s.listen(port, bindAddress, function () {
          s.removeListener('error', reject)
          server = s
          s.on('error', function () {})
          resolve({ port, address: bindAddress })
        })
      })
    },
    stop () {
      return new Promise(function (resolve) {
        if (!server) {
          resolve()
          return
        }
        const s = server
        server = null
        s.close(function () {
          resolve()
        })
      })
    }
  }
}

module.exports = {
  createIpfsDwebHttpServer
}
