'use strict'

const http = require('http')
const hc = require('hypercore-crypto')

/**
 * HTTP “hello” on the topic TUN address: looks up the visitor via whois (by IP) and returns a
 * signed line with local and remote wire identities.
 * @param {{ bindAddress: string, port?: number, myPublicKeyZ32: string, secretKey: Buffer, fetchVisitorKeyLine: (ip: string) => Promise<string>, onError?: (e: Error) => void }} opts
 */
function createSpoonHelloServer (opts) {
  const bindAddress = String(opts.bindAddress || '').trim()
  const port = opts.port != null ? Number(opts.port) : 80
  const myPublicKeyZ32 = String(opts.myPublicKeyZ32 || '')
  const secretKey = opts.secretKey
  const fetchVisitorKeyLine = opts.fetchVisitorKeyLine
  const onError = typeof opts.onError === 'function' ? opts.onError : function () {}

  if (!bindAddress) throw new Error('spoon hello: bindAddress is required')
  if (!secretKey || !Buffer.isBuffer(secretKey)) {
    throw new Error('spoon hello: secretKey is required')
  }
  if (typeof fetchVisitorKeyLine !== 'function') {
    throw new Error('spoon hello: fetchVisitorKeyLine is required')
  }

  /** @type {import('http').Server | null} */
  let server = null

  function onRequest (req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' })
      res.end()
      return
    }

    let remote = req.socket.remoteAddress || ''
    if (remote.startsWith('::ffff:')) remote = remote.slice(7)

    Promise.resolve()
      .then(function () {
        return fetchVisitorKeyLine(remote)
      })
      .then(function (visitorLine) {
        const yourKey = String(visitorLine || '').trim() || '(unknown)'
        const bodyLine = `greetings ${yourKey}. signed, ${myPublicKeyZ32}`
        const msgBuf = Buffer.from(bodyLine, 'utf8')
        const sig = hc.sign(msgBuf, secretKey)
        const sigHex = sig.toString('hex')
        const out = bodyLine + '\n' + sigHex + '\n'
        if (req.method === 'HEAD') {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': Buffer.byteLength(out, 'utf8')
          })
          res.end()
          return
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end(out)
      })
      .catch(function (err) {
        onError(err instanceof Error ? err : new Error(String(err)))
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
          res.end('error\n')
        }
      })
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

module.exports = { createSpoonHelloServer }
