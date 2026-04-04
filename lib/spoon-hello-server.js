'use strict'

const http = require('http')
const hc = require('hypercore-crypto')

/**
 * HTTP “hello” on one or more bind addresses (topic TUN + optional primary TUN): looks up the
 * visitor via whois (by IP) and returns a signed line with local and remote wire identities.
 * @param {{ bindAddress?: string, bindAddresses?: string[], port?: number, myPublicKeyZ32: string, secretKey: Buffer, fetchVisitorKeyLine: (ip: string) => Promise<string>, onError?: (e: Error) => void }} opts
 */
function createSpoonHelloServer (opts) {
  const raw =
    opts.bindAddresses != null && Array.isArray(opts.bindAddresses)
      ? opts.bindAddresses
      : [opts.bindAddress]
  const bindAddresses = [
    ...new Set(
      raw
        .map(function (a) {
          return String(a || '').trim()
        })
        .filter(Boolean)
    )
  ]
  const port = opts.port != null ? Number(opts.port) : 80
  const myPublicKeyZ32 = String(opts.myPublicKeyZ32 || '')
  const secretKey = opts.secretKey
  const fetchVisitorKeyLine = opts.fetchVisitorKeyLine
  const onError = typeof opts.onError === 'function' ? opts.onError : function () {}

  if (bindAddresses.length === 0) {
    throw new Error('spoon hello: bindAddress or bindAddresses is required')
  }
  if (!secretKey || !Buffer.isBuffer(secretKey)) {
    throw new Error('spoon hello: secretKey is required')
  }
  if (typeof fetchVisitorKeyLine !== 'function') {
    throw new Error('spoon hello: fetchVisitorKeyLine is required')
  }

  /** @type {import('http').Server[]} */
  let servers = []

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
        const ts = new Date().toISOString()
        const bodyLine = `greetings ${yourKey}.\n
        signed, ${myPublicKeyZ32} @ ${ts}\n`
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
      servers = []
      const pending = bindAddresses.map(function (bindAddress) {
        return new Promise(function (resolve, reject) {
          const server = http.createServer(onRequest)
          function onListenErr (err) {
            server.removeListener('error', onListenErr)
            reject(err)
          }
          server.once('error', onListenErr)
          server.listen(port, bindAddress, function () {
            server.removeListener('error', onListenErr)
            server.on('error', function (err) {
              onError(err)
            })
            servers.push(server)
            const addr = server.address()
            const listenPort =
              addr && typeof addr === 'object' ? addr.port : port
            resolve(listenPort)
          })
        })
      })
      return Promise.all(pending)
        .then(function (ports) {
          return { port: ports[0] }
        })
        .catch(function (err) {
          const started = servers
          servers = []
          return Promise.all(
            started.map(function (s) {
              return new Promise(function (r) {
                s.close(r)
              })
            })
          ).then(function () {
            throw err
          })
        })
    },
    /**
     * @returns {Promise<void>}
     */
    stop () {
      const toClose = servers
      servers = []
      return Promise.all(
        toClose.map(function (s) {
          return new Promise(function (resolve) {
            s.close(function () {
              resolve()
            })
          })
        })
      ).then(function () {})
    }
  }
}

module.exports = { createSpoonHelloServer }
