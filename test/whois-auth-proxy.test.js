'use strict'

const { describe, it, before, after } = require('node:test')
const assert = require('node:assert/strict')
const http = require('http')
const { createWhoisAuthProxy } = require('../lib/dns/whois-auth-proxy')

function httpGet (opts) {
  return new Promise(function (resolve, reject) {
    const req = http.get(opts, resolve)
    req.on('error', reject)
  })
}

describe('whois-auth-proxy', function () {
  /** @type {import('http').Server} */
  let upstream
  let upstreamPort = 0
  /** @type {{ start: () => Promise<{ port: number }>, stop: () => Promise<void> }} */
  let proxy
  let proxyPort = 0

  before(async function () {
    upstream = http.createServer(function (req, res) {
      const u = req.url || ''
      if (u === '/api/whois/foo') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('ok\n')
        return
      }
      if (u === '/api/whois/') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
        res.end('defaultkey\n')
        return
      }
      res.writeHead(404)
      res.end()
    })
    await new Promise(function (resolve, reject) {
      upstream.listen(0, '127.0.0.1', resolve)
      upstream.on('error', reject)
    })
    const a = upstream.address()
    upstreamPort = typeof a === 'object' && a ? a.port : 0

    proxy = createWhoisAuthProxy({
      bindAddress: '127.0.0.1',
      port: 0,
      controlPort: upstreamPort
    })
    const { port } = await proxy.start()
    proxyPort = port
  })

  after(async function () {
    if (proxy) await proxy.stop()
    if (upstream) await new Promise((r) => upstream.close(r))
  })

  it('maps GET /foo to upstream /api/whois/foo', async function () {
    const res = await httpGet({
      hostname: '127.0.0.1',
      port: proxyPort,
      path: '/foo'
    })
    assert.equal(res.statusCode, 200)
    const body = await new Promise(function (resolve, reject) {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve(Buffer.concat(chunks).toString()))
      res.on('error', reject)
    })
    assert.equal(body, 'ok\n')
  })

  it('maps GET / to upstream /api/whois/', async function () {
    const r = await httpGet({
      hostname: '127.0.0.1',
      port: proxyPort,
      path: '/'
    })
    assert.equal(r.statusCode, 200)
    const body = await new Promise(function (resolve, reject) {
      const chunks = []
      r.on('data', (c) => chunks.push(c))
      r.on('end', () => resolve(Buffer.concat(chunks).toString()))
      r.on('error', reject)
    })
    assert.equal(body, 'defaultkey\n')
  })

  it('404 for two path segments', async function () {
    const r1 = await httpGet({
      hostname: '127.0.0.1',
      port: proxyPort,
      path: '/a/b'
    })
    assert.equal(r1.statusCode, 404)
    r1.resume()
  })
})
