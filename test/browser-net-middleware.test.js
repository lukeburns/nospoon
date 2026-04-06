'use strict'

const http = require('http')
const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const WebSocket = require('ws')
const { createBrowserNetMiddleware } = require('../web/net/lib/browser-net-middleware')
const {
  parseIpv4Tcp,
  buildIpv4TcpPacket,
  FLAG_SYN,
  FLAG_ACK
} = require('../web/net/lib/tcp-ipv4')

const TEST_KEY = 'aa'.repeat(32)
const LOCAL_IP = '10.0.0.1'
const REMOTE_IP = '10.0.0.2'
const REMOTE_PORT = 9000

/**
 * @param {() => boolean} fn
 * @param {number} [ms]
 */
function waitUntil (fn, ms = 3000) {
  const start = Date.now()
  return new Promise(function (resolve, reject) {
    ;(function tick () {
      try {
        if (fn()) return resolve()
      } catch (e) {
        return reject(e)
      }
      if (Date.now() - start > ms) return reject(new Error('waitUntil: timeout'))
      setImmediate(tick)
    })()
  })
}

/**
 * Wait for open, then subscribe to `message` and send `payload` in the same `open` turn (avoids losing fast server replies).
 * @param {import('ws')} ws
 * @param {string} payload
 * @param {number} [ms]
 * @returns {Promise<import('ws').RawData>}
 */
function sendAndReadFirstMessage (ws, payload, ms = 8000) {
  return new Promise(function (resolve, reject) {
    const t = setTimeout(function () {
      reject(new Error('timeout waiting for WebSocket message'))
    }, ms)
    ws.once('error', function (err) {
      clearTimeout(t)
      reject(err)
    })
    ws.once('open', function () {
      ws.once('message', function (data) {
        clearTimeout(t)
        resolve(data)
      })
      ws.send(payload)
    })
  })
}

describe('browser-net-middleware (integration)', function () {
  it('connect: SYN then inbound SYN-ACK yields connected', async function () {
    /** @type {Buffer[]} */
    const outboundFramed = []
    const mw = createBrowserNetMiddleware({
      frameIpv4ForPeerStream: function (b) {
        return b
      },
      getDefaultListenIpv4: function () {
        return LOCAL_IP
      },
      getOutboundRoute: function (remoteIp) {
        assert.equal(remoteIp, REMOTE_IP)
        return {
          peerKeyHex: TEST_KEY,
          peerAliasIp: REMOTE_IP,
          writeFramed: function (buf) {
            outboundFramed.push(Buffer.from(buf))
          }
        }
      }
    })

    const server = http.createServer()
    mw.attachToHttpServer(server)

    await new Promise(function (resolve, reject) {
      server.listen(0, '127.0.0.1', function (err) {
        if (err) reject(err)
        else resolve()
      })
    })

    const addr = server.address()
    assert.ok(addr && typeof addr === 'object')
    const port = /** @type {import('net').AddressInfo} */ (addr).port

    const rid = `rid-${Date.now()}`
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/browser-net`)

    try {
      {
        const raw = await sendAndReadFirstMessage(
          ws,
          JSON.stringify({ op: 'hello', v: 1 })
        )
        const hello = JSON.parse(
          Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)
        )
        assert.equal(hello.op, 'hello_ok')
      }

      const connectedP = new Promise(function (resolve, reject) {
        const t = setTimeout(function () {
          reject(new Error('timeout waiting for connected'))
        }, 8000)
        ws.once('message', function (data) {
          clearTimeout(t)
          resolve(data)
        })
      })
      ws.send(
        JSON.stringify({
          op: 'connect',
          host: REMOTE_IP,
          port: REMOTE_PORT,
          rid
        })
      )

      await waitUntil(function () {
        return outboundFramed.length >= 1
      })

      const syn = parseIpv4Tcp(outboundFramed[0])
      assert.ok(syn)
      assert.ok(syn.flags & FLAG_SYN)
      assert.equal(syn.srcIp, LOCAL_IP)
      assert.equal(syn.dstIp, REMOTE_IP)
      assert.equal(syn.dstPort, REMOTE_PORT)

      const peerIsn = 0xabc12345 >>> 0
      const synAck = buildIpv4TcpPacket({
        srcIp: REMOTE_IP,
        dstIp: LOCAL_IP,
        srcPort: REMOTE_PORT,
        dstPort: syn.srcPort,
        seq: peerIsn,
        ack: (syn.seq + 1) >>> 0,
        flags: FLAG_SYN | FLAG_ACK
      })

      mw.tryConsumeInboundPacket(synAck, {
        peerKeyHex: TEST_KEY,
        peerAliasIp: REMOTE_IP,
        writeFramed: function () {}
      })

      const rawConnected = await connectedP
      const connected = JSON.parse(
        Buffer.isBuffer(rawConnected)
          ? rawConnected.toString('utf8')
          : String(rawConnected)
      )
      assert.equal(connected.op, 'connected')
      assert.equal(connected.rid, rid)

      assert.equal(connected.local.ip, LOCAL_IP)
      assert.equal(connected.remote.ip, REMOTE_IP)
      assert.equal(connected.remote.port, REMOTE_PORT)
      assert.ok(typeof connected.stream === 'number')
    } finally {
      try {
        ws.close()
      } catch (_) {}
      await new Promise(function (resolve) {
        server.close(function () {
          resolve()
        })
      })
    }
  })

  it('connect: resolveConnectHost can supply IPv4 for non-literal host', async function () {
    /** @type {Buffer[]} */
    const outboundFramed = []
    const mw = createBrowserNetMiddleware({
      frameIpv4ForPeerStream: function (b) {
        return b
      },
      getDefaultListenIpv4: function () {
        return LOCAL_IP
      },
      resolveConnectHost: function (host) {
        return host === 'peer.example' ? REMOTE_IP : null
      },
      getOutboundRoute: function (remoteIp) {
        assert.equal(remoteIp, REMOTE_IP)
        return {
          peerKeyHex: TEST_KEY,
          peerAliasIp: REMOTE_IP,
          writeFramed: function (buf) {
            outboundFramed.push(Buffer.from(buf))
          }
        }
      }
    })

    const server = http.createServer()
    mw.attachToHttpServer(server)

    await new Promise(function (resolve, reject) {
      server.listen(0, '127.0.0.1', function (err) {
        if (err) reject(err)
        else resolve()
      })
    })

    const addr = server.address()
    assert.ok(addr && typeof addr === 'object')
    const port = /** @type {import('net').AddressInfo} */ (addr).port

    const rid = `rid-${Date.now()}-dns`
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/browser-net`)

    try {
      {
        const raw = await sendAndReadFirstMessage(
          ws,
          JSON.stringify({ op: 'hello', v: 1 })
        )
        const hello = JSON.parse(
          Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)
        )
        assert.equal(hello.op, 'hello_ok')
      }

      const connectedP = new Promise(function (resolve, reject) {
        const t = setTimeout(function () {
          reject(new Error('timeout waiting for connected'))
        }, 8000)
        ws.once('message', function (data) {
          clearTimeout(t)
          resolve(data)
        })
      })
      ws.send(
        JSON.stringify({
          op: 'connect',
          host: 'peer.example',
          port: REMOTE_PORT,
          rid
        })
      )

      await waitUntil(function () {
        return outboundFramed.length >= 1
      })

      const syn = parseIpv4Tcp(outboundFramed[0])
      assert.ok(syn)

      const synAck = buildIpv4TcpPacket({
        srcIp: REMOTE_IP,
        dstIp: LOCAL_IP,
        srcPort: REMOTE_PORT,
        dstPort: syn.srcPort,
        seq: 0x11111111,
        ack: (syn.seq + 1) >>> 0,
        flags: FLAG_SYN | FLAG_ACK
      })

      mw.tryConsumeInboundPacket(synAck, {
        peerKeyHex: TEST_KEY,
        peerAliasIp: REMOTE_IP,
        writeFramed: function () {}
      })

      const rawConnected = await connectedP
      const j = JSON.parse(
        Buffer.isBuffer(rawConnected)
          ? rawConnected.toString('utf8')
          : String(rawConnected)
      )
      assert.equal(j.op, 'connected')
      assert.equal(j.rid, rid)
    } finally {
      try {
        ws.close()
      } catch (_) {}
      await new Promise(function (resolve) {
        server.close(function () {
          resolve()
        })
      })
    }
  })
})
