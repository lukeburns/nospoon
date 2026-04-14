'use strict'

const net = require('net')
const { formatKeyToDnsName, formatMeshTopicDnsName } = require('../dns/dns-mesh-name')
const {
  HTML_TYPE,
  SSE_TYPE,
  CORS_STAR,
  WEB_BUNDLE_JS,
  WEB_BUNDLE_CSS,
  readBody,
  sendJson,
  sendPlainText,
  controlPageHtml,
  sendWebBundle
} = require('./control-http-io')

/**
 * @param {*} sessions — `ControlPlaneSessionManager` from control-http.js
 */
function createControlHttpListener (sessions) {
  const sseClients = new Set()

  function broadcast (obj) {
    const line = 'data: ' + JSON.stringify(obj) + '\n\n'
    for (const res of sseClients) {
      try {
        res.write(line)
      } catch (_) {
        sseClients.delete(res)
      }
    }
  }

  async function handleRequest (req, res) {
    const url = new URL(req.url || '/', 'http://127.0.0.1')
    const path = url.pathname

    try {
      if (req.method === 'GET' && path === '/') {
        res.writeHead(200, HTML_TYPE)
        res.end(controlPageHtml())
        return
      }

      if (req.method === 'GET' && path === '/web.js') {
        sendWebBundle(
          res,
          WEB_BUNDLE_JS,
          'application/javascript; charset=utf-8'
        )
        return
      }

      if (req.method === 'GET' && path === '/web.css') {
        sendWebBundle(res, WEB_BUNDLE_CSS, 'text/css; charset=utf-8')
        return
      }

      if (req.method === 'GET' && path === '/api/status') {
        sendJson(res, 200, sessions.getStatus())
        return
      }

      if (req.method === 'GET' && path === '/api/dns/loopback') {
        const snap = await sessions.probeDnsLoopbackAliases()
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (
        req.method === 'OPTIONS' &&
        (path === '/api/whois' || path.startsWith('/api/whois/'))
      ) {
        res.writeHead(204, {
          ...CORS_STAR,
          'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        })
        res.end()
        return
      }

      if (
        (req.method === 'GET' || req.method === 'HEAD') &&
        (path === '/api/whois' || path.startsWith('/api/whois/'))
      ) {
        const tailRaw =
          path === '/api/whois' ? '' : path.slice('/api/whois/'.length)
        if (!tailRaw) {
          const line = sessions._clientPublicKeyZ32 + '\n'
          if (req.method === 'HEAD') {
            res.writeHead(200, {
              'Content-Type': 'text/plain; charset=utf-8',
              'Content-Length': Buffer.byteLength(line, 'utf8'),
              ...CORS_STAR
            })
            res.end()
            return
          }
          sendPlainText(res, 200, line, CORS_STAR)
          return
        }
        if (req.method === 'HEAD') {
          sendPlainText(res, 405, 'method not allowed\n', CORS_STAR)
          return
        }
        const decoded = decodeURIComponent(tailRaw)
        let asIp = decoded
        if (/^\[[^\]]+\]$/.test(asIp)) {
          asIp = asIp.slice(1, -1)
        }
        const isAddr = net.isIPv4(asIp) || net.isIPv6(asIp)

        if (isAddr) {
          const out = sessions.whoisIp(asIp)
          if (!out) {
            sendPlainText(res, 404, 'not found\n', CORS_STAR)
            return
          }
          let line = out.wire
          if (!line) {
            try {
              line =
                out.kind === 'key'
                  ? formatKeyToDnsName(out.keyHex)
                  : formatMeshTopicDnsName(out.keyHex, out.topic || out.topicId)
            } catch (_) {
              sendPlainText(res, 500, 'wire format error\n', CORS_STAR)
              return
            }
          }
          sendPlainText(res, 200, line + '\n', CORS_STAR)
          return
        }

        let out = null
        try {
          const d = decoded.indexOf('.')
          if (d === -1) {
            out = sessions.whoisKey(decoded, null)
          } else {
            const keyPart = decoded.slice(0, d)
            const topicPart = decoded.slice(d + 1)
            if (!keyPart || !topicPart || topicPart.indexOf('.') >= 0) {
              sendPlainText(
                res,
                400,
                'bad key.topic (single dot, one topic label)\n',
                CORS_STAR
              )
              return
            }
            out = sessions.whoisKey(keyPart, topicPart)
          }
        } catch (e) {
          sendPlainText(
            res,
            400,
            String(e && e.message ? e.message : e) + '\n',
            CORS_STAR
          )
          return
        }
        if (!out || !out.ip) {
          sendPlainText(res, 404, 'not found\n', CORS_STAR)
          return
        }
        sendPlainText(res, 200, out.ip + '\n', CORS_STAR)
        return
      }

      if (req.method === 'GET' && path === '/api/events') {
        res.writeHead(200, SSE_TYPE)
        res.write(': ok\n\n')
        sseClients.add(res)
        res.write('data: ' + JSON.stringify(sessions.getStatus()) + '\n\n')
        req.on('close', function () {
          sseClients.delete(res)
        })
        return
      }

      if (req.method === 'POST' && path === '/api/topics') {
        const body = await readBody(req)
        const snap = await sessions.addTopic(body)
        sendJson(res, 201, snap)
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/topics/')) {
        const id = decodeURIComponent(path.slice('/api/topics/'.length))
        await sessions.removeTopic(id)
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'POST' && path === '/api/peers') {
        const body = await readBody(req)
        const snap = sessions.joinPeer(body)
        sendJson(res, 201, snap)
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/peers/')) {
        const keyHex = decodeURIComponent(path.slice('/api/peers/'.length))
        await sessions.leavePeer(keyHex)
        sendJson(res, 200, { ok: true })
        return
      }

      if (req.method === 'POST' && path === '/api/mesh-reservations') {
        const body = await readBody(req)
        const op = String(body.op || '').trim()
        if (op === 'reservePrimary') {
          const out = sessions.reservePrimaryMeshKey(body.key)
          sendJson(res, 200, out)
          return
        }
        if (op === 'releasePrimary') {
          const ok = sessions.releasePrimaryMeshReservation(body.key)
          sendJson(res, 200, { ok })
          return
        }
        if (op === 'reserveTopic') {
          const out = sessions.reserveTopicMeshPeer(body.topicId, body.key)
          sendJson(res, 200, out)
          return
        }
        if (op === 'releaseTopic') {
          const ok = sessions.releaseTopicMeshReservation(
            body.topicId,
            body.key
          )
          sendJson(res, 200, { ok })
          return
        }
        throw new Error(
          'unknown mesh-reservations op (use reservePrimary, releasePrimary, reserveTopic, releaseTopic)'
        )
      }

      if (req.method === 'PATCH' && path === '/api/dns') {
        const body = await readBody(req)
        const out = await sessions.applyDnsSettings(body)
        sendJson(res, 200, out)
        return
      }

      if (req.method === 'POST' && path === '/api/dns/manual') {
        const body = await readBody(req)
        const out = await sessions.setDnsManualRecord(body)
        sendJson(res, 200, out)
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/dns/manual/')) {
        const host = decodeURIComponent(path.slice('/api/dns/manual/'.length))
        const ok = await sessions.deleteDnsManualRecord(host)
        sendJson(res, 200, { ok })
        return
      }

      if (req.method === 'POST' && path === '/api/dns/loopback') {
        const body = await readBody(req)
        const snap = await sessions.addDnsLoopbackAlias(body)
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/dns/loopback/')) {
        const ip = decodeURIComponent(path.slice('/api/dns/loopback/'.length))
        const snap = await sessions.removeDnsLoopbackAlias(ip)
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (req.method === 'PATCH' && path === '/api/policy/primary') {
        const body = await readBody(req)
        const policy = sessions.setPrimaryPolicy(body)
        sendJson(res, 200, { policy })
        return
      }

      if (req.method === 'PATCH' && path.startsWith('/api/policy/primary/peers/')) {
        const keyHex = decodeURIComponent(path.slice('/api/policy/primary/peers/'.length))
        const body = await readBody(req)
        const policy = sessions.setPrimaryPeerPolicy(keyHex, body)
        sendJson(res, 200, { peerKeyHex: keyHex.trim().toLowerCase(), policy })
        return
      }

      if (req.method === 'PATCH') {
        const mTop = path.match(/^\/api\/topics\/([^/]+)\/policy$/)
        if (mTop) {
          const id = decodeURIComponent(mTop[1])
          const body = await readBody(req)
          const policy = sessions.setTopicInterfacePolicy(id, body)
          sendJson(res, 200, { id, policy })
          return
        }
        const mPeer = path.match(/^\/api\/topics\/([^/]+)\/peers\/([0-9a-fA-F]{64})\/policy$/)
        if (mPeer) {
          const id = decodeURIComponent(mPeer[1])
          const peerKeyHex = mPeer[2].trim().toLowerCase()
          const body = await readBody(req)
          const policy = sessions.setTopicPeerPolicy(id, peerKeyHex, body)
          sendJson(res, 200, { id, peerKeyHex, policy })
          return
        }
      }

      sendJson(res, 404, { error: 'not found' })
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      sendJson(res, 400, { error: msg })
    }
  }

  return { handleRequest, sseClients, broadcast }
}

module.exports = { createControlHttpListener }
