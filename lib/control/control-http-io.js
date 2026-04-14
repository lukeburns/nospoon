'use strict'

const fs = require('fs')
const nodePath = require('path')

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' }
const TEXT_PLAIN_UTF8 = { 'Content-Type': 'text/plain; charset=utf-8' }
const HTML_TYPE = { 'Content-Type': 'text/html; charset=utf-8' }
const SSE_TYPE = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive'
}

const CORS_STAR = { 'Access-Control-Allow-Origin': '*' }

const WEB_BUNDLE_JS = nodePath.join(__dirname, '..', 'web.bundle.js')
const WEB_BUNDLE_CSS = nodePath.join(__dirname, '..', 'web.bundle.css')

const MAX_FRAME_READ = 256 * 1024

/**
 * First length-prefixed frame, including zero-length payload (keepalive).
 * {@link createDecoder} skips len===0 frames, so it must not be used here — the responder
 * would hang until non-keepalive tun traffic arrived and Peer B would never get a direct peer row.
 * @param {import('stream').Duplex} conn
 * @returns {Promise<Buffer>}
 */
function readFirstCompleteFramePayload (conn) {
  return new Promise(function (resolve, reject) {
    let buffer = Buffer.alloc(0)
    function onData (chunk) {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length > MAX_FRAME_READ) {
        cleanup()
        reject(new Error('frame buffer overflow'))
        return
      }
      while (buffer.length >= 4) {
        const len = buffer.readUInt32BE(0)
        if (len > 65535) {
          cleanup()
          reject(new Error('bad frame length'))
          return
        }
        if (buffer.length < 4 + len) return
        const payload = Buffer.from(buffer.subarray(4, 4 + len))
        buffer = buffer.subarray(4 + len)
        cleanup()
        resolve(payload)
        return
      }
    }
    function onClose () {
      cleanup()
      reject(new Error('closed'))
    }
    function cleanup () {
      conn.removeListener('data', onData)
      conn.removeListener('close', onClose)
    }
    conn.on('data', onData)
    conn.on('close', onClose)
  })
}

function readBody (req) {
  return new Promise(function (resolve, reject) {
    const chunks = []
    req.on('data', function (c) { chunks.push(c) })
    req.on('end', function () {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw.trim()) return resolve({})
      try {
        resolve(JSON.parse(raw))
      } catch (e) {
        reject(new Error('Invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

function sendJson (res, code, obj) {
  res.writeHead(code, JSON_TYPE)
  res.end(JSON.stringify(obj))
}

function sendPlainText (res, code, text, extraHeaders) {
  const headers = Object.assign({}, TEXT_PLAIN_UTF8, extraHeaders || {})
  res.writeHead(code, headers)
  res.end(text)
}

function controlPageHtml () {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>nospoon control</title>
  <link rel="stylesheet" href="/web.css"/>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/web.js"></script>
</body>
</html>`
}

function sendWebBundle (res, filePath, contentType, extraHeaders) {
  fs.readFile(filePath, function (err, data) {
    if (err) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end(
        'Web bundle missing. From the nospoon package root run: npm install && npm run build\n'
      )
      return
    }
    const headers = Object.assign(
      { 'Content-Type': contentType },
      extraHeaders || {}
    )
    res.writeHead(200, headers)
    res.end(data)
  })
}

module.exports = {
  JSON_TYPE,
  TEXT_PLAIN_UTF8,
  HTML_TYPE,
  SSE_TYPE,
  CORS_STAR,
  WEB_BUNDLE_JS,
  WEB_BUNDLE_CSS,
  readFirstCompleteFramePayload,
  readBody,
  sendJson,
  sendPlainText,
  controlPageHtml,
  sendWebBundle
}
