'use strict'

/**
 * In-band Helia/libp2p PeerId on the same length-framed Hyperswarm tunnel as IPv4 payloads
 * (same pattern as {@link ./hub-directory}).
 * Payload: 0x00 (invalid IPv4 IHL) + type + JSON body.
 */

const HELIA_MESH_ANNOUNCE_TYPE = 0x02

/**
 * @param {Buffer} buf — framed payload (after 4-byte length), not yet IP-wrapped
 * @returns {boolean}
 */
function isHeliaMeshAnnounceFrame (buf) {
  return (
    buf.length >= 3 &&
    buf[0] === 0x00 &&
    buf[1] === HELIA_MESH_ANNOUNCE_TYPE
  )
}

/**
 * @param {{ peerId: string, port?: number }} o
 * @returns {Buffer} inner payload for {@link ./framing}.encode()
 */
function encodeHeliaMeshAnnounce (o) {
  const peerId = String(o.peerId || '').trim()
  const port =
    o.port != null && Number(o.port) === (o.port | 0) && o.port >= 1 && o.port <= 65535
      ? o.port | 0
      : null
  const body = JSON.stringify({
    v: 1,
    peerId,
    ...(port != null ? { port } : {})
  })
  return Buffer.concat([
    Buffer.from([0x00, HELIA_MESH_ANNOUNCE_TYPE]),
    Buffer.from(body, 'utf8')
  ])
}

/**
 * @param {Buffer} buf
 * @returns {{ peerId: string, port: number } | null}
 */
function tryDecodeHeliaMeshAnnounce (buf) {
  if (!isHeliaMeshAnnounceFrame(buf)) return null
  try {
    const json = JSON.parse(buf.subarray(2).toString('utf8'))
    if (json == null || json.v !== 1) return null
    const peerId = String(json.peerId || '').trim()
    if (!peerId) return null
    let port = Number(json.port)
    if (!Number.isFinite(port) || port !== (port | 0) || port < 1 || port > 65535) {
      port = null
    }
    return { peerId, port: port != null ? port : 4011 }
  } catch {
    return null
  }
}

module.exports = {
  HELIA_MESH_ANNOUNCE_TYPE,
  isHeliaMeshAnnounceFrame,
  encodeHeliaMeshAnnounce,
  tryDecodeHeliaMeshAnnounce
}
