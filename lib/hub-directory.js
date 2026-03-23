/**
 * In-band multiplexing on the same length-framed DHT stream as tunnel payloads.
 * First byte 0x00 is invalid for IPv4/IPv6; second byte is message type.
 */

const DIRECTORY_TYPE = 0x01

function isDirectoryFrame (buf) {
  return buf.length >= 2 && buf[0] === 0x00 && buf[1] === DIRECTORY_TYPE
}

/**
 * @param {string[]} peerKeyHex — remote public keys currently connected to the hub (hex, any case)
 * @returns {Buffer} payload to pass to framing encode() (not yet length-prefixed)
 */
function encodeHubDirectory (peerKeyHex) {
  const sorted = [...new Set(peerKeyHex.map(function (k) { return k.toLowerCase() }))].sort()
  const body = JSON.stringify({ v: 1, peers: sorted.map(function (k) { return { k } }) })
  return Buffer.concat([Buffer.from([0x00, DIRECTORY_TYPE]), Buffer.from(body, 'utf8')])
}

/**
 * @returns {{ v: number, peers: Array<{ k: string }> }}
 */
function decodeHubDirectory (buf) {
  if (!isDirectoryFrame(buf)) {
    throw new Error('Not a hub directory frame')
  }
  const json = JSON.parse(buf.subarray(2).toString('utf8'))
  if (json.v !== 1 || !Array.isArray(json.peers)) {
    throw new Error('Invalid hub directory payload')
  }
  return json
}

module.exports = {
  isDirectoryFrame,
  encodeHubDirectory,
  decodeHubDirectory,
  DIRECTORY_TYPE
}
