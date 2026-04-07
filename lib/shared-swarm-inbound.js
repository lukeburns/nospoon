'use strict'

const { encode, createDecoder } = require('./framing')
const { unwrapTunnelPayload, wrapTunnelPayload } = require('./key-address')
const { readDestinationIp, tunnelSourceAllowedForPeerStream } = require('./routing')
const { isDirectoryFrame } = require('./hub-directory')
const { isHeliaMeshAnnounceFrame, tryDecodeHeliaMeshAnnounce } = require('./ipfs-mesh-announce')
const { swarmTopicCapability, timingSafeEqual } = require('./swarm-topic')

/**
 * One length-prefixed frame decoder + tunnel routing for a shared Hyperswarm peer stream.
 * Primary and topic stacks share this instead of each attaching their own `data` listener.
 *
 * @param {object} opts
 * @param {*} opts.ka
 * @param {string} opts.peerKeyHex — 64 hex
 * @param {string} opts.peerAliasIp — peer’s alias on this host (primary or topic) for mesh source checks
 * @param {function(string): import('stream').Duplex|null} opts.lookupRelayConnection — dest IPv4 → peer stream
 * @param {function(Buffer): boolean} [opts.deliverLocalMeshPacket]
 * @param {function(Buffer): void} opts.fallbackTunWrite — e.g. primary TUN for internet / unmatched locals
 * @param {boolean} [opts.ignoreDirectoryFrames=false]
 * @param {null|{ handshakeHash: Buffer, topicSecret: Buffer, isInitiator: boolean, conn: import('stream').Duplex, onSuccess: function(): void, onFail: function(): void }} [opts.topicFirstFrameAuth]
 * @param {import('stream').Duplex|null} [opts.inboundConn] — peer stream (for browser-net proxy replies)
 * @param {function(Buffer, { peerKeyHex: string, peerAliasIp: string, writeFramed: function(Buffer): void }): boolean} [opts.tryBrowserProxy] — if returns true, packet was consumed (skip TUN)
 * @param {function({ peerId: string, port: number }, { peerKeyHex: string, peerAliasIp: string }): void} [opts.onHeliaMeshAnnounce]
 * @returns {function(Buffer): void} push — feed raw socket bytes
 */
function createSharedSwarmInboundPush (opts) {
  const {
    ka,
    peerKeyHex,
    peerAliasIp,
    lookupRelayConnection,
    deliverLocalMeshPacket,
    fallbackTunWrite,
    ignoreDirectoryFrames = false,
    topicFirstFrameAuth,
    inboundConn = null,
    tryBrowserProxy = null,
    onHeliaMeshAnnounce = null
  } = opts

  let topicAuthConsumed = !topicFirstFrameAuth

  const onFramedPayload = function (framedPayload) {
    if (!topicAuthConsumed && topicFirstFrameAuth) {
      topicAuthConsumed = true
      const {
        handshakeHash,
        topicSecret,
        isInitiator,
        conn,
        onSuccess,
        onFail
      } = topicFirstFrameAuth
      const expectedRemote = swarmTopicCapability(!isInitiator, topicSecret, handshakeHash)
      if (!timingSafeEqual(framedPayload, expectedRemote)) {
        onFail()
        return
      }
      if (!isInitiator) {
        try {
          conn.write(encode(swarmTopicCapability(false, topicSecret, handshakeHash)))
        } catch (_) {}
      }
      onSuccess()
      return
    }

    if (framedPayload.length === 0) return
    if (isHeliaMeshAnnounceFrame(framedPayload)) {
      const ann = tryDecodeHeliaMeshAnnounce(framedPayload)
      if (ann != null && typeof onHeliaMeshAnnounce === 'function') {
        try {
          onHeliaMeshAnnounce(ann, { peerKeyHex, peerAliasIp })
        } catch (_) {}
      }
      return
    }
    if (ignoreDirectoryFrames && isDirectoryFrame(framedPayload)) return

    const packet = unwrapTunnelPayload(ka, framedPayload)
    if (!packet) return

    const destIp = readDestinationIp(packet)
    const peerConn = lookupRelayConnection(destIp)
    if (peerConn && !peerConn.destroyed) {
      if (!tunnelSourceAllowedForPeerStream(packet, peerAliasIp, peerKeyHex, ka)) return
      try {
        peerConn.write(encode(wrapTunnelPayload(ka, packet)))
      } catch (_) {}
      return
    }

    if (typeof tryBrowserProxy === 'function') {
      try {
        if (
          tryBrowserProxy(packet, {
            peerKeyHex,
            peerAliasIp,
            writeFramed (buf) {
              if (inboundConn && !inboundConn.destroyed) inboundConn.write(buf)
            }
          })
        ) {
          return
        }
      } catch (_) {}
    }

    if (deliverLocalMeshPacket) {
      try {
        if (deliverLocalMeshPacket(packet)) return
      } catch (_) {}
    }

    try {
      fallbackTunWrite(packet)
    } catch (_) {}
  }

  return createDecoder(onFramedPayload)
}

module.exports = {
  createSharedSwarmInboundPush
}
