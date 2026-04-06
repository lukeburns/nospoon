'use strict'

/**
 * nospoon adapter: browser-net TCP middleman with mesh tunnel framing and source checks.
 * Core implementation: {@link ../web/net/lib/browser-net-middleware.js}.
 */

const { createBrowserNetMiddleware, BIN_TAG } = require('../web/net/lib/browser-net-middleware')
const { encode } = require('./framing')
const { wrapTunnelPayload } = require('./key-address')
const { tunnelSourceAllowedForPeerStream } = require('./routing')

/**
 * @param {object} opts
 * @param {function(): import('./key-address').KeyAddressTable} opts.getKa
 * @param {function(): string | null | undefined} opts.getPrimaryTunIp
 * @param {function(string): string | null | undefined} [opts.resolveListenBind]
 * @param {function(string): string | null | undefined} [opts.resolveConnectHost]
 * @param {function(string): { peerKeyHex: string, peerAliasIp: string, writeFramed: function(Buffer): void } | null | undefined} [opts.getOutboundRoute]
 */
function createBrowserNetProxy (opts) {
  const getKa = opts.getKa
  return createBrowserNetMiddleware({
    frameIpv4ForPeerStream: function (innerIpv4) {
      return encode(wrapTunnelPayload(getKa(), innerIpv4))
    },
    shouldAcceptInboundPacket: function (packet, ctx) {
      return tunnelSourceAllowedForPeerStream(
        packet,
        ctx.peerAliasIp,
        ctx.peerKeyHex,
        getKa()
      )
    },
    getDefaultListenIpv4: opts.getPrimaryTunIp,
    resolveListenHost: opts.resolveListenBind,
    resolveConnectHost: opts.resolveConnectHost,
    getOutboundRoute: opts.getOutboundRoute,
    webSocketPath: '/api/browser-net',
    messages: {
      defaultListenNotReady: 'primary mesh not ready; set host explicitly',
      unknownListenHost:
        'host must be a local mesh IPv4 or mesh DNS for this key (z32 or z32.topic e.g. z32.spoon)'
    }
  })
}

module.exports = {
  createBrowserNetProxy,
  BIN_TAG
}
