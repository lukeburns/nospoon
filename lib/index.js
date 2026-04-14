'use strict'

/**
 * Programmatic API for building on nospoon (VPN mesh, key-address framing, swarm topics).
 * The CLI (`bin/cli.js`) is a thin wrapper over these modules.
 *
 * Example:
 *   const nospoon = require('nospoon')
 *   const mesh = await nospoon.startSwarmMesh({ topic: 'my-lan' })
 *   await mesh.shutdown()
 *   const ctl = await nospoon.startControlHttpServer({ port: 80 })
 *   await ctl.closeHttpServer(); await ctl.sessions.destroy()
 */

const { startSwarmMesh } = require('./mesh/swarm-mesh')
const { startControlHttpServer, ControlPlaneSessionManager } = require('./control/control-http')
const { createDirectPool } = require('./mesh/direct-pool')
const { createTunDevice } = require('./tun/tun')

const keyAddress = require('./mesh/key-address')
const routing = require('./route/routing')
const framing = require('./wire/framing')
const ipSubnet = require('./ip/ip-subnet')
const fullTunnel = require('./tun/full-tunnel')
const swarmTopic = require('./mesh/swarm-topic')
const keyEncoding = require('./wire/key-encoding')
const meshIdentifier = require('./wire/mesh-identifier')
const meshIpReservations = require('./mesh/mesh-ip-reservations')
const dnsServer = require('./dns/dns-server')
const dnsMeshName = require('./dns/dns-mesh-name')
const dnsManualRegistry = require('./dns/dns-manual-registry')

const { version } = require('../package.json')

module.exports = {
  version,

  startSwarmMesh,
  startControlHttpServer,
  ControlPlaneSessionManager,
  createDirectPool,

  createTunDevice,

  keyAddress,
  routing,
  framing,
  ipSubnet,
  fullTunnel,
  swarmTopic,
  keyEncoding,
  meshIdentifier,
  meshIpReservations,
  dnsServer,
  dnsMeshName,
  dnsManualRegistry
}
