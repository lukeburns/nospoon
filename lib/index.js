'use strict'

/**
 * Programmatic API for building on nospoon (VPN mesh, key-address framing, swarm topics).
 * The CLI (`bin/cli.js`) wraps the control plane, `swarm`, and `genkey`; hub mode uses this API directly.
 *
 * Example:
 *   const nospoon = require('nospoon')
 *   const { shutdown } = nospoon.createClient({ key: '<server-hex>', dht: sharedDht }) // hub client (TUN + routing); pass `cli: true` or use startClient for signal handling + process.exit on shutdown
 *   await nospoon.startServer({ ip: '10.0.0.1/24' })
 *   const dk = nospoon.swarmTopic.swarmDiscoveryKey(Buffer.from('my-topic', 'utf8'))
 */

const { startServer } = require('./server')
const { createClient, startClient, connectAsClient } = require('./client')
const { startSwarmMesh } = require('./swarm-mesh')
const { startControlHttpServer, ControlPlaneSessionManager } = require('./control-http')
const { createDirectPool } = require('./direct-pool')
const { createTunDevice } = require('./tun')

const keyAddress = require('./key-address')
const routing = require('./routing')
const framing = require('./framing')
const ipSubnet = require('./ip-subnet')
const hubDirectory = require('./hub-directory')
const fullTunnel = require('./full-tunnel')
const swarmTopic = require('./swarm-topic')
const keyEncoding = require('./key-encoding')
const meshIdentifier = require('./mesh-identifier')
const meshIpReservations = require('./mesh-ip-reservations')
const dnsServer = require('./dns-server')
const dnsMeshName = require('./dns-mesh-name')
const dnsManualRegistry = require('./dns-manual-registry')

const { version } = require('../package.json')

module.exports = {
  version,

  startServer,
  createClient,
  startClient,
  connectAsClient,
  startSwarmMesh,
  startControlHttpServer,
  ControlPlaneSessionManager,
  createDirectPool,

  createTunDevice,

  keyAddress,
  routing,
  framing,
  ipSubnet,
  hubDirectory,
  fullTunnel,
  swarmTopic,
  keyEncoding,
  meshIdentifier,
  meshIpReservations,
  dnsServer,
  dnsMeshName,
  dnsManualRegistry
}
