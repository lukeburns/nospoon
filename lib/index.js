'use strict'

/**
 * Programmatic API for building on nospoon (VPN mesh, key-address framing, swarm topics).
 * The CLI (`bin/cli.js`) is a thin wrapper over these modules.
 *
 * Example:
 *   const nospoon = require('nospoon')
 *   await nospoon.startServer({ ip: '10.0.0.1/24' })
 *   const dk = nospoon.swarmTopic.swarmDiscoveryKey(Buffer.from('my-topic', 'utf8'))
 */

const { startServer } = require('./server')
const { startClient } = require('./client')
const { startSwarmMesh } = require('./swarm-mesh')
const { createTunDevice } = require('./tun')

const keyAddress = require('./key-address')
const routing = require('./routing')
const framing = require('./framing')
const ipSubnet = require('./ip-subnet')
const hubDirectory = require('./hub-directory')
const fullTunnel = require('./full-tunnel')
const swarmTopic = require('./swarm-topic')
const keyEncoding = require('./key-encoding')

const { version } = require('../package.json')

module.exports = {
  version,

  startServer,
  startClient,
  startSwarmMesh,

  createTunDevice,

  keyAddress,
  routing,
  framing,
  ipSubnet,
  hubDirectory,
  fullTunnel,
  swarmTopic,
  keyEncoding
}
