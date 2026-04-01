'use strict'

const fs = require('fs')
const nodePath = require('path')
const http = require('http')
const crypto = require('crypto')
const { EventEmitter } = require('events')
const { once } = require('events')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const { startSwarmMesh, swarmDiscoveryKey } = require('./swarm-mesh')
const { createDirectPool } = require('./direct-pool')
const { swarmTopicCapability, timingSafeEqual } = require('./swarm-topic')
const { parse32Bytes, encodeZ32 } = require('./key-encoding')
const { meshIdentifierStorageKey } = require('./mesh-identifier')
const {
  collectAssignedIpv4Addresses,
  pickFreeTenDotZeroSubnet,
  parseSubnet,
  intToIp
} = require('./ip-subnet')
const { createKeyAddressTable, stripHostFromCidr } = require('./key-address')
const rp = require('./routing-policy')
const {
  enableServerForwarding,
  disableServerForwarding,
  enableClientFullTunnel,
  addHostExemption,
  disableClientFullTunnel
} = require('./full-tunnel')

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' }
const HTML_TYPE = { 'Content-Type': 'text/html; charset=utf-8' }
const SSE_TYPE = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive'
}

const SWARM_STATUS_DEBOUNCE_MS = 120

function natSourceCidrFromDirectPool (ipv4Cidr) {
  const { network, prefix } = parseSubnet(String(ipv4Cidr || '10.0.0.1/24'))
  return `${intToIp(network)}/${prefix}`
}

function discoveryIncludedInPeerTopics (topics, discoveryBuf) {
  if (!topics || !topics.length || !discoveryBuf) return false
  const want = Buffer.isBuffer(discoveryBuf) ? discoveryBuf : Buffer.from(discoveryBuf)
  for (const t of topics) {
    const buf = Buffer.isBuffer(t) ? t : Buffer.from(t)
    if (buf.length === want.length && buf.equals(want)) return true
  }
  return false
}

function publicKeysEqual (a, b) {
  if (!a || !b) return false
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(a)
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(b)
  return ba.length === bb.length && ba.equals(bb)
}

function swarmHasLiveConnection (swarm, remotePublicKey) {
  if (!swarm || !remotePublicKey) return false
  for (const c of swarm.connections) {
    try {
      if (
        c &&
        !c.destroyed &&
        c.remotePublicKey &&
        publicKeysEqual(c.remotePublicKey, remotePublicKey)
      ) {
        return true
      }
    } catch (_) {}
  }
  return false
}

/**
 * @typedef {object} TopicRow
 * @property {string} id
 * @property {string} topic
 * @property {string} cidr
 * @property {string} discoveryKeyZ32
 * @property {string} publicKeyZ32
 * @property {string} localTunIp
 * @property {Array<{ peerKeyHex: string, peerKeyZ32: string, ipv4: string, meshIdKey: string, status: string }>} peers
 */

class ControlPlaneSessionManager extends EventEmitter {
  constructor () {
    super()
    this._clientSeedHex = crypto.randomBytes(32).toString('hex')
    this._clientKeyPair = HyperDHT.keyPair(Buffer.from(this._clientSeedHex, 'hex'))
    this._clientPublicKeyZ32 = encodeZ32(this._clientKeyPair.publicKey)
    /** @type {Map<string, TopicRow & { _handle: object, _peers: Map<string, object> }>} */
    this._topics = new Map()
    /** Discovery key hex — topic join in flight (before row is inserted; blocks double-click races). */
    this._pendingTopicDiscoveryHex = new Set()
    /** @type {ReturnType<typeof createDirectPool> | null} */
    this._directPool = null
    /** Process-wide wire endpoint id ↔ IP registry (direct pool + all topic meshes). */
    this._sharedKeyAddress = createKeyAddressTable({})
    /** Single Hyperswarm for direct + all topic meshes (same Noise identity as {@link #_clientKeyPair}). */
    this._sharedSwarm = null
    /** Discovery key hex → topic row (for routing `connection` events). */
    this._topicByDiscoveryHex = new Map()
    /** @type {import('./routing-policy').RoutingInterfacePolicy} */
    this._primaryPolicy = rp.createInterfacePolicy()
    /** @type {Map<string, Partial<{ ingress: Partial<import('./routing-policy').RoutingSidePolicy>, egress: Partial<import('./routing-policy').RoutingSidePolicy> }>>} */
    this._primaryPeerPolicies = new Map()
    /** primary peer keyHex → remote host used for full-tunnel exemption */
    this._fullTunnelHostsByPeer = new Map()
    /** @type {ReturnType<typeof enableServerForwarding> | null} — NAT/forward for peers using this host as egress */
    this._serverNatState = null
    /** @type {NodeJS.Timeout | null} */
    this._swarmStatusDebounceTimer = null
  }

  _resolvePrimaryPeerPolicy (keyHex) {
    const h = String(keyHex || '').trim().toLowerCase()
    return rp.resolvePeerPolicy(this._primaryPolicy, this._primaryPeerPolicies.get(h))
  }

  /**
   * Apply primary direct-pool full-tunnel policy to the OS: ingress (server NAT) and egress (client split routes).
   * Call after stream open/close or when primary policy changes.
   */
  _syncPrimaryFullTunnelPolicy () {
    if (!this._directPool) return
    try {
      this._syncPrimaryIngressServer()
    } catch (e) {
      console.error(
        'nospoon web: ingress full tunnel:',
        e && e.message ? e.message : e
      )
    }
    try {
      this._syncPrimaryEgressClient()
    } catch (e) {
      console.error(
        'nospoon web: egress full tunnel:',
        e && e.message ? e.message : e
      )
    }
  }

  _syncPrimaryIngressServer () {
    if (!this._directPool) return
    const tunName = this._directPool.tun && this._directPool.tun.name
    if (!tunName) return

    let needServer = false
    for (const p of this._directPool.listPeers()) {
      if (p.status !== 'connected') continue
      if (!this._resolvePrimaryPeerPolicy(p.keyHex).ingress.fullTunnel) continue
      needServer = true
      break
    }

    if (!needServer) {
      if (this._serverNatState) {
        try {
          disableServerForwarding(this._serverNatState)
        } catch (e) {
          console.error(
            'nospoon web: disable server forwarding:',
            e && e.message ? e.message : e
          )
        }
        this._serverNatState = null
      }
      return
    }

    if (this._serverNatState) return

    try {
      this._serverNatState = enableServerForwarding(
        undefined,
        natSourceCidrFromDirectPool(this._directPool.ipv4Cidr),
        tunName
      )
    } catch (e) {
      console.error(
        'nospoon web: enable server forwarding:',
        e && e.message ? e.message : e
      )
    }
  }

  _syncPrimaryEgressClient () {
    if (!this._directPool) return
    const tunName = this._directPool.tun && this._directPool.tun.name
    if (!tunName) return

    const want = []
    for (const p of this._directPool.listPeers()) {
      if (p.status !== 'connected') continue
      if (!this._resolvePrimaryPeerPolicy(p.keyHex).egress.fullTunnel) continue
      const host = p.remoteDialHost
      if (!host || typeof host !== 'string') continue
      want.push({ keyHex: p.keyHex, remoteHost: host })
    }

    if (want.length === 0) {
      if (this._fullTunnelHostsByPeer.size > 0) {
        try {
          disableClientFullTunnel()
        } catch (e) {
          console.error(
            'nospoon web: disable client full tunnel:',
            e && e.message ? e.message : e
          )
        }
        this._fullTunnelHostsByPeer.clear()
      }
      return
    }

    const sig = want
      .map((w) => w.keyHex + '\0' + w.remoteHost)
      .sort()
      .join('|')
    const prevSig = [...this._fullTunnelHostsByPeer.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([k, h]) => k + '\0' + h)
      .join('|')

    if (
      sig === prevSig &&
      this._fullTunnelHostsByPeer.size === want.length
    ) {
      return
    }

    try {
      disableClientFullTunnel()
    } catch (_) {}
    this._fullTunnelHostsByPeer.clear()

    try {
      enableClientFullTunnel(want[0].remoteHost, tunName)
      this._fullTunnelHostsByPeer.set(want[0].keyHex, want[0].remoteHost)
      for (let i = 1; i < want.length; i++) {
        addHostExemption(want[i].remoteHost)
        this._fullTunnelHostsByPeer.set(want[i].keyHex, want[i].remoteHost)
      }
    } catch (e) {
      console.error(
        'nospoon web: enable client full tunnel:',
        e && e.message ? e.message : e
      )
    }
  }

  _teardownPrimaryFullTunnelOs () {
    if (this._serverNatState) {
      try {
        disableServerForwarding(this._serverNatState)
      } catch (_) {}
      this._serverNatState = null
    }
    if (this._fullTunnelHostsByPeer.size > 0) {
      try {
        disableClientFullTunnel()
      } catch (_) {}
      this._fullTunnelHostsByPeer.clear()
    }
  }

  setPrimaryPolicy (body) {
    this._primaryPolicy = rp.applyPolicyUpdate(this._primaryPolicy, body)
    this._syncPrimaryFullTunnelPolicy()
    this._emitStatus()
    return rp.clonePolicy(this._primaryPolicy)
  }

  setPrimaryPeerPolicy (keyHex, body) {
    const h = String(keyHex || '').trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('expected 64 hex key')
    if (body && body.clear === true) {
      this._primaryPeerPolicies.delete(h)
    } else {
      const { preset, patch } = rp.parsePolicyUpdateBody(body)
      if (preset) throw new Error('preset is only valid for interface-level policy')
      this._primaryPeerPolicies.set(h, rp.accumulatePeerPatch(this._primaryPeerPolicies.get(h), patch))
    }
    this._syncPrimaryFullTunnelPolicy()
    this._emitStatus()
    return this._resolvePrimaryPeerPolicy(h)
  }

  setTopicInterfacePolicy (topicId, body) {
    const row = this._topics.get(String(topicId))
    if (!row) throw new Error('topic session not found')
    row._ifacePolicy = rp.applyPolicyUpdate(row._ifacePolicy, body)
    this._emitStatus()
    return rp.clonePolicy(row._ifacePolicy)
  }

  setTopicPeerPolicy (topicId, peerKeyHex, body) {
    const row = this._topics.get(String(topicId))
    if (!row) throw new Error('topic session not found')
    const h = String(peerKeyHex || '').trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('expected 64 hex peer key')
    if (body && body.clear === true) {
      row._peerPolicies.delete(h)
    } else {
      const { preset, patch } = rp.parsePolicyUpdateBody(body)
      if (preset) throw new Error('preset is only valid for interface-level policy')
      row._peerPolicies.set(h, rp.accumulatePeerPatch(row._peerPolicies.get(h), patch))
    }
    this._emitStatus()
    return rp.resolvePeerPolicy(row._ifacePolicy, row._peerPolicies.get(h))
  }

  _topicPeerSnapshotPolicy (row, peerKeyHex) {
    const h = String(peerKeyHex).toLowerCase()
    return {
      policy: rp.resolvePeerPolicy(row._ifacePolicy, row._peerPolicies.get(h)),
      policyPatch: row._peerPolicies.has(h) ? row._peerPolicies.get(h) : null
    }
  }

  async _ensureSharedSwarm () {
    if (this._sharedSwarm) return
    const self = this
    this._sharedSwarm = new Hyperswarm({
      keyPair: this._clientKeyPair,
      maxPeers: 512
    })
    this._sharedSwarm.on('connection', function (conn, peerInfo) {
      self._routeSwarmConnection(conn, peerInfo).catch(function () {
        try {
          conn.destroy()
        } catch (_) {}
      })
    })
    this._sharedSwarm.on('update', function () {
      self._scheduleSwarmStatusRefresh()
    })
    const swarm = this._sharedSwarm
    const origHandlePeer = swarm._handlePeer.bind(swarm)
    swarm._handlePeer = function (peer, topic) {
      origHandlePeer(peer, topic)
      self._scheduleSwarmStatusRefresh()
    }
    await this._sharedSwarm.listen()
  }

  /**
   * Hyperswarm does not always emit `update` when discovery tags an existing connection with a
   * topic (`_handlePeer` adds `peerInfo.topics` then returns — no new connection). Debounced
   * refresh keeps topic UI (synthetic rows) in sync for both peers.
   */
  _scheduleSwarmStatusRefresh () {
    if (this._swarmStatusDebounceTimer) clearTimeout(this._swarmStatusDebounceTimer)
    const self = this
    this._swarmStatusDebounceTimer = setTimeout(function () {
      self._swarmStatusDebounceTimer = null
      self._emitStatus()
    }, SWARM_STATUS_DEBOUNCE_MS)
  }

  async _routeSwarmConnection (conn, peerInfo) {
    if (!conn.remotePublicKey) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }
    if (peerInfo.explicit && this._directPool) {
      this._directPool.acceptConnection(conn)
      return
    }
    const row = this._pickTopicRowForPeerInfo(peerInfo)
    if (row) {
      row._handle.acceptConnection(conn)
      return
    }
    if (this._topics.size === 0 && this._directPool) {
      this._directPool.acceptConnection(conn)
      return
    }
    await this._demuxUnknownInbound(conn)
  }

  _pickTopicRowForPeerInfo (peerInfo) {
    const topics = peerInfo.topics || []
    for (const topicBuf of topics) {
      const row = this._topicByDiscoveryHex.get(topicBuf.toString('hex'))
      if (row) return row
    }
    return null
  }

  /**
   * Inbound server streams may lack `peerInfo.topics`; sniff first payload to distinguish topic cap vs direct tunnel.
   */
  async _demuxUnknownInbound (conn) {
    try {
      // Server-side streams often finish Noise before Hyperswarm emits `connection`;
      // `handshake` may already have fired, so `once()` would hang forever.
      if (!conn.handshakeHash) await once(conn, 'handshake')
    } catch {
      return
    }
    const h = conn.handshakeHash
    if (!h) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }

    if (conn.isInitiator) {
      if (this._directPool) this._directPool.acceptConnection(conn)
      return
    }

    const payload = await readFirstCompleteFramePayload(conn)
    for (const row of this._topics.values()) {
      const secret = row._handle.topicSecret
      const expected = swarmTopicCapability(!conn.isInitiator, secret, h)
      if (timingSafeEqual(payload, expected)) {
        await row._handle.acceptResponderPreauthed(conn, h)
        return
      }
    }
    if (this._directPool) {
      const hdr = Buffer.allocUnsafe(4)
      hdr.writeUInt32BE(payload.length, 0)
      this._directPool.acceptConnection(conn, { primedFramedChunks: [Buffer.concat([hdr, payload])] })
    } else {
      try {
        conn.destroy()
      } catch (_) {}
    }
  }

  /**
   * Allocate the shared direct TUN + 10.0.x.0/24 pool (first free /24 vs local + topic interfaces).
   * Starts the shared Hyperswarm listener and primary interface; requires TUN permissions.
   */
  async initDirectPool () {
    if (this._directPool) return
    await this._ensureSharedSwarm()
    const picked = pickFreeTenDotZeroSubnet(this._assignedHosts())
    const self = this
    this._directPool = createDirectPool({
      seed: this._clientSeedHex,
      ipv4: picked.cidr,
      mtu: 1400,
      swarm: this._sharedSwarm,
      keyAddress: this._sharedKeyAddress,
      onPeersChange () {
        self._emitStatus()
      },
      policyHooks: {
        onStreamOpen () {
          self._syncPrimaryFullTunnelPolicy()
          self._emitStatus()
        },
        onStreamClose () {
          self._syncPrimaryFullTunnelPolicy()
          self._emitStatus()
        }
      }
    })
  }

  _assignedHosts () {
    const s = collectAssignedIpv4Addresses()
    if (this._directPool) {
      s.add(stripHostFromCidr(this._directPool.ipv4Cidr))
    }
    for (const t of this._topics.values()) {
      s.add(stripHostFromCidr(t.cidr))
    }
    return s
  }

  _pickSubnet () {
    return pickFreeTenDotZeroSubnet(this._assignedHosts())
  }

  /**
   * @param {{ topic: string, ip?: string, seed?: string, mtu?: number, ipv6?: object }} opts
   */
  async addTopic (opts) {
    const topic = String(opts.topic || '').trim()
    if (!topic) throw new Error('topic is required')

    const newDiscovery = swarmDiscoveryKey(topic)
    const discoveryHex = newDiscovery.toString('hex')
    for (const row of this._topics.values()) {
      if (swarmDiscoveryKey(row.topic).equals(newDiscovery)) {
        throw new Error('this topic is already joined (leave it first to re-add)')
      }
    }
    if (this._pendingTopicDiscoveryHex.has(discoveryHex)) {
      throw new Error('this topic join is already in progress')
    }

    this._pendingTopicDiscoveryHex.add(discoveryHex)
    try {
      await this._ensureSharedSwarm()
      const picked = opts.ip && String(opts.ip).trim()
        ? { cidr: String(opts.ip).trim(), peerAlias: null }
        : this._pickSubnet()
      const cidr = picked.cidr
      const id = crypto.randomUUID()

      const self = this
      const _peers = new Map()

      const handle = await startSwarmMesh({
        topic,
        ip: cidr,
        ipv6: opts.ipv6,
        mtu: opts.mtu != null ? Number(opts.mtu) : 1400,
        topicId: id,
        quiet: true,
        silentRouter: true,
        manageProcessSignals: false,
        swarm: this._sharedSwarm,
        registerConnectionListener: false,
        keyAddress: this._sharedKeyAddress,
        hooks: {
          onPeerUp (info) {
            _peers.set(info.peerKeyHex, {
              peerKeyHex: info.peerKeyHex,
              peerKeyZ32: encodeZ32(Buffer.from(info.peerKeyHex, 'hex')),
              ipv4: info.ipv4,
              meshIdKey: info.meshIdKey,
              status: 'connected'
            })
            self._emitStatus()
          },
          onPeerDown (info) {
            _peers.delete(info.peerKeyHex)
            self._emitStatus()
          }
        }
      })

      const row = {
        id,
        topic,
        cidr,
        discoveryKeyZ32: encodeZ32(handle.topic),
        publicKeyZ32: encodeZ32(handle.keyPair.publicKey),
        localTunIp: stripHostFromCidr(cidr),
        peers: [],
        _handle: handle,
        _peers,
        _ifacePolicy: rp.createInterfacePolicy(),
        _peerPolicies: new Map()
      }
      this._topics.set(id, row)
      this._topicByDiscoveryHex.set(handle.topic.toString('hex'), row)
      this._emitStatus()
      return this.getTopicSnapshot(id)
    } finally {
      this._pendingTopicDiscoveryHex.delete(discoveryHex)
    }
  }

  async removeTopic (id) {
    const row = this._topics.get(id)
    if (!row) throw new Error('topic session not found')
    const dhex = row._handle.topic.toString('hex')
    try {
      row._handle.shutdown()
    } catch (_) {}
    this._topicByDiscoveryHex.delete(dhex)
    this._topics.delete(id)
    this._emitStatus()
  }

  getTopicSnapshot (id) {
    const row = this._topics.get(id)
    if (!row) return null
    const discoveryBuf = row._handle.topic
    const fromMesh = [...row._peers.values()].map((p) => ({
      ...p,
      ...this._topicPeerSnapshotPolicy(row, p.peerKeyHex)
    }))
    const seenHex = new Set(fromMesh.map((p) => p.peerKeyHex))
    const merged = [...fromMesh]

    if (this._sharedSwarm) {
      for (const [, peerInfo] of this._sharedSwarm.peers) {
        if (!discoveryIncludedInPeerTopics(peerInfo.topics, discoveryBuf)) continue
        const keyHex = peerInfo.publicKey.toString('hex')
        if (seenHex.has(keyHex)) continue
        if (!swarmHasLiveConnection(this._sharedSwarm, peerInfo.publicKey)) continue
        if (!peerInfo.explicit) continue

        let ipv4 = '—'
        if (this._directPool) {
          const d = this._directPool.listPeers().find(function (x) {
            return x.keyHex === keyHex
          })
          if (d) ipv4 = d.peerAliasIp
        }
        const synthetic = {
          peerKeyHex: keyHex,
          peerKeyZ32: encodeZ32(Buffer.from(keyHex, 'hex')),
          ipv4,
          meshIdKey: meshIdentifierStorageKey({
            kind: 'keyTopic',
            keyHex,
            topicId: row.id
          }),
          status: 'connected',
          tunViaPrimary: true
        }
        merged.push({
          ...synthetic,
          ...this._topicPeerSnapshotPolicy(row, keyHex)
        })
        seenHex.add(keyHex)
      }
    }

    row.peers = merged
    return {
      id: row.id,
      topic: row.topic,
      cidr: row.cidr,
      discoveryKeyZ32: row.discoveryKeyZ32,
      publicKeyZ32: row.publicKeyZ32,
      localTunIp: row.localTunIp,
      policy: rp.clonePolicy(row._ifacePolicy),
      peers: row.peers
    }
  }

  /**
   * @param {{ key: string }} opts — remote public key z32 or hex; IPs come from the shared direct pool
   */
  joinPeer (opts) {
    if (!this._directPool) {
      throw new Error('direct pool not initialized')
    }
    const buf = parse32Bytes(String(opts.key || '').trim(), 'key')
    const keyHex = buf.toString('hex')

    const self = this
    const info = this._directPool.joinPeer(keyHex, {
      onStreamOpen () {
        self._emitStatus()
      },
      onStreamClose () {
        self._emitStatus()
      },
      onStreamError () {
        self._emitStatus()
      }
    })
    this._emitStatus()
    return info
  }

  leavePeer (keyHex) {
    if (!this._directPool) throw new Error('direct pool not initialized')
    const h = String(keyHex || '').trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('expected 64 hex key')
    this._directPool.leavePeer(h)
    this._emitStatus()
  }

  getStatus () {
    const topics = []
    for (const id of this._topics.keys()) {
      const s = this.getTopicSnapshot(id)
      if (s) topics.push(s)
    }
    let directPool = null
    let directPeers = []
    if (this._directPool) {
      const p = this._directPool
      directPool = {
        cidr: p.ipv4Cidr,
        localTunIp: p.localTunIp,
        localMeshIdKey: p.localMeshIdKey,
        policy: rp.clonePolicy(this._primaryPolicy),
        policyNotes: {
          ingressFullTunnelApplied: this._serverNatState != null,
          egressFullTunnelAppliesToOsRoutes: true,
          relayFlagsStoredOnly: true
        }
      }
      directPeers = p.listPeers().map((peer) => ({
        ...peer,
        policy: this._resolvePrimaryPeerPolicy(peer.keyHex),
        policyPatch: this._primaryPeerPolicies.has(peer.keyHex)
          ? this._primaryPeerPolicies.get(peer.keyHex)
          : null
      }))
    }
    return {
      clientPublicKeyZ32: this._clientPublicKeyZ32,
      topics,
      directPool,
      directPeers
    }
  }

  _emitStatus () {
    const status = this.getStatus()
    this.emit('status', status)
  }

  async destroy () {
    if (this._swarmStatusDebounceTimer) {
      clearTimeout(this._swarmStatusDebounceTimer)
      this._swarmStatusDebounceTimer = null
    }
    for (const id of [...this._topics.keys()]) {
      try {
        await this.removeTopic(id)
      } catch (_) {}
    }
    this._topicByDiscoveryHex.clear()
    this._teardownPrimaryFullTunnelOs()
    if (this._directPool) {
      try {
        await this._directPool.shutdown()
      } catch (_) {}
      this._directPool = null
    }
    if (this._sharedSwarm) {
      try {
        await this._sharedSwarm.destroy()
      } catch (_) {}
      this._sharedSwarm = null
    }
  }
}

const MAX_FRAME_READ = 256 * 1024

/**
 * First length-prefixed frame, including zero-length payload (keepalive).
 * {@link createDecoder} skips len===0 frames, so it must not be used here — the responder
 * would hang until non-keepalive tun traffic arrived and Peer B would never get a direct peer row.
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

const WEB_BUNDLE_JS = nodePath.join(__dirname, 'web.bundle.js')
const WEB_BUNDLE_CSS = nodePath.join(__dirname, 'web.bundle.css')

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

function sendWebBundle (res, filePath, contentType) {
  fs.readFile(filePath, function (err, data) {
    if (err) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end(
        'Web UI bundle missing. From the nospoon package root run: npm install && npm run build\n'
      )
      return
    }
    res.writeHead(200, { 'Content-Type': contentType })
    res.end(data)
  })
}

/**
 * @param {{ port?: number, host?: string }} [opts]
 * @returns {Promise<{ server: import('http').Server, sessions: ControlPlaneSessionManager, port: number, closeHttpServer: function(): Promise<void> }>}
 */
async function startControlHttpServer (opts = {}) {
  const port = opts.port != null ? Number(opts.port) : 8790
  const host = opts.host != null ? String(opts.host) : '127.0.0.1'

  const sessions = new ControlPlaneSessionManager()
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

  function onSessionsStatus (status) {
    broadcast(status)
  }
  sessions.on('status', onSessionsStatus)

  const server = http.createServer(async function (req, res) {
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
  })

  await new Promise(function (resolve, reject) {
    server.listen(port, host, function () { resolve() })
    server.on('error', reject)
  })

  const addr = server.address()
  const actualPort = addr && typeof addr === 'object' ? addr.port : port

  await sessions.initDirectPool()

  /**
   * End SSE streams and close the HTTP server so **server.close** does not hang on open /api/events.
   * @returns {Promise<void>}
   */
  function closeHttpServer () {
    sessions.removeListener('status', onSessionsStatus)
    for (const res of sseClients) {
      try {
        res.end()
      } catch (_) {}
    }
    sseClients.clear()
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections()
    }
    return new Promise(function (resolve, reject) {
      server.close(function (err) {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  return { server, sessions, port: actualPort, closeHttpServer }
}

module.exports = {
  ControlPlaneSessionManager,
  startControlHttpServer
}
