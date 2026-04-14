'use strict'

// Maintenance: aim ≤ ~1,200 lines here; ceiling ~1,500 before splitting again (ARCHITECTURE.md).

const http = require('http')
const crypto = require('crypto')
const { EventEmitter } = require('events')
const HyperDHT = require('hyperdht')
const { startSwarmMesh, swarmDiscoveryKey } = require('../mesh/swarm-mesh')
const { createDirectPool } = require('../mesh/direct-pool')
const { parse32Bytes, encodeZ32 } = require('../wire/key-encoding')
const { meshIdentifierStorageKey } = require('../wire/mesh-identifier')
const {
  collectAssignedIpv4Addresses,
  pickFreeTenDotZeroSubnet,
  ipv4ContainedInCidr
} = require('../ip/ip-subnet')
const { createKeyAddressTable, stripHostFromCidr } = require('../mesh/key-address')
const { MeshIpReservationManager } = require('../mesh/mesh-ip-reservations')
const { DnsManualRegistry } = require('../dns/dns-manual-registry')
const dnsLoopbackAliases = require('../dns/dns-loopback-aliases')
const {
  formatKeyToDnsName,
  formatMeshTopicDnsName,
  normalizeFqdn,
  parseMeshDnsName
} = require('../dns/dns-mesh-name')
const net = require('net')
const rp = require('../route/routing-policy')
const {
  discoveryIncludedInPeerTopics,
  swarmHasLiveConnection,
  validateControlPrimaryCidr,
  resolveControlClientSeedHex,
  resolveSystemDnsOverrideOpt
} = require('./control-helpers')
const { createControlHttpListener } = require('./control-http-handler')
const { CONTROL_PANEL_DNS_HOST } = require('./control-constants')

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
  /**
   * @param {{
   *   primaryCidr?: string | null,
   *   clientSeedHex?: string | null,
   *   ephemeralClientKey?: boolean,
   *   systemDnsOverride?: boolean,
   *   darwinSystemDns?: boolean
   * }} [opts] — default persists identity under ~/.nospoon/identity.json; use ephemeralClientKey for tests
   */
  constructor (opts = {}) {
    super()
    this._clientSeedHex = resolveControlClientSeedHex(opts)
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
    /** @type {import('../route/routing-policy').RoutingInterfacePolicy} */
    this._primaryPolicy = rp.createInterfacePolicy()
    /** @type {Map<string, Partial<{ ingress: Partial<import('../route/routing-policy').RoutingSidePolicy>, egress: Partial<import('../route/routing-policy').RoutingSidePolicy> }>>} */
    this._primaryPeerPolicies = new Map()
    /** primary peer keyHex → remote host used for full-tunnel exemption */
    this._fullTunnelHostsByPeer = new Map()
    /** @type {object | null} — NAT/forward for peers using this host as egress */
    this._serverNatState = null
    /** Last OS error from ingress full-tunnel sync (for status UI) */
    this._lastIngressFtError = null
    /** Last OS error from egress full-tunnel sync (for status UI) */
    this._lastEgressFtError = null
    /** @type {NodeJS.Timeout | null} */
    this._swarmStatusDebounceTimer = null
    /** Optional fixed primary (direct pool) IPv4 CIDR instead of auto 10.0.n.1/24. */
    this._primaryCidrOverride =
      opts.primaryCidr != null && String(opts.primaryCidr).trim()
        ? validateControlPrimaryCidr(opts.primaryCidr, 'primaryCidr')
        : null
    /** @type {MeshIpReservationManager} */
    this._meshIpReservations = new MeshIpReservationManager()
    /** @type {DnsManualRegistry} */
    this._dnsManualRegistry = new DnsManualRegistry()
    /** @type {ReturnType<import('../dns/dns-server').createDnsServer> | null} */
    this._dnsServer = null
    this._dnsListening = false
    /** @type {string | null} */
    this._dnsLastError = null
    /** @type {{ enabled: boolean, port: number, address: string, forwardEnabled: boolean, forwardTarget: string | null }} */
    this._dnsConfig = {
      enabled: true,
      port: 53,
      address: '127.0.0.1',
      forwardEnabled: true,
      forwardTarget: null
    }
    /** macOS/Linux: set system DNS to 127.0.0.1 while mesh DNS listens on :53; restore on stop (needs root). */
    this._systemDnsOverride = resolveSystemDnsOverrideOpt(opts)
    /** Control HTTP listen port (set by {@link startControlHttpServer}); used by whois auth proxy. */
    this._controlHttpPort = null
    /** Control HTTP bind address (set with port); whois proxy must reach this host, not assume 127.0.0.1. */
    this._controlHttpBindAddress = null
    /** User removed default `whois` manual record — do not auto-recreate until DNS is toggled off→on. */
    this._whoisDefaultRemoved = false
    /** @type {boolean} */
    this._whoisAuthListening = false
    /** @type {string | null} */
    this._whoisAuthBindIpv4 = null
    /** @type {string | null} */
    this._whoisAuthLastError = null
    /** @type {(() => Promise<void>) | null} */
    this._whoisAuthProxyStop = null
    /** Cached `ifconfig`/`ip` probe for DNS loopback aliases (macOS/Linux). */
    this._dnsLoopbackSnapshot = dnsLoopbackAliases.initialSnapshot()
    /** Shared swarm: single inbound `data` pipeline per remote key. */
    this._sharedInboundByPeerKey = new Map()
    /** @type {WeakSet<import('stream').Duplex>} */
    this._keepaliveOnce = new WeakSet()
  }

  /**
   * @param {string} topicRef — topic row UUID or topic preimage (single label)
   * @returns {TopicRow & { _handle: object, _peers: Map<string, object> } | null}
   */
  _resolveTopicRowByRef (topicRef) {
    const t = String(topicRef || '').trim()
    if (!t) return null
    if (this._topics.has(t)) return this._topics.get(t)
    const lower = t.toLowerCase()
    let match = null
    for (const rec of this._topics.values()) {
      if (rec.topic === t || rec.topic.toLowerCase() === lower) {
        if (match) return null
        match = rec
      }
    }
    return match
  }

  /**
   * IPv4 from the topic TUN mesh only (Noise + topic capability on this interface).
   * Peers reached only via the primary direct pool are not included — use
   * {@link #_resolveTopicPeerMeshIpv4} for topic-subnet addressing in DNS/UI.
   * @param {TopicRow & { _handle: object, _peers: Map<string, object> }} row
   * @param {string} keyHex
   * @returns {string | null}
   */
  _topicLiveIpv4ForPeer (row, keyHex) {
    const h = String(keyHex || '').trim().toLowerCase()
    if (h.length !== 64) return null
    const fromPeers = row._peers.get(h)
    if (fromPeers && fromPeers.ipv4) return fromPeers.ipv4
    return null
  }

  /**
   * Topic-subnet IPv4: key-address `keyTopic` row, live topic TUN peer, then persistent reservation.
   * Used for mesh DNS and topic UI when Hyperswarm carries the topic but the stream is on the primary pool.
   * @param {object} row — topic row from this._topics
   * @param {string} keyHex — 64 hex
   * @returns {string | null}
   */
  _resolveTopicPeerMeshIpv4 (row, keyHex) {
    const h = String(keyHex || '').trim().toLowerCase()
    if (h.length !== 64) return null
    const tid = row.id
    const ka = this._sharedKeyAddress
    try {
      const fromKa = ka.ipForMeshIdentifier({
        kind: 'keyTopic',
        keyHex: h,
        topicId: tid
      })
      if (fromKa) return fromKa
    } catch (_) {}
    const live = this._topicLiveIpv4ForPeer(row, h)
    if (live) return live
    try {
      return this._meshIpReservations.reserveTopicPeer(
        tid,
        h,
        this._topicSubnetBaseUsedIps(tid)
      )
    } catch (_) {
      return null
    }
  }


  /**
   * Allocate the shared direct TUN + 10.0.x.0/24 pool (first free /24 vs local + topic interfaces).
   * Starts the shared Hyperswarm listener and primary interface; requires TUN permissions.
   */
  async initDirectPool () {
    if (this._directPool) return
    await this._ensureSharedSwarm()
    const picked = this._primaryCidrOverride
      ? { cidr: this._primaryCidrOverride, peerAlias: null }
      : pickFreeTenDotZeroSubnet(this._assignedHosts())
    this._meshIpReservations.setPrimaryCidr(picked.cidr)
    const self = this
    this._directPool = createDirectPool({
      seed: this._clientSeedHex,
      ipv4: picked.cidr,
      mtu: 1400,
      tunQuiet: true,
      swarm: this._sharedSwarm,
      keyAddress: this._sharedKeyAddress,
      attachSharedSwarmTunnel (payload) {
        self._attachSharedPeerInbound({
          conn: payload.conn,
          directSt: {
            st: payload.st,
            peerIp: payload.st.peerIp,
            keyHex: payload.st.keyHex
          },
          primeChunks: payload.primeOpts && payload.primeOpts.primedFramedChunks
            ? payload.primeOpts.primedFramedChunks
            : []
        })
      },
      takeReservedPeerIp (keyHex) {
        return self._meshIpReservations.consumePrimaryReservation(
          String(keyHex || '').trim().toLowerCase()
        )
      },
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
    for (const ent of this._sharedInboundByPeerKey.values()) {
      if (ent.conn && !ent.conn.destroyed && ent.conn.remotePublicKey) {
        this._addSharedConnToDirectPoolRouter(ent.conn)
      }
    }
  }

  _requireDirectPool () {
    if (!this._directPool) throw new Error('direct pool not initialized')
  }

  /**
   * All IPv4 addresses already occupying the primary (direct pool) subnet.
   * @returns {Set<string>}
   */
  _primarySubnetBaseUsedIps () {
    this._requireDirectPool()
    const cidr = this._directPool.ipv4Cidr
    const used = new Set()
    const addIf = (ip) => {
      if (ip && ipv4ContainedInCidr(ip, cidr)) used.add(ip)
    }
    addIf(this._directPool.localTunIp)
    for (const p of this._directPool.listPeers()) addIf(p.peerAliasIp)
    for (const t of this._topics.values()) {
      addIf(stripHostFromCidr(t.cidr))
      for (const pr of t._peers.values()) addIf(pr.ipv4)
    }
    return used
  }

  /**
   * @param {string} topicId
   * @returns {Set<string>}
   */
  _topicSubnetBaseUsedIps (topicId) {
    const row = this._topics.get(String(topicId).trim())
    if (!row) throw new Error('topic session not found')
    const used = new Set()
    used.add(stripHostFromCidr(row.cidr))
    for (const pr of row._peers.values()) used.add(pr.ipv4)
    return used
  }

  /**
   * @param {string} keyInput — z32 or 64 hex
   * @returns {{ keyHex: string, ipv4: string, meshIdKey: string, state: 'live' | 'reserved' }}
   */
  reservePrimaryMeshKey (keyInput) {
    this._requireDirectPool()
    const buf = parse32Bytes(String(keyInput || '').trim(), 'key')
    const keyHex = buf.toString('hex').toLowerCase()
    const localHex = this._clientKeyPair.publicKey.toString('hex')
    if (keyHex === localHex) {
      throw new Error('cannot reserve an address for the local identity')
    }
    for (const p of this._directPool.listPeers()) {
      if (p.keyHex === keyHex) {
        return {
          keyHex,
          ipv4: p.peerAliasIp,
          meshIdKey: meshIdentifierStorageKey({ kind: 'key', keyHex }),
          state: 'live'
        }
      }
    }
    const ipv4 = this._meshIpReservations.reservePrimaryKey(
      keyHex,
      this._primarySubnetBaseUsedIps()
    )
    this._emitStatus()
    return {
      keyHex,
      ipv4,
      meshIdKey: meshIdentifierStorageKey({ kind: 'key', keyHex }),
      state: 'reserved'
    }
  }

  /**
   * @param {string} topicId
   * @param {string} keyInput
   * @returns {{ topicId: string, keyHex: string, ipv4: string, meshIdKey: string, state: 'live' | 'reserved' }}
   */
  reserveTopicMeshPeer (topicId, keyInput) {
    const id = String(topicId || '').trim()
    const row = this._topics.get(id)
    if (!row) throw new Error('topic session not found')
    const buf = parse32Bytes(String(keyInput || '').trim(), 'key')
    const keyHex = buf.toString('hex').toLowerCase()
    const existing = row._peers.get(keyHex)
    if (existing && existing.ipv4) {
      const meshId = {
        kind: 'keyTopic',
        keyHex,
        topicId: id
      }
      return {
        topicId: id,
        keyHex,
        ipv4: existing.ipv4,
        meshIdKey: meshIdentifierStorageKey(meshId),
        state: 'live'
      }
    }
    const ipv4 = this._meshIpReservations.reserveTopicPeer(
      id,
      keyHex,
      this._topicSubnetBaseUsedIps(id)
    )
    this._emitStatus()
    const meshId = {
      kind: 'keyTopic',
      keyHex,
      topicId: id
    }
    return {
      topicId: id,
      keyHex,
      ipv4,
      meshIdKey: meshIdentifierStorageKey(meshId),
      state: 'reserved'
    }
  }

  /**
   * @param {string} keyInput
   * @returns {boolean}
   */
  releasePrimaryMeshReservation (keyInput) {
    const buf = parse32Bytes(String(keyInput || '').trim(), 'key')
    const keyHex = buf.toString('hex').toLowerCase()
    const ok = this._meshIpReservations.releasePrimaryKey(keyHex)
    this._emitStatus()
    return ok
  }

  /**
   * @param {string} topicId
   * @param {string} keyInput
   * @returns {boolean}
   */
  releaseTopicMeshReservation (topicId, keyInput) {
    const id = String(topicId || '').trim()
    const buf = parse32Bytes(String(keyInput || '').trim(), 'key')
    const keyHex = buf.toString('hex').toLowerCase()
    const ok = this._meshIpReservations.releaseTopicPeer(id, keyHex)
    this._emitStatus()
    return ok
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

      this._meshIpReservations.setTopicCidr(id, cidr)

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
        attachSharedSwarmTunnel (payload) {
          self._attachSharedPeerInbound(payload)
        },
        consumeReservedPeerIp (peerKeyHex) {
          return self._meshIpReservations.consumeTopicReservation(
            id,
            String(peerKeyHex || '').trim().toLowerCase()
          )
        },
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
      for (const ent of this._sharedInboundByPeerKey.values()) {
        if (ent.conn && !ent.conn.destroyed && ent.conn.remotePublicKey) {
          if (typeof handle.ensureSharedPeerKeyAddress === 'function') {
            handle.ensureSharedPeerKeyAddress(ent.conn)
          }
          handle.router.addPeer(ent.conn.remotePublicKey, ent.conn)
        }
      }
      this._startTopicDiscoveryPolling(row)
      this._emitStatus()
      return this.getTopicSnapshot(id)
    } finally {
      this._pendingTopicDiscoveryHex.delete(discoveryHex)
    }
  }

  async removeTopic (id) {
    const row = this._topics.get(id)
    if (!row) throw new Error('topic session not found')
    if (row._discoveryPollTimer) {
      clearInterval(row._discoveryPollTimer)
      row._discoveryPollTimer = null
    }
    const dhex = row._handle.topic.toString('hex')
    try {
      row._handle.shutdown()
    } catch (_) {}
    this._topicByDiscoveryHex.delete(dhex)
    this._topics.delete(id)
    this._meshIpReservations.deleteTopic(id)
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
        const primaryPeer = this._directPool
          ? this._directPool.listPeers().find(function (x) {
            return x.keyHex === keyHex
          })
          : null
        if (!primaryPeer) continue

        const topicIp = this._resolveTopicPeerMeshIpv4(row, keyHex)
        const ipv4 = topicIp != null ? topicIp : (primaryPeer.peerAliasIp || '—')
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

    row.peers = merged.map((p) => {
      let meshDnsWireName = null
      try {
        meshDnsWireName = formatMeshTopicDnsName(p.peerKeyHex, row.topic)
      } catch (_) {
        try {
          meshDnsWireName = formatMeshTopicDnsName(p.peerKeyHex, row.id)
        } catch (_) {}
      }
      return { ...p, meshDnsWireName }
    })
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
    const ent = this._sharedInboundByPeerKey.get(keyHex.toLowerCase())
    if (ent && ent.conn && !ent.conn.destroyed) {
      this._addSharedConnToDirectPoolRouter(ent.conn)
    }
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

  /**
   * @param {string} ipStr
   * @returns {{ ip: string, kind: 'key', keyHex: string, keyZ32: string, wire: string|null } | { ip: string, kind: 'keyTopic', keyHex: string, keyZ32: string, topicId: string, topic: string|null, wire: string|null } | null}
   */
  whoisIp (ipStr) {
    const ip = String(ipStr || '').trim()
    if (!ip || (!net.isIPv4(ip) && !net.isIPv6(ip))) return null
    const ka = this._sharedKeyAddress
    const mesh = ka.meshIdentifierForIp(ip)
    if (!mesh) return null
    let keyBuf
    try {
      keyBuf = ka.ipToKey(ip)
    } catch (_) {
      return null
    }
    const keyHex = keyBuf.toString('hex')
    let keyZ32
    try {
      keyZ32 = encodeZ32(keyBuf)
    } catch (_) {
      keyZ32 = null
    }
    if (mesh.kind === 'key') {
      let wire = null
      try {
        wire = formatKeyToDnsName(keyHex)
      } catch (_) {}
      return { ip, kind: 'key', keyHex, keyZ32, wire }
    }
    const row = this._topics.get(mesh.topicId)
    const topicRefForWire = row ? row.topic : mesh.topicId
    let wire = null
    try {
      wire = formatMeshTopicDnsName(keyHex, topicRefForWire)
    } catch (_) {}
    return {
      ip,
      kind: 'keyTopic',
      keyHex,
      keyZ32,
      topicId: mesh.topicId,
      topic: row ? row.topic : null,
      wire
    }
  }

  /**
   * @param {string} keyInput — z32 or 64 hex
   * @param {string|null|undefined} topicRef — primary if omitted; else topic row id (UUID) or topic label
   */
  whoisKey (keyInput, topicRef) {
    const buf = parse32Bytes(String(keyInput || '').trim(), 'key')
    const keyHex = buf.toString('hex').toLowerCase()
    const keyZ32 = encodeZ32(buf)
    const ka = this._sharedKeyAddress
    const t = topicRef != null && String(topicRef).trim() !== '' ? String(topicRef).trim() : null
    if (!t) {
      const meshId = { kind: 'key', keyHex }
      const ip = ka.ipForMeshIdentifier(meshId)
      if (!ip) return null
      let wire = null
      try {
        wire = formatKeyToDnsName(keyHex)
      } catch (_) {}
      return { ip, kind: 'key', keyHex, keyZ32, wire }
    }
    let topicRowId = t
    const uuidLike =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)
    if (!uuidLike) {
      const row = this._resolveTopicRowByRef(t)
      if (!row) return null
      topicRowId = row.id
    }
    const meshId = { kind: 'keyTopic', keyHex, topicId: topicRowId }
    const ip = ka.ipForMeshIdentifier(meshId)
    if (!ip) return null
    const row = this._topics.get(topicRowId)
    const human = row ? row.topic : topicRowId
    let wire = null
    try {
      wire = formatMeshTopicDnsName(keyHex, human)
    } catch (_) {}
    return {
      ip,
      kind: 'keyTopic',
      keyHex,
      keyZ32,
      topicId: topicRowId,
      topic: row ? row.topic : null,
      wire
    }
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
        },
        fullTunnelOs: this._fullTunnelOsSnapshotForPeers(),
        fullTunnelOsInterface: this._fullTunnelOsForPrimaryInterfaceRow()
      }
      directPeers = p.listPeers().map((peer) => {
        let meshDnsWireName = null
        try {
          meshDnsWireName = formatKeyToDnsName(peer.keyHex)
        } catch (_) {}
        return {
          ...peer,
          meshDnsWireName,
          policy: this._resolvePrimaryPeerPolicy(peer.keyHex),
          policyPatch: this._primaryPeerPolicies.has(peer.keyHex)
            ? this._primaryPeerPolicies.get(peer.keyHex)
            : null,
          fullTunnelOs: this._fullTunnelOsForPeerRow(peer)
        }
      })
    }
    return {
      clientPublicKeyZ32: this._clientPublicKeyZ32,
      topics,
      directPool,
      directPeers,
      meshReservations: this._meshIpReservations.getSnapshot(),
      primaryCidrOverride: this._primaryCidrOverride,
      dns: this.getDnsStatus()
    }
  }

  _emitStatus () {
    const status = this.getStatus()
    this.emit('status', status)
  }

  async destroy () {
    await this._stopWhoisAuthProxy()
    await this._stopDnsServer()
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
    this._meshIpReservations.resetAll()
  }
}

/**
 * @param {{ port?: number, host?: string, primaryCidr?: string | null, clientSeedHex?: string | null, systemDnsOverride?: boolean, darwinSystemDns?: boolean }} [opts] — omit `host` to bind on an auto loopback alias with manual name {@link CONTROL_PANEL_DNS_HOST} (port defaults to 80). Omit `clientSeedHex` to load or create ~/.nospoon/identity.json. By default, macOS/Linux point the OS resolver at 127.0.0.1 while mesh DNS runs on :53; disable with `systemDnsOverride: false` or env `NOSPOON_SYSTEM_DNS=0` (legacy: `NOSPOON_DARWIN_SYSTEM_DNS=0`). Restored on shutdown.
 * @returns {Promise<{ server: import('http').Server, sessions: ControlPlaneSessionManager, port: number, closeHttpServer: function(): Promise<void>, controlPanelBaseUrl: string, controlPanelRunningOnDisplay: string, keyLinkUrl: string, keyLinkDisplay: string }>}
 */
async function startControlHttpServer (opts = {}) {
  const explicitHost =
    opts.host != null && String(opts.host).trim() !== ''
  const port = opts.port != null ? Number(opts.port) : 80

  const sessions = new ControlPlaneSessionManager({
    primaryCidr: opts.primaryCidr != null ? opts.primaryCidr : null,
    clientSeedHex: opts.clientSeedHex,
    systemDnsOverride: opts.systemDnsOverride,
    darwinSystemDns: opts.darwinSystemDns
  })
  const { handleRequest, sseClients, broadcast } = createControlHttpListener(sessions)
  sessions.on('status', broadcast)

  const server = http.createServer(handleRequest)

  await sessions.initDirectPool()

  let listenHost
  if (explicitHost) {
    listenHost = String(opts.host).trim()
  } else {
    const lo = await sessions._ensureControlPanelNospoonAlias()
    listenHost = lo || '127.0.0.1'
  }

  await new Promise(function (resolve, reject) {
    server.listen(port, listenHost, function () { resolve() })
    server.on('error', reject)
  })

  const addr = server.address()
  const actualPort = addr && typeof addr === 'object' ? addr.port : port
  sessions._controlHttpBindAddress =
    addr && typeof addr === 'object' ? addr.address : listenHost

  await sessions._syncDnsServer()
  sessions._controlHttpPort = actualPort
  await sessions._syncWhoisAuthService()
  sessions._emitStatus()

  setImmediate(function () {
    sessions.probeDnsLoopbackAliases().catch(function () {})
  })

  /**
   * End SSE streams and close the HTTP server so **server.close** does not hang on open /api/events.
   * @returns {Promise<void>}
   */
  function closeHttpServer () {
    sessions.removeListener('status', broadcast)
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

  function formatHttpOrigin (host, listenPort) {
    const p = Number(listenPort)
    const h = net.isIPv6(host) ? `[${host}]` : String(host)
    if (p === 80) return `http://${h}/`
    return `http://${h}:${p}/`
  }

  function computeControlPanelBaseUrl () {
    const dns = sessions.getDnsStatus()
    const want = normalizeFqdn(CONTROL_PANEL_DNS_HOST)
    if (dns.enabled && dns.listening) {
      const recNamed = sessions.dnsResolveManualAddresses(want)
      if (recNamed && recNamed.ipv4) {
        return 'http://nospoon/'
      }
    }
    const rec = sessions.dnsResolveManualAddresses(want)
    if (rec && rec.ipv4) {
      return `http://${rec.ipv4}/`
    }
    try {
      const a = server.address()
      if (a && typeof a === 'object') {
        return formatHttpOrigin(a.address, a.port)
      }
    } catch (_) {}
    return formatHttpOrigin('127.0.0.1', actualPort)
  }

  function computeControlPanelRunningOnDisplay () {
    const primary = computeControlPanelBaseUrl()
    if (primary === 'http://nospoon/') {
      const want = normalizeFqdn(CONTROL_PANEL_DNS_HOST)
      const rec = sessions.dnsResolveManualAddresses(want)
      const ip = rec && rec.ipv4
      if (ip) {
        return `${primary} (${formatHttpOrigin(ip, actualPort)})`
      }
    }
    return primary
  }

  function computeKeyLinkUrl () {
    const hex = sessions._clientKeyPair.publicKey.toString('hex')
    return `http://${formatKeyToDnsName(hex)}/`
  }

  function computeKeyLinkDisplay () {
    const primary = computeKeyLinkUrl()
    const meshIp = sessions._dnsPrimaryTunHostIpv4()
    if (meshIp && net.isIPv4(meshIp)) {
      return `${primary} (${formatHttpOrigin(meshIp, 80)})`
    }
    return primary
  }

  return {
    server,
    sessions,
    port: actualPort,
    closeHttpServer,
    controlPanelBaseUrl: computeControlPanelBaseUrl(),
    controlPanelRunningOnDisplay: computeControlPanelRunningOnDisplay(),
    keyLinkUrl: computeKeyLinkUrl(),
    keyLinkDisplay: computeKeyLinkDisplay()
  }
}

Object.assign(
  ControlPlaneSessionManager.prototype,
  require('./control-session-dns'),
  require('./control-session-policy'),
  require('./control-session-swarm')
)

module.exports = {
  ControlPlaneSessionManager,
  startControlHttpServer
}
