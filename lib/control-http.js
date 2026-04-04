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
  intToIp,
  ipv4ContainedInCidr
} = require('./ip-subnet')
const { createKeyAddressTable, stripHostFromCidr } = require('./key-address')
const { MeshIpReservationManager } = require('./mesh-ip-reservations')
const { DnsManualRegistry } = require('./dns-manual-registry')
const dnsLoopbackAliases = require('./dns-loopback-aliases')
const {
  formatKeyToDnsName,
  formatMeshTopicDnsName,
  normalizeFqdn
} = require('./dns-mesh-name')
const net = require('net')
const rp = require('./routing-policy')
const {
  enableServerForwarding,
  disableServerForwarding,
  enableClientFullTunnel,
  addHostExemption,
  disableClientFullTunnel
} = require('./full-tunnel')
const { readDestinationIp } = require('./routing')
const { startKeepalive } = require('./framing')
const { createSharedSwarmInboundPush } = require('./shared-swarm-inbound')

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' }
const TEXT_PLAIN_UTF8 = { 'Content-Type': 'text/plain; charset=utf-8' }
const HTML_TYPE = { 'Content-Type': 'text/html; charset=utf-8' }
const SSE_TYPE = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive'
}

const SWARM_STATUS_DEBOUNCE_MS = 120
/** Re-run DHT lookup this often while a topic session is active so peers who announce later are seen (Hyperswarm’s own refresh can be ~10m). */
const TOPIC_DISCOVERY_POLL_MS = 12_000
/** Manual DNS hostname for the control panel (loopback alias + port 80 by default). */
const CONTROL_PANEL_DNS_HOST = 'nospoon'
/** Default Hyperswarm topic name — joined at control-plane startup. */
const DEFAULT_SPOON_TOPIC = 'spoon'
/** HTTP port for {@link DEFAULT_SPOON_TOPIC} mesh “hello” (bound to topic TUN IPv4). */
const SPOON_HELLO_HTTP_PORT = 80

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
 * @param {unknown} value
 * @param {string} label
 * @returns {string}
 */
function validateControlPrimaryCidr (value, label) {
  const s = String(value == null ? '' : value).trim()
  if (!s) throw new Error(`${label} is required`)
  try {
    parseSubnet(s)
  } catch {
    throw new Error(`${label} must be a valid IPv4 CIDR (e.g. 10.0.5.1/24)`)
  }
  return s
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
  /**
   * @param {{ primaryCidr?: string | null }} [opts]
   */
  constructor (opts = {}) {
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
    /** @type {ReturnType<import('./dns-server').createDnsServer> | null} */
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
    /** Control HTTP listen port (set by {@link startControlHttpServer}); used by whois auth proxy. */
    this._controlHttpPort = null
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
    /** @type {(() => Promise<void>) | null} */
    this._spoonHelloStop = null
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
   * After answering mesh DNS, open (or refresh) a primary direct pool session — same idea as
   * spoondns ambient {@link createClient} nudges, using this host’s shared Hyperswarm identity.
   * @param {string} keyHex
   */
  _dnsMaybeJoinPeerForDns (keyHex) {
    if (!this._directPool) return
    const h = String(keyHex || '').trim().toLowerCase()
    if (h.length !== 64) return
    if (h === this._clientKeyPair.publicKey.toString('hex')) return
    for (const p of this._directPool.listPeers()) {
      if (p.keyHex === h) return
    }
    try {
      this.joinPeer({ key: h })
    } catch (_) {}
  }

  /**
   * @param {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string }} meshId
   */
  _scheduleDnsDial (meshId) {
    if (!meshId || !meshId.keyHex) return
    const self = this
    const h = meshId.keyHex
    setImmediate(function () {
      self._dnsMaybeJoinPeerForDns(h)
    })
  }

  /**
   * Primary (direct pool) TUN host IPv4 for this process — same address as `z32(local key)` mesh DNS.
   * @returns {string | null}
   */
  _dnsPrimaryTunHostIpv4 () {
    if (this._directPool) return this._directPool.localTunIp
    const cidr = this._meshIpReservations.getPrimaryCidr()
    return cidr ? stripHostFromCidr(cidr) : null
  }

  /**
   * Mesh DNS A record: shared key-address, live peers, then reservation (no status emit).
   * Successful answers schedule a primary {@link #joinPeer} (DNS as a dial surface).
   * The control plane’s own key always resolves: {@code z32(me)} → primary TUN host,
   * {@code z32(me).topic} → that topic interface’s local TUN address when the topic exists.
   * @param {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string }} meshId
   * @returns {string | null}
   */
  dnsResolveMeshIpv4 (meshId) {
    if (!meshId || !meshId.kind) return null
    const ka = this._sharedKeyAddress
    const selfHex = this._clientKeyPair.publicKey.toString('hex')
    /** @type {string | null} */
    let ip = null

    if (meshId.kind === 'key') {
      const h = String(meshId.keyHex || '').trim().toLowerCase()
      if (h.length !== 64) return null
      if (h === selfHex) {
        ip = this._dnsPrimaryTunHostIpv4()
        if (!ip) return null
        this._scheduleDnsDial(meshId)
        return ip
      }
      if (!this._directPool) return null
      const fromKa = ka.ipForMeshIdentifier({ kind: 'key', keyHex: h })
      if (fromKa) ip = fromKa
      else {
        for (const p of this._directPool.listPeers()) {
          if (p.keyHex === h) {
            ip = p.peerAliasIp
            break
          }
        }
      }
      if (!ip) {
        try {
          ip = this._meshIpReservations.reservePrimaryKey(
            h,
            this._primarySubnetBaseUsedIps()
          )
        } catch (_) {
          return null
        }
      }
    } else if (meshId.kind === 'keyTopic') {
      const row = this._resolveTopicRowByRef(meshId.topicRef)
      if (!row) return null
      const h = String(meshId.keyHex || '').trim().toLowerCase()
      if (h.length !== 64) return null
      if (h === selfHex) {
        ip = row.localTunIp || null
        if (!ip) return null
        this._scheduleDnsDial(meshId)
        return ip
      }
      ip = this._resolveTopicPeerMeshIpv4(row, h)
      if (!ip) return null
    } else {
      return null
    }

    if (ip) this._scheduleDnsDial(meshId)
    return ip
  }

  getDnsStatus () {
    const fwd =
      this._dnsConfig.forwardEnabled
        ? this._dnsConfig.forwardTarget || '1.1.1.1'
        : null
    return {
      enabled: this._dnsConfig.enabled,
      listening: this._dnsListening,
      port: this._dnsConfig.port,
      address: this._dnsConfig.address,
      forwardEnabled: this._dnsConfig.forwardEnabled,
      forward: fwd,
      lastError: this._dnsLastError,
      manual: this._dnsManualRegistry.list(),
      loopback: this._dnsLoopbackSnapshot,
      whoisAuth: {
        listening: this._whoisAuthListening,
        ipv4: this._whoisAuthBindIpv4,
        httpPort: 80,
        lastError: this._whoisAuthLastError
      }
    }
  }

  /**
   * Re-read loopback IPv4 aliases from the OS (requires `ifconfig` or `ip` in PATH; add/remove needs root).
   * @returns {Promise<{ supported: boolean, aliases: string[], error: string | null }>}
   */
  async probeDnsLoopbackAliases () {
    const snap = await dnsLoopbackAliases.probeLoopbackAliases()
    this._dnsLoopbackSnapshot = snap
    this._emitStatus()
    return snap
  }

  /**
   * @param {{ ipv4?: string }} body — omit or empty string to auto-pick from 10.254.0.0/16
   * @returns {Promise<{ loopback: { supported: boolean, aliases: string[], error: string | null }, addedIpv4: string }>}
   */
  async addDnsLoopbackAlias (body) {
    const ipv4 = String(body && body.ipv4 != null ? body.ipv4 : '').trim()
    const addedIpv4 = await dnsLoopbackAliases.addLoopbackAlias(ipv4)
    const loopback = await this.probeDnsLoopbackAliases()
    return { loopback, addedIpv4 }
  }

  /**
   * @param {string} ipv4
   * @returns {Promise<{ supported: boolean, aliases: string[], error: string | null }>}
   */
  async removeDnsLoopbackAlias (ipv4) {
    await dnsLoopbackAliases.removeLoopbackAlias(String(ipv4 || '').trim())
    return this.probeDnsLoopbackAliases()
  }

  async _stopDnsServer () {
    if (!this._dnsServer) return
    const h = this._dnsServer
    this._dnsServer = null
    try {
      await h.stop()
    } catch (_) {}
    this._dnsListening = false
  }

  async _syncDnsServer () {
    await this._stopDnsServer()
    this._dnsLastError = null
    if (!this._dnsConfig.enabled) return

    const { createDnsServer, parseForwardTarget } = require('./dns-server')
    let forward = null
    if (this._dnsConfig.forwardEnabled) {
      const spec = this._dnsConfig.forwardTarget || '1.1.1.1'
      try {
        forward = parseForwardTarget(spec)
      } catch (e) {
        this._dnsLastError = e && e.message ? e.message : String(e)
        this._dnsConfig.enabled = false
        return
      }
    }

    const self = this
    this._dnsServer = createDnsServer({
      port: this._dnsConfig.port,
      address: this._dnsConfig.address,
      forward,
      lookupManual: function (n) {
        return self._dnsManualRegistry.lookup(n)
      },
      resolveMeshA: function (id) {
        return self.dnsResolveMeshIpv4(id)
      },
      onError: function (err) {
        self._dnsLastError = err && err.message ? err.message : String(err)
      }
    })
    try {
      await this._dnsServer.start()
      this._dnsListening = true
      this._dnsLastError = null
    } catch (e) {
      this._dnsLastError = e && e.message ? e.message : String(e)
      this._dnsServer = null
      this._dnsListening = false
      this._dnsConfig.enabled = false
    }
  }

  async _stopWhoisAuthProxy () {
    if (this._whoisAuthProxyStop) {
      try {
        await this._whoisAuthProxyStop()
      } catch (_) {}
      this._whoisAuthProxyStop = null
    }
    this._whoisAuthListening = false
    this._whoisAuthBindIpv4 = null
  }

  /**
   * When DNS is listening, ensure a `whois` manual host → loopback alias and serve HTTP :80 proxy:
   * public `GET /<z32-or-key.topic>` only, forwarded to internal `/api/whois/…`.
   * @returns {Promise<void>}
   */
  async _syncWhoisAuthService () {
    await this._stopWhoisAuthProxy()
    this._whoisAuthLastError = null

    if (!this._dnsListening || !this._dnsConfig.enabled) return
    if (this._controlHttpPort == null) return

    if (!dnsLoopbackAliases.platformSupportsLoopbackAliases()) {
      this._whoisAuthLastError =
        'whois auth HTTP proxy needs loopback aliases (macOS or Linux)'
      return
    }

    let rec = this._dnsManualRegistry.lookup(normalizeFqdn('whois'))
    if ((!rec || !rec.ipv4) && !this._whoisDefaultRemoved) {
      try {
        const ip = await dnsLoopbackAliases.addLoopbackAlias('')
        this._dnsManualRegistry.set('whois', {
          ipv4: ip,
          ipv6: rec && rec.ipv6
        })
        await this.probeDnsLoopbackAliases()
        rec = this._dnsManualRegistry.lookup(normalizeFqdn('whois'))
      } catch (e) {
        this._whoisAuthLastError = e && e.message ? e.message : String(e)
        return
      }
    }

    if (!rec || !rec.ipv4) return

    const bindIpv4 = rec.ipv4
    const { createWhoisAuthProxy } = require('./whois-auth-proxy')
    const self = this
    const proxy = createWhoisAuthProxy({
      bindAddress: bindIpv4,
      port: 80,
      controlPort: this._controlHttpPort,
      onError: function (err) {
        self._whoisAuthLastError = err && err.message ? err.message : String(err)
        self._emitStatus()
      }
    })
    try {
      await proxy.start()
      this._whoisAuthProxyStop = function () {
        return proxy.stop()
      }
      this._whoisAuthListening = true
      this._whoisAuthBindIpv4 = bindIpv4
    } catch (e) {
      this._whoisAuthLastError = e && e.message ? e.message : String(e)
      this._whoisAuthProxyStop = null
    }
  }

  /**
   * @param {object} body
   * @returns {Promise<object>}
   */
  async applyDnsSettings (body) {
    if (!body || typeof body !== 'object') body = {}
    const prevEnabled = this._dnsConfig.enabled
    if (typeof body.enabled === 'boolean') this._dnsConfig.enabled = body.enabled
    if (body.port != null) {
      const p = Number(body.port)
      if (Number.isNaN(p) || p < 1 || p > 65535) {
        throw new Error('DNS port must be 1–65535')
      }
      this._dnsConfig.port = p
    }
    if (body.address != null && String(body.address).trim()) {
      const a = String(body.address).trim()
      if (!net.isIPv4(a) && !net.isIPv6(a)) {
        throw new Error('DNS bind address must be a valid IPv4 or IPv6 address')
      }
      this._dnsConfig.address = a
    }
    if (typeof body.forwardEnabled === 'boolean') {
      this._dnsConfig.forwardEnabled = body.forwardEnabled
    }
    if (body.forward != null) {
      if (body.forward === false || body.forward === '') {
        this._dnsConfig.forwardTarget = null
      } else {
        this._dnsConfig.forwardTarget = String(body.forward).trim() || null
      }
    }
    await this._syncDnsServer()
    this._emitStatus()
    return this.getDnsStatus()
  }

  /**
   * @param {{ hostname?: string, host?: string, ipv4?: string, ipv6?: string }} body
   * @returns {Promise<{ manual: Array<{ hostname: string, ipv4?: string, ipv6?: string }>, allocatedLoopbackIpv4?: string }>}
   */
  async setDnsManualRecord (body) {
    const host = String(body.hostname || body.host || '').trim()
    if (!host) throw new Error('hostname is required')
    const ipv4In =
      body.ipv4 != null && String(body.ipv4).trim() ? String(body.ipv4).trim() : ''
    const ipv6In =
      body.ipv6 != null && String(body.ipv6).trim() ? String(body.ipv6).trim() : ''
    /** @type {string | undefined} */
    let ipv4 = ipv4In || undefined
    /** @type {string | undefined} */
    let ipv6 = ipv6In || undefined
    /** @type {string | undefined} */
    let allocatedLoopbackIpv4
    if (!ipv4 && !ipv6) {
      allocatedLoopbackIpv4 = await dnsLoopbackAliases.addLoopbackAlias('')
      ipv4 = allocatedLoopbackIpv4
    }
    this._dnsManualRegistry.set(host, { ipv4, ipv6 })
    const manual = this._dnsManualRegistry.list()
    if (allocatedLoopbackIpv4) {
      await this.probeDnsLoopbackAliases()
    }
    await this._syncWhoisAuthService()
    this._emitStatus()
    return allocatedLoopbackIpv4
      ? { manual, allocatedLoopbackIpv4 }
      : { manual }
  }

  /**
   * @param {string} hostname
   * @returns {Promise<boolean>}
   */
  async deleteDnsManualRecord (hostname) {
    const n = normalizeFqdn(String(hostname || '').trim())
    if (n === 'whois') {
      this._whoisDefaultRemoved = true
    }
    const ok = this._dnsManualRegistry.delete(String(hostname || '').trim())
    await this._syncWhoisAuthService()
    this._emitStatus()
    return ok
  }

  /**
   * Allocate a loopback alias and set manual {@link CONTROL_PANEL_DNS_HOST} → IPv4 for the HTTP UI.
   * @returns {Promise<string | null>} bind address, or null if loopback aliases are unsupported
   */
  async _ensureControlPanelNospoonAlias () {
    const name = normalizeFqdn(CONTROL_PANEL_DNS_HOST)
    const existing = this._dnsManualRegistry.lookup(name)
    if (existing && existing.ipv4) return existing.ipv4
    if (!dnsLoopbackAliases.platformSupportsLoopbackAliases()) {
      return null
    }
    const ip = await dnsLoopbackAliases.addLoopbackAlias('')
    this._dnsManualRegistry.set(CONTROL_PANEL_DNS_HOST, {
      ipv4: ip,
      ipv6: existing && existing.ipv6
    })
    await this.probeDnsLoopbackAliases()
    return ip
  }

  _findTopicByName (name) {
    const n = String(name || '').trim()
    for (const row of this._topics.values()) {
      if (row.topic === n) return row
    }
    return null
  }

  /**
   * Resolve a visitor mesh IP via the local whois HTTP service (hostname {@code whois}, port 80).
   * @param {string} ip
   * @returns {Promise<string>}
   */
  async _fetchWhoisLineForVisitorIp (ip) {
    const s = String(ip || '').trim()
    if (!s || s === '127.0.0.1' || s === '::1') return ''
    const pathSeg = net.isIPv6(s) ? `[${s}]` : s
    const path = '/' + encodeURIComponent(pathSeg)
    return new Promise(function (resolve) {
      const req = http.get(
        {
          hostname: 'whois',
          port: 80,
          path
        },
        function (res) {
          let data = ''
          res.on('data', function (c) {
            data += c
          })
          res.on('end', function () {
            if (res.statusCode !== 200) resolve('')
            else resolve(data.replace(/\r?\n$/, ''))
          })
        }
      )
      req.on('error', function () {
        resolve('')
      })
      req.setTimeout(8000, function () {
        req.destroy()
        resolve('')
      })
    })
  }

  async _stopSpoonHelloServer () {
    if (this._spoonHelloStop) {
      try {
        await this._spoonHelloStop()
      } catch (_) {}
      this._spoonHelloStop = null
    }
  }

  async _startSpoonHelloServer (row) {
    await this._stopSpoonHelloServer()
    const self = this
    const { createSpoonHelloServer } = require('./spoon-hello-server')
    const srv = createSpoonHelloServer({
      bindAddress: row.localTunIp,
      port: SPOON_HELLO_HTTP_PORT,
      myPublicKeyZ32: this._clientPublicKeyZ32,
      secretKey: this._clientKeyPair.secretKey,
      fetchVisitorKeyLine: function (ip) {
        return self._fetchWhoisLineForVisitorIp(ip)
      },
      onError: function (err) {
        console.error(
          'nospoon spoon hello:',
          err && err.message ? err.message : err
        )
      }
    })
    try {
      await srv.start()
      this._spoonHelloStop = function () {
        return srv.stop()
      }
    } catch (e) {
      console.error(
        'nospoon spoon hello bind:',
        e && e.message ? e.message : e
      )
    }
  }

  /**
   * Join the default {@link DEFAULT_SPOON_TOPIC} mesh and bind the hello HTTP server on its TUN IPv4.
   * @returns {Promise<void>}
   */
  async _ensureSpoonTopicAndHello () {
    if (this._spoonHelloStop) return
    try {
      await this.addTopic({ topic: DEFAULT_SPOON_TOPIC })
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      if (!msg.includes('already joined')) {
        console.error('nospoon default spoon topic:', msg)
        return
      }
    }
    const row = this._findTopicByName(DEFAULT_SPOON_TOPIC)
    if (!row) return
    await this._startSpoonHelloServer(row)
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
      this._lastIngressFtError = null
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

    if (this._serverNatState) {
      this._lastIngressFtError = null
      return
    }

    try {
      this._serverNatState = enableServerForwarding(
        undefined,
        natSourceCidrFromDirectPool(this._directPool.ipv4Cidr),
        tunName
      )
      this._lastIngressFtError = null
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      this._lastIngressFtError = msg
      console.error('nospoon web: enable server forwarding:', msg)
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
      this._lastEgressFtError = null
      if (this._directPool.setInternetExitKeyHex) {
        this._directPool.setInternetExitKeyHex(null)
      }
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
      this._lastEgressFtError = null
      if (this._directPool.setInternetExitKeyHex) {
        this._directPool.setInternetExitKeyHex(want[0].keyHex)
      }
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
      this._lastEgressFtError = null
      if (this._directPool.setInternetExitKeyHex) {
        this._directPool.setInternetExitKeyHex(want[0].keyHex)
      }
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      this._lastEgressFtError = msg
      if (this._directPool.setInternetExitKeyHex) {
        this._directPool.setInternetExitKeyHex(null)
      }
      console.error('nospoon web: enable client full tunnel:', msg)
    }
  }

  _teardownPrimaryFullTunnelOs () {
    if (this._directPool && this._directPool.setInternetExitKeyHex) {
      this._directPool.setInternetExitKeyHex(null)
    }
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
    this._lastIngressFtError = null
    this._lastEgressFtError = null
  }

  /**
   * Per-toggle OS/debug status for the primary direct pool (full tunnel + relay stored-only).
   */
  _fullTunnelOsSnapshotForPeers () {
    const tunName = this._directPool && this._directPool.tun && this._directPool.tun.name
    return {
      tunName: tunName || null,
      ipv4Only: true,
      clientRoutesActive: this._fullTunnelHostsByPeer.size > 0,
      serverNatActive: this._serverNatState != null,
      lastIngressError: this._lastIngressFtError,
      lastEgressError: this._lastEgressFtError
    }
  }

  _relayStoredHint () {
    return {
      state: 'stored',
      text: 'Not wired on the network yet (flag stored only).'
    }
  }

  _ftOsLine (state, text) {
    return { state, text }
  }

  /** Interface-default row: how OS state relates to the checkbox defaults (peers can differ). */
  _fullTunnelOsForPrimaryInterfaceRow () {
    const pol = this._primaryPolicy
    const relay = this._relayStoredHint()
    const snap = this._directPool ? this._fullTunnelOsSnapshotForPeers() : null
    const srv = snap && snap.serverNatActive
    const cli = snap && snap.clientRoutesActive

    let ingFt
    if (!pol.ingress.fullTunnel) {
      ingFt = this._ftOsLine(
        'off',
        'Interface default off. Per-peer ingress toggles still apply.'
      )
    } else if (!srv) {
      ingFt = this._ftOsLine(
        'error',
        this._lastIngressFtError
          ? `NAT/forward not active: ${this._lastIngressFtError}`
          : 'NAT/forward not active (need a connected peer with ingress full tunnel and usually root).'
      )
    } else {
      ingFt = this._ftOsLine(
        'ok',
        'Pool exit NAT is active on this host (iptables/pf).'
      )
    }

    let egFt
    if (!pol.egress.fullTunnel) {
      egFt = this._ftOsLine(
        'off',
        'Interface default off. Per-peer egress toggles still apply.'
      )
    } else if (!cli) {
      egFt = this._ftOsLine(
        'error',
        this._lastEgressFtError
          ? `Client split routes not active: ${this._lastEgressFtError}`
          : 'Client split routes not active (need a connected peer with egress FT and remoteDialHost; often root).'
      )
    } else {
      egFt = this._ftOsLine(
        'ok',
        'Client IPv4 full-tunnel routes are installed on this host.'
      )
    }

    return {
      ingress: { fullTunnel: ingFt, relay },
      egress: { fullTunnel: egFt, relay }
    }
  }

  _fullTunnelOsForPeerRow (peer) {
    const pol = this._resolvePrimaryPeerPolicy(peer.keyHex)
    const relay = this._relayStoredHint()
    const conn = peer.status === 'connected'

    let ingFt
    if (!pol.ingress.fullTunnel) {
      ingFt = this._ftOsLine('off', 'Not offering exit NAT for this peer.')
    } else if (!conn) {
      ingFt = this._ftOsLine('pending', 'Waiting for a connected stream to this peer.')
    } else if (this._serverNatState) {
      ingFt = this._ftOsLine('ok', 'This peer qualifies; pool exit NAT is on.')
    } else {
      ingFt = this._ftOsLine(
        'error',
        this._lastIngressFtError
          ? `NAT not up: ${this._lastIngressFtError}`
          : 'NAT not up for this pool (permissions or enableServerForwarding failed — check terminal logs).'
      )
    }

    let egFt
    if (!pol.egress.fullTunnel) {
      egFt = this._ftOsLine('off', 'Not routing default traffic via this peer.')
    } else if (!conn) {
      egFt = this._ftOsLine('pending', 'Waiting for a connected stream.')
    } else if (!peer.remoteDialHost) {
      egFt = this._ftOsLine(
        'error',
        'No remoteDialHost on the socket — Hyperswarm has no public relay IP for this path yet; egress routes cannot be installed.'
      )
    } else if (this._fullTunnelHostsByPeer.has(peer.keyHex)) {
      egFt = this._ftOsLine(
        'ok',
        `IPv4 split routes active; exempt ${peer.remoteDialHost} for the tunnel path.`
      )
    } else {
      egFt = this._ftOsLine(
        'error',
        this._lastEgressFtError
          ? `Routes missing: ${this._lastEgressFtError}`
          : 'Egress policy is on but this peer is not in the client full-tunnel set (sync error or permission issue).'
      )
    }

    return {
      ingress: { fullTunnel: ingFt, relay },
      egress: { fullTunnel: egFt, relay }
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

  /**
   * Periodically re-run the topic’s DHT lookup so the first peer to join still learns about peers
   * who announce after the initial lookup (Hyperswarm’s built-in refresh interval is very long).
   */
  _startTopicDiscoveryPolling (row) {
    const sess = row._handle && row._handle.discoverySession
    if (!sess) return
    if (row._discoveryPollTimer) {
      clearInterval(row._discoveryPollTimer)
      row._discoveryPollTimer = null
    }
    const self = this
    const tick = function () {
      if (!self._topics.has(row.id)) return
      sess.refresh().catch(function () {})
      self._scheduleSwarmStatusRefresh()
    }
    row._discoveryPollTimer = setInterval(tick, TOPIC_DISCOVERY_POLL_MS)
    tick()
  }

  /**
   * Deliver inner IPv4 packets addressed to our primary or any topic TUN (single-stream demux).
   * @param {Buffer} packet
   * @returns {boolean}
   */
  _deliverLocalMeshPacket (packet) {
    const dest = readDestinationIp(packet)
    if (!dest) return false
    if (this._directPool && dest === this._directPool.localTunIp) {
      try {
        this._directPool.tun.write(packet)
      } catch (_) {}
      return true
    }
    for (const row of this._topics.values()) {
      if (dest === row.localTunIp) {
        const h = row._handle
        if (h && h.tun) {
          try {
            h.tun.write(packet)
          } catch (_) {}
        }
        return true
      }
    }
    return false
  }

  _sharedMeshRelayCtx () {
    return {
      localKey: this._clientKeyPair.publicKey,
      ka: this._sharedKeyAddress,
      ipToKeyHex: null
    }
  }

  /**
   * @param {string|null|undefined} destIp
   * @returns {import('stream').Duplex|null}
   */
  _lookupRelayConnection (destIp) {
    if (!destIp) return null
    const ctx = this._sharedMeshRelayCtx()
    if (this._directPool) {
      const c = this._directPool.router.getConnectionForDestination(destIp, ctx)
      if (c && !c.destroyed) return c
    }
    for (const row of this._topics.values()) {
      const h = row._handle
      if (!h || !h.router) continue
      const c = h.router.getConnectionForDestination(destIp, ctx)
      if (c && !c.destroyed) return c
    }
    return null
  }

  /**
   * Outbound topic TUN uses each topic mesh's router. The same Hyperswarm stream is often wired
   * only through the direct pool (`explicit` join), so topic routers never saw addPeer and packets
   * were dropped in tun.on('data').
   */
  _addSharedConnToTopicMeshRouters (conn) {
    if (!conn || !conn.remotePublicKey || conn.destroyed) return
    const pk = conn.remotePublicKey
    for (const row of this._topics.values()) {
      const h = row._handle
      if (h && typeof h.ensureSharedPeerKeyAddress === 'function') {
        h.ensureSharedPeerKeyAddress(conn)
      }
      if (h && h.router) h.router.addPeer(pk, conn)
    }
  }

  _removeSharedConnFromTopicMeshRouters (conn) {
    if (!conn || !conn.remotePublicKey) return
    const pk = conn.remotePublicKey
    for (const row of this._topics.values()) {
      const h = row._handle
      if (h && h.router) {
        try {
          h.router.removePeer(pk)
        } catch (_) {}
      }
    }
  }

  _addSharedConnToDirectPoolRouter (conn) {
    if (!this._directPool || !conn || !conn.remotePublicKey || conn.destroyed) return
    if (typeof this._directPool.syncSharedInboundToPrimary === 'function') {
      this._directPool.syncSharedInboundToPrimary(conn)
    } else {
      this._directPool.router.addPeer(conn.remotePublicKey, conn)
      if (typeof this._directPool.attachSharedStreamToPeerState === 'function') {
        this._directPool.attachSharedStreamToPeerState(conn)
      }
    }
  }

  _removeSharedConnFromDirectPoolRouter (conn) {
    if (!this._directPool || !conn || !conn.remotePublicKey) return
    try {
      this._directPool.router.removePeer(conn.remotePublicKey)
    } catch (_) {}
  }

  _startKeepaliveOnce (conn) {
    if (!conn || this._keepaliveOnce.has(conn)) return
    this._keepaliveOnce.add(conn)
    startKeepalive(conn)
  }

  /**
   * Single framed-tunnel inbound pipeline for shared Hyperswarm (direct + topic).
   * @param {object} args
   * @param {import('stream').Duplex} args.conn
   * @param {{ st: object, peerIp: string, keyHex: string }|null} [args.directSt]
   * @param {Buffer[]} [args.primeChunks]
   * @param {object} [args.topicWireInbound]
   * @param {object} [args.topicPreauthedInbound]
   */
  _attachSharedPeerInbound (args) {
    const conn = args.conn
    if (!conn.remotePublicKey) return
    const rk = conn.remotePublicKey.toString('hex')

    const prev = this._sharedInboundByPeerKey.get(rk)
    if (prev && prev.conn === conn) {
      if (args.directSt) {
        const st = args.directSt.st
        st.connection = conn
        st.status = 'connected'
        if (this._directPool) {
          this._directPool.router.addPeer(conn.remotePublicKey, conn)
        }
        this._addSharedConnToTopicMeshRouters(conn)
      }
      return
    }

    if (prev && prev.conn !== conn) {
      prev.conn.removeListener('data', prev.onData)
      this._sharedInboundByPeerKey.delete(rk)
    }

    let peerAliasIp =
      args.directSt != null
        ? args.directSt.peerIp
        : args.topicWireInbound != null
          ? args.topicWireInbound.clientIp
          : args.topicPreauthedInbound != null
            ? args.topicPreauthedInbound.clientIp
            : null
    if (peerAliasIp == null || peerAliasIp === '') {
      throw new Error('shared inbound: missing peer alias IP')
    }

    if (args.topicPreauthedInbound) {
      args.topicPreauthedInbound.onTunnelReady()
      this._addSharedConnToDirectPoolRouter(conn)
      this._startKeepaliveOnce(conn)
    }

    let topicFirstFrameAuth = null
    if (args.topicWireInbound) {
      const tw = args.topicWireInbound
      const self = this
      topicFirstFrameAuth = {
        handshakeHash: tw.handshakeHash,
        topicSecret: tw.topicSecret,
        isInitiator: tw.isInitiator,
        conn,
        onSuccess: function () {
          tw.onAuthenticated()
          self._addSharedConnToDirectPoolRouter(conn)
          self._startKeepaliveOnce(conn)
        },
        onFail: tw.onAuthFail
      }
    }

    const self = this
    const push = createSharedSwarmInboundPush({
      ka: this._sharedKeyAddress,
      peerKeyHex: rk,
      peerAliasIp,
      lookupRelayConnection: function (dest) {
        return self._lookupRelayConnection(dest)
      },
      deliverLocalMeshPacket: function (p) {
        return self._deliverLocalMeshPacket(p)
      },
      fallbackTunWrite: function (p) {
        if (self._directPool) {
          try {
            self._directPool.tun.write(p)
          } catch (_) {}
        }
      },
      ignoreDirectoryFrames: args.directSt != null,
      topicFirstFrameAuth
    })

    const onData = function (chunk) {
      push(chunk)
    }
    conn.on('data', onData)

    const chunks = args.primeChunks || []
    for (let i = 0; i < chunks.length; i++) {
      push(chunks[i])
    }

    this._sharedInboundByPeerKey.set(rk, { conn, onData, push })

    const selfMap = this
    conn.on('close', function () {
      const cur = selfMap._sharedInboundByPeerKey.get(rk)
      if (cur && cur.conn === conn && cur.onData === onData) {
        selfMap._sharedInboundByPeerKey.delete(rk)
        selfMap._removeSharedConnFromTopicMeshRouters(conn)
        selfMap._removeSharedConnFromDirectPoolRouter(conn)
      }
    })

    if (!args.topicWireInbound && !args.topicPreauthedInbound) {
      this._addSharedConnToTopicMeshRouters(conn)
    }

    if (!topicFirstFrameAuth && !args.topicPreauthedInbound) {
      this._startKeepaliveOnce(conn)
    }
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
    if (row.topic === DEFAULT_SPOON_TOPIC) {
      await this._stopSpoonHelloServer()
    }
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
    await this._stopSpoonHelloServer()
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

function sendPlainText (res, code, text) {
  res.writeHead(code, TEXT_PLAIN_UTF8)
  res.end(text)
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
 * @param {{ port?: number, host?: string, primaryCidr?: string | null }} [opts] — omit `host` to bind on an auto loopback alias with manual name {@link CONTROL_PANEL_DNS_HOST} (port defaults to 80)
 * @returns {Promise<{ server: import('http').Server, sessions: ControlPlaneSessionManager, port: number, closeHttpServer: function(): Promise<void>, controlPanelBaseUrl: string }>}
 */
async function startControlHttpServer (opts = {}) {
  const explicitHost =
    opts.host != null && String(opts.host).trim() !== ''
  const port = opts.port != null ? Number(opts.port) : 80

  const sessions = new ControlPlaneSessionManager({
    primaryCidr: opts.primaryCidr != null ? opts.primaryCidr : null
  })
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

      if (req.method === 'GET' && path === '/api/dns/loopback') {
        const snap = await sessions.probeDnsLoopbackAliases()
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (
        (req.method === 'GET' || req.method === 'HEAD') &&
        (path === '/api/whois' || path.startsWith('/api/whois/'))
      ) {
        const tailRaw =
          path === '/api/whois' ? '' : path.slice('/api/whois/'.length)
        if (!tailRaw) {
          const line = sessions._clientPublicKeyZ32 + '\n'
          if (req.method === 'HEAD') {
            res.writeHead(200, {
              'Content-Type': 'text/plain; charset=utf-8',
              'Content-Length': Buffer.byteLength(line, 'utf8')
            })
            res.end()
            return
          }
          sendPlainText(res, 200, line)
          return
        }
        if (req.method === 'HEAD') {
          sendPlainText(res, 405, 'method not allowed\n')
          return
        }
        const decoded = decodeURIComponent(tailRaw)
        let asIp = decoded
        if (/^\[[^\]]+\]$/.test(asIp)) {
          asIp = asIp.slice(1, -1)
        }
        const isAddr = net.isIPv4(asIp) || net.isIPv6(asIp)

        if (isAddr) {
          const out = sessions.whoisIp(asIp)
          if (!out) {
            sendPlainText(res, 404, '')
            return
          }
          let line = out.wire
          if (!line) {
            try {
              line =
                out.kind === 'key'
                  ? formatKeyToDnsName(out.keyHex)
                  : formatMeshTopicDnsName(out.keyHex, out.topic || out.topicId)
            } catch (_) {
              sendPlainText(res, 500, 'wire format error\n')
              return
            }
          }
          sendPlainText(res, 200, line + '\n')
          return
        }

        let out = null
        try {
          const d = decoded.indexOf('.')
          if (d === -1) {
            out = sessions.whoisKey(decoded, null)
          } else {
            const keyPart = decoded.slice(0, d)
            const topicPart = decoded.slice(d + 1)
            if (!keyPart || !topicPart || topicPart.indexOf('.') >= 0) {
              sendPlainText(res, 400, 'bad key.topic (single dot, one topic label)\n')
              return
            }
            out = sessions.whoisKey(keyPart, topicPart)
          }
        } catch (e) {
          sendPlainText(res, 400, String(e && e.message ? e.message : e) + '\n')
          return
        }
        if (!out || !out.ip) {
          sendPlainText(res, 404, '')
          return
        }
        sendPlainText(res, 200, out.ip + '\n')
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

      if (req.method === 'POST' && path === '/api/mesh-reservations') {
        const body = await readBody(req)
        const op = String(body.op || '').trim()
        if (op === 'reservePrimary') {
          const out = sessions.reservePrimaryMeshKey(body.key)
          sendJson(res, 200, out)
          return
        }
        if (op === 'releasePrimary') {
          const ok = sessions.releasePrimaryMeshReservation(body.key)
          sendJson(res, 200, { ok })
          return
        }
        if (op === 'reserveTopic') {
          const out = sessions.reserveTopicMeshPeer(body.topicId, body.key)
          sendJson(res, 200, out)
          return
        }
        if (op === 'releaseTopic') {
          const ok = sessions.releaseTopicMeshReservation(
            body.topicId,
            body.key
          )
          sendJson(res, 200, { ok })
          return
        }
        throw new Error(
          'unknown mesh-reservations op (use reservePrimary, releasePrimary, reserveTopic, releaseTopic)'
        )
      }

      if (req.method === 'PATCH' && path === '/api/dns') {
        const body = await readBody(req)
        const out = await sessions.applyDnsSettings(body)
        sendJson(res, 200, out)
        return
      }

      if (req.method === 'POST' && path === '/api/dns/manual') {
        const body = await readBody(req)
        const out = await sessions.setDnsManualRecord(body)
        sendJson(res, 200, out)
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/dns/manual/')) {
        const host = decodeURIComponent(path.slice('/api/dns/manual/'.length))
        const ok = await sessions.deleteDnsManualRecord(host)
        sendJson(res, 200, { ok })
        return
      }

      if (req.method === 'POST' && path === '/api/dns/loopback') {
        const body = await readBody(req)
        const snap = await sessions.addDnsLoopbackAlias(body)
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/dns/loopback/')) {
        const ip = decodeURIComponent(path.slice('/api/dns/loopback/'.length))
        const snap = await sessions.removeDnsLoopbackAlias(ip)
        sendJson(res, 200, { loopback: snap })
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

  await sessions._syncDnsServer()
  sessions._controlHttpPort = actualPort
  await sessions._syncWhoisAuthService()
  await sessions._ensureSpoonTopicAndHello()
  sessions._emitStatus()

  setImmediate(function () {
    sessions.probeDnsLoopbackAliases().catch(function () {})
  })

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
      for (const r of dns.manual || []) {
        if (normalizeFqdn(r.hostname) === want && r.ipv4) {
          return 'http://nospoon/'
        }
      }
    }
    const rec = sessions._dnsManualRegistry.lookup(want)
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

  return {
    server,
    sessions,
    port: actualPort,
    closeHttpServer,
    controlPanelBaseUrl: computeControlPanelBaseUrl()
  }
}

module.exports = {
  ControlPlaneSessionManager,
  startControlHttpServer
}
