'use strict'

const fs = require('fs')
const os = require('os')
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
  decodePublicKeyLabel,
  formatKeyToDnsName,
  formatMeshTopicDnsName,
  normalizeFqdn,
  parseMeshDnsName
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
const { createBrowserNetProxy } = require('./browser-net-proxy')
const busboy = require('busboy')

const JSON_TYPE = { 'Content-Type': 'application/json; charset=utf-8' }
const TEXT_PLAIN_UTF8 = { 'Content-Type': 'text/plain; charset=utf-8' }
const HTML_TYPE = { 'Content-Type': 'text/html; charset=utf-8' }
const SSE_TYPE = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-cache',
  Connection: 'keep-alive'
}

const CORS_STAR = { 'Access-Control-Allow-Origin': '*' }

const SWARM_STATUS_DEBOUNCE_MS = 120
/** Re-run DHT lookup this often while a topic session is active so peers who announce later are seen (Hyperswarm’s own refresh can be ~10m). */
const TOPIC_DISCOVERY_POLL_MS = 12_000
/** Manual DNS hostname for the control panel (loopback alias + port 80 by default). */
const CONTROL_PANEL_DNS_HOST = 'nospoon'
/** Manual DNS name for the IPFS/CID HTTP gateway (loopback alias), distinct from {@link CONTROL_PANEL_DNS_HOST} and whois. */
const IPFS_DWEB_DNS_HOST = 'ipfs'
/**
 * Manual DNS hostname for browser-net WebSocket on the **same** loopback IPv4 as {@link IPFS_DWEB_DNS_HOST},
 * on {@link BROWSER_NET_DWEB_WS_PORT} (so CID pages can use `ws://middle:port/...` while HTTP stays on the CID host).
 */
const BROWSER_NET_DWEB_DNS_HOST = 'middle'
/** WebSocket port for browser-net beside IPFS CID HTTP (:80). */
const BROWSER_NET_DWEB_WS_PORT = 8766
/** Default Hyperswarm topic name — joined at control-plane startup. */
const DEFAULT_SPOON_TOPIC = 'spoon'
/** HTTP port for {@link DEFAULT_SPOON_TOPIC} mesh “hello” (bound to topic TUN IPv4). */
const SPOON_HELLO_HTTP_PORT = 80
/** Max wait for {@code addTopic} while answering the first mesh DNS {@code z32.topic} A query. */
const MESH_DNS_TOPIC_JOIN_WAIT_MS = 120_000

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
    /** Control HTTP bind address (set with port); whois proxy must reach this host, not assume 127.0.0.1. */
    this._controlHttpBindAddress = null
    /** User removed default `whois` manual record — do not auto-recreate until DNS is toggled off→on. */
    this._whoisDefaultRemoved = false
    /** User removed default `ipfs` gateway manual record — do not auto-recreate until IPFS off→on. */
    this._ipfsGatewayDefaultRemoved = false
    /** User removed default `middle` manual record — do not auto-recreate until IPFS off→on. */
    this._browserNetMiddleDefaultRemoved = false
    /** @type {{ enabled: boolean, mode: 'helia' | 'external', dataDir: string, externalGatewayUrl: string }} */
    this._ipfsConfig = {
      enabled: true,
      mode: 'helia',
      dataDir: '',
      externalGatewayUrl: 'http://127.0.0.1:8080'
    }
    /** @type {(() => Promise<void>) | null} */
    this._ipfsDwebStop = null
    this._ipfsDwebListening = false
    /** @type {string | null} */
    this._ipfsDwebBindIpv4 = null
    /** @type {string | null} */
    this._ipfsDwebLastError = null
    /** @type {{ stop: function(): Promise<void>, resolveContent: function(o: object): Promise<object> } | null} */
    this._ipfsHeliaBackend = null
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
    const selfSm = this
    this._browserNetProxy = createBrowserNetProxy({
      getKa () {
        return selfSm._sharedKeyAddress
      },
      getPrimaryTunIp () {
        return selfSm._directPool && selfSm._directPool.localTunIp
      },
      getDefaultListenIpv4 (ws) {
        return selfSm.getBrowserNetDefaultListenIpv4(ws)
      },
      prepareWebSocket (ws, req) {
        return selfSm.prepareBrowserNetWebSocket(ws, req)
      },
      resolveListenBind (hostRaw, ws) {
        return selfSm.resolveBrowserNetListenBind(hostRaw, ws)
      },
      resolveConnectHost (hostRaw, ws) {
        return selfSm.resolveBrowserNetConnectHost(hostRaw, ws)
      },
      getOutboundRoute (remoteIpv4, ws) {
        return selfSm.getBrowserNetOutboundRoute(remoteIpv4, ws)
      }
    })
    /** @type {import('ws').WebSocketServer | null} */
    this._browserNetWss = null
    /** @type {import('ws').WebSocketServer | null} */
    this._browserNetDwebWss = null
    /** @type {import('http').Server | null} */
    this._browserNetDwebHttpServer = null
    this._browserNetDwebListening = false
    /** @type {string | null} */
    this._browserNetDwebBindIpv4 = null
    /** @type {string | null} */
    this._browserNetDwebLastError = null
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
   * First {@code A} lookup for {@code z32.*.topic} with no topic row yet: join that Hyperswarm topic
   * in the background (same as {@link #prepareBrowserNetWebSocket} for browser tabs). The current
   * query still returns no A; a repeat query after the join completes can resolve {@code z32(me).topic}.
   * @param {string} topicRef — mesh DNS topic label (from {@link parseMeshDnsName})
   */
  _scheduleTopicJoinFromDns (topicRef) {
    const t = String(topicRef || '').trim()
    if (!t) return
    const self = this
    setImmediate(function () {
      void (async function () {
        try {
          if (self._resolveTopicRowByRef(t)) return
          await self.addTopic({ topic: t })
          self._emitStatus()
        } catch (e) {
          const msg = e && e.message ? e.message : String(e)
          if (/already joined|already in progress/i.test(msg)) return
        }
      })()
    })
  }

  /**
   * Block until {@code topicRef} has a topic row: run {@link #addTopic} or wait for an in-flight join.
   * @param {string} topicRef
   */
  async _ensureTopicJoinedForDnsAwait (topicRef) {
    const t = String(topicRef || '').trim()
    if (!t) return
    const discoveryHex = swarmDiscoveryKey(t).toString('hex')
    const deadline = Date.now() + MESH_DNS_TOPIC_JOIN_WAIT_MS
    while (Date.now() < deadline) {
      if (this._resolveTopicRowByRef(t)) return
      if (this._pendingTopicDiscoveryHex.has(discoveryHex)) {
        await new Promise(function (r) {
          setTimeout(r, 50)
        })
        continue
      }
      try {
        await this.addTopic({ topic: t })
      } catch (e) {
        const msg = e && e.message ? e.message : String(e)
        if (/already joined|already in progress/i.test(msg)) {
          await new Promise(function (r) {
            setTimeout(r, 50)
          })
          continue
        }
        throw e
      }
    }
    if (!this._resolveTopicRowByRef(t)) {
      throw new Error('mesh DNS: timeout waiting for topic join: ' + t)
    }
  }

  /**
   * Mesh DNS path: await topic join + TUN before resolving {@code key.topic} so the first A query can
   * return an address instead of NODATA. Other callers keep using {@link #dnsResolveMeshIpv4} (async join in background).
   * @param {{ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string }} meshId
   * @returns {Promise<string | null>}
   */
  async dnsResolveMeshIpv4ForDnsQuery (meshId) {
    if (
      meshId &&
      meshId.kind === 'keyTopic' &&
      !this._resolveTopicRowByRef(meshId.topicRef)
    ) {
      await this._ensureTopicJoinedForDnsAwait(meshId.topicRef)
    }
    return this.dnsResolveMeshIpv4(meshId)
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
   * @param {string} ip
   * @returns {boolean}
   */
  _isLocalMeshTunIp (ip) {
    const p = String(ip || '').trim()
    if (!net.isIPv4(p)) return false
    if (this._directPool && p === this._directPool.localTunIp) return true
    for (const row of this._topics.values()) {
      if (p === row.localTunIp) return true
    }
    return false
  }

  /**
   * Loopback `Origin` hosts allowed for local dev (full primary + topic listen/connect policy).
   * @param {string} host — {@link URL#hostname}
   * @returns {boolean}
   */
  _isLoopbackBrowserNetOriginHost (host) {
    const h = String(host || '').toLowerCase()
    if (h === 'localhost') return true
    if (net.isIPv4(h) && h === '127.0.0.1') return true
    if (h === '::1') return true
    return false
  }

  /**
   * @param {string} norm — {@link normalizeFqdn} topic label
   * @returns {object | null}
   */
  _findTopicRowByNormalizedTopicRef (norm) {
    const n = String(norm || '').trim().toLowerCase()
    if (!n) return null
    for (const row of this._topics.values()) {
      if (normalizeFqdn(row.topic) === n) return row
    }
    return null
  }

  /**
   * Single-label host from `Origin` that looks like an IPFS CID (HTTP `Host` for CID gateway pages).
   * @param {string} host
   * @returns {boolean}
   */
  _looksLikeIpfsCidHostname (host) {
    const h = String(host || '').toLowerCase()
    if (!h || h.includes('.')) return false
    if (h.startsWith('qm') && h.length >= 46) return true
    if (h.startsWith('baf')) return true
    return /^[a-z0-9]{46,}$/.test(h)
  }

  /**
   * @param {object | undefined} ws
   * @returns {boolean}
   */
  _browserNetOriginRestrictsListen (ws) {
    return !!(ws && ws._browserNetOriginRestricted && ws._browserNetOriginTopicRef)
  }

  /**
   * Hyperswarm topic for this browser tab. Joins the topic when the WebSocket opens for:
   * - `http://[cid]/` or `http://[z32]/` (topic string = that hostname label)
   * - `http://[z32key].[topic]/` mesh DNS shape — auto-join **`topic`** (not the remote key label)
   *
   * Requires a browser `Origin` (missing Origin closes the socket). Arbitrary multi-label sites
   * (e.g. `https://app.example/`) are rejected; **`z32.peer.topic`** two-label mesh names are allowed.
   * Use loopback `http://127.0.0.1/` / `http://localhost/` for dev. Real browsers set `Origin` and
   * cannot forge another site’s origin from a web page; native clients can still send arbitrary
   * `Origin`, so this is policy not cryptographic proof.
   *
   * @param {import('ws')} ws
   * @param {import('http').IncomingMessage} req
   * @returns {Promise<void>}
   */
  async prepareBrowserNetWebSocket (ws, req) {
    delete ws._browserNetOriginRestricted
    delete ws._browserNetOriginTopicRef
    delete ws._browserNetOriginDev

    const raw = req && req.headers && req.headers.origin
    if (!raw || !String(raw).trim()) {
      throw new Error('browser-net: Origin header required')
    }
    let u
    try {
      u = new URL(String(raw))
    } catch {
      throw new Error('browser-net: invalid Origin')
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error('browser-net: Origin must be http(s)')
    }
    const host = u.hostname

    if (this._isLoopbackBrowserNetOriginHost(host)) {
      ws._browserNetOriginDev = true
      return
    }

    if (net.isIPv4(host)) {
      throw new Error('browser-net: non-loopback IPv4 Origin not allowed')
    }
    if (net.isIPv6(host) && host !== '::1') {
      throw new Error('browser-net: non-loopback IPv6 Origin not allowed')
    }

    const meshFromOrigin = parseMeshDnsName(normalizeFqdn(host))
    if (meshFromOrigin && meshFromOrigin.kind === 'keyTopic') {
      const topicForJoin = meshFromOrigin.topicRef
      const topicNorm = normalizeFqdn(topicForJoin)
      ws._browserNetOriginRestricted = true
      ws._browserNetOriginTopicRef = topicNorm
      try {
        await this.addTopic({ topic: topicForJoin })
      } catch (e) {
        const msg = e && e.message ? e.message : String(e)
        if (!/already joined/i.test(msg)) throw e
      }
      return
    }

    if (host.includes('.') && !net.isIPv4(host)) {
      throw new Error('browser-net: multi-label Origin not allowed')
    }

    const topicForJoin = host
    const topicNorm = normalizeFqdn(host)
    let anchor = false
    if (this._looksLikeIpfsCidHostname(host)) anchor = true
    if (!anchor && decodePublicKeyLabel(host)) anchor = true
    if (!anchor) {
      throw new Error(
        'browser-net: Origin must be a CID or mesh key label (or loopback for dev)'
      )
    }

    ws._browserNetOriginRestricted = true
    ws._browserNetOriginTopicRef = topicNorm

    try {
      await this.addTopic({ topic: topicForJoin })
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      if (!/already joined/i.test(msg)) throw e
    }
  }

  /**
   * Default bind IP for `listen` / outbound local address when `host` is omitted: primary TUN,
   * or topic TUN when {@link #prepareBrowserNetWebSocket} pinned this socket to a topic-scoped Origin.
   * @param {import('ws') | undefined} ws
   * @returns {string | null}
   */
  getBrowserNetDefaultListenIpv4 (ws) {
    if (ws && ws._browserNetOriginDev) {
      return this._dnsPrimaryTunHostIpv4() || null
    }
    if (this._browserNetOriginRestrictsListen(ws)) {
      const T = ws._browserNetOriginTopicRef
      if (!T) return null
      return (
        this.dnsResolveMeshIpv4({
          kind: 'keyTopic',
          keyHex: this._clientKeyPair.publicKey.toString('hex'),
          topicRef: T
        }) || null
      )
    }
    return this._dnsPrimaryTunHostIpv4() || null
  }

  /**
   * Resolve a browser-net virtual `listen` bind: literal IPv4 must be this host’s primary or topic
   * TUN address; mesh DNS must name this node’s key only. Use {@link parseMeshDnsName} forms:
   * single-label z32 (primary mesh) or `z32.topic` (e.g. `… .spoon` is the **topic** label — do not strip
   * `.spoon` or it becomes primary-only and disagrees with DNS for the same hostname).
   * When the socket was opened from a single-label `Origin` (CID or z32 key host), only
   * `z32(this).topic` (and that topic’s TUN IPv4) is allowed — not the primary `z32` label alone.
   * @param {string} hostRaw
   * @param {import('ws') | undefined} [ws]
   * @returns {string | null} IPv4 or null
   */
  resolveBrowserNetListenBind (hostRaw, ws) {
    const s = String(hostRaw || '').trim()
    if (!s) return null
    const selfHex = this._clientKeyPair.publicKey.toString('hex')
    let ip = null
    let meshIdForSelf = null
    if (net.isIPv4(s)) {
      ip = this._isLocalMeshTunIp(s) ? s : null
    } else {
      const fqdn = normalizeFqdn(s)
      const meshId = parseMeshDnsName(fqdn)
      if (!meshId) return null
      if (meshId.keyHex !== selfHex) return null
      meshIdForSelf = meshId
      ip = this.dnsResolveMeshIpv4(meshId)
      if (!ip || !this._isLocalMeshTunIp(ip)) return null
    }

    if (!this._browserNetOriginRestrictsListen(ws)) return ip

    const T = /** @type {import('ws')} */ (ws)._browserNetOriginTopicRef
    if (net.isIPv4(s)) {
      const want = this.dnsResolveMeshIpv4({
        kind: 'keyTopic',
        keyHex: selfHex,
        topicRef: T
      })
      return want && s === want ? s : null
    }
    if (!meshIdForSelf || meshIdForSelf.kind !== 'keyTopic') return null
    if (normalizeFqdn(meshIdForSelf.topicRef) !== T) return null
    return ip
  }

  /**
   * Resolve browser-net outbound `connect` destination: IPv4 literal or mesh DNS for any peer.
   * Topic-scoped sockets ({@link #prepareBrowserNetWebSocket}): only `z32.peer.topic` names for the
   * same topic as `Origin`, not primary-only `z32` names (avoids reaching the global mesh from a
   * topic tab). IPv4 literals are still accepted; {@link #getBrowserNetOutboundRoute} uses only the
   * topic mesh router so primary-pool-only peers are unreachable.
   * @param {string} hostRaw
   * @param {import('ws') | undefined} [ws]
   * @returns {string | null}
   */
  resolveBrowserNetConnectHost (hostRaw, ws) {
    const s = String(hostRaw || '').trim()
    if (!s) return null
    if (!this._browserNetOriginRestrictsListen(ws)) {
      if (net.isIPv4(s)) return s
      const meshId = parseMeshDnsName(normalizeFqdn(s))
      if (!meshId) return null
      return this.dnsResolveMeshIpv4(meshId)
    }
    const T = /** @type {import('ws')} */ (ws)._browserNetOriginTopicRef
    if (net.isIPv4(s)) return s
    const meshId = parseMeshDnsName(normalizeFqdn(s))
    if (!meshId) return null
    if (meshId.kind === 'key') return null
    if (
      meshId.kind === 'keyTopic' &&
      normalizeFqdn(meshId.topicRef) !== T
    ) {
      return null
    }
    return this.dnsResolveMeshIpv4(meshId)
  }

  /**
   * Hyperswarm stream used to send framed IPv4 to a mesh peer (browser-net outbound SYN/data).
   * Topic-scoped sockets use only that topic’s TUN router (not the primary direct pool), so
   * outbound TCP targets peers on the same topic mesh only.
   * @param {string} remoteIpv4
   * @param {import('ws') | undefined} [ws]
   * @returns {{ peerKeyHex: string, peerAliasIp: string, writeFramed: (buf: Buffer) => void } | null}
   */
  getBrowserNetOutboundRoute (remoteIpv4, ws) {
    const p = String(remoteIpv4 || '').trim()
    if (!net.isIPv4(p)) return null
    if (this._browserNetOriginRestrictsListen(ws)) {
      const T = /** @type {import('ws')} */ (ws)._browserNetOriginTopicRef
      const row = this._findTopicRowByNormalizedTopicRef(T)
      if (!row || !row._handle || !row._handle.router) return null
      const ctx = this._sharedMeshRelayCtx()
      const c = row._handle.router.getConnectionForDestination(p, ctx)
      if (!c || c.destroyed || !c.remotePublicKey) return null
      return {
        peerKeyHex: c.remotePublicKey.toString('hex'),
        peerAliasIp: p,
        writeFramed (buf) {
          if (!c.destroyed) c.write(buf)
        }
      }
    }
    const conn = this._lookupRelayConnection(p)
    if (!conn || conn.destroyed || !conn.remotePublicKey) return null
    return {
      peerKeyHex: conn.remotePublicKey.toString('hex'),
      peerAliasIp: p,
      writeFramed (buf) {
        if (!conn.destroyed) conn.write(buf)
      }
    }
  }

  /**
   * Mesh DNS A record: shared key-address, live peers, then reservation (no status emit).
   * Successful answers schedule a primary {@link #joinPeer} (DNS as a dial surface).
   * The control plane’s own key always resolves: {@code z32(me)} → primary TUN host,
   * {@code z32(me).topic} → that topic interface’s local TUN address when the topic exists.
   * For unknown topics, the embedded DNS server awaits join (see {@link #dnsResolveMeshIpv4ForDnsQuery});
   * other callers still trigger {@link #_scheduleTopicJoinFromDns} on the first {@code key.topic} resolve.
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
      if (!row) {
        this._scheduleTopicJoinFromDns(meshId.topicRef)
        return null
      }
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
      },
      ipfsDweb: this.getIpfsDwebStatus()
    }
  }

  /**
   * @returns {{ enabled: boolean, mode: string, dataDir: string, externalGatewayUrl: string, listening: boolean, ipv4: string | null, httpPort: number, lastError: string | null, canUpload: boolean, browserNetDweb: { listening: boolean, ipv4: string | null, wsPort: number, dnsHost: string, lastError: string | null } }}
   */
  getIpfsDwebStatus () {
    const defaultDir = nodePath.join(os.homedir(), '.nospoon', 'helia')
    return {
      enabled: this._ipfsConfig.enabled,
      mode: this._ipfsConfig.mode,
      dataDir: this._ipfsConfig.dataDir.trim() || defaultDir,
      externalGatewayUrl:
        this._ipfsConfig.externalGatewayUrl.trim() ||
        'http://127.0.0.1:8080',
      listening: this._ipfsDwebListening,
      ipv4: this._ipfsDwebBindIpv4,
      httpPort: 80,
      lastError: this._ipfsDwebLastError,
      canUpload:
        Boolean(this._ipfsHeliaBackend) && this._ipfsConfig.mode === 'helia',
      browserNetDweb: {
        listening: this._browserNetDwebListening,
        ipv4: this._browserNetDwebBindIpv4,
        wsPort: BROWSER_NET_DWEB_WS_PORT,
        dnsHost: BROWSER_NET_DWEB_DNS_HOST,
        lastError: this._browserNetDwebLastError
      }
    }
  }

  /**
   * Add bytes to the local Helia blockstore (embedded mode only).
   * @param {string} filename
   * @param {Buffer} buffer
   * @returns {Promise<{ cid: string, filename: string }>}
   */
  async addIpfsFile (filename, buffer) {
    if (!this._ipfsConfig.enabled) {
      throw new Error('IPFS gateway is disabled')
    }
    if (this._ipfsConfig.mode !== 'helia') {
      throw new Error(
        'Upload from the panel requires embedded Helia; use `ipfs add` on your external node, or switch backend to Helia'
      )
    }
    const b = this._ipfsHeliaBackend
    if (!b || typeof b.addFile !== 'function') {
      throw new Error('Helia is not ready yet (enable DNS and IPFS, then wait for startup)')
    }
    const cid = await b.addFile({
      filename: String(filename || 'upload'),
      content: buffer
    })
    return { cid, filename: String(filename || 'upload').replace(/[/\\]/g, '_') || 'upload' }
  }

  /**
   * Add a directory tree (multipart file parts with relative paths) to local Helia.
   * @param {Array<{ path: string, content: Buffer }>} entries
   * @returns {Promise<{ cid: string, filename: string }>}
   */
  async addIpfsDirectory (entries) {
    if (!this._ipfsConfig.enabled) {
      throw new Error('IPFS gateway is disabled')
    }
    if (this._ipfsConfig.mode !== 'helia') {
      throw new Error(
        'Upload from the panel requires embedded Helia; use `ipfs add -r` on your external node, or switch backend to Helia'
      )
    }
    const b = this._ipfsHeliaBackend
    if (!b || typeof b.addDirectory !== 'function') {
      throw new Error('Helia is not ready yet (enable DNS and IPFS, then wait for startup)')
    }
    return b.addDirectory(entries)
  }

  /**
   * List recursive root pins in embedded Helia (persisted under the Helia data directory).
   * @returns {Promise<{ pins: Array<{ cid: string, filename: string }> }>}
   */
  async listIpfsPins () {
    if (!this._ipfsConfig.enabled || this._ipfsConfig.mode !== 'helia') {
      return { pins: [] }
    }
    const b = this._ipfsHeliaBackend
    if (!b || typeof b.listPins !== 'function') {
      return { pins: [] }
    }
    const pins = await b.listPins()
    return { pins }
  }

  /**
   * Unpin a CID and run blockstore GC (embedded Helia only).
   * @param {string} cidStr
   */
  async unpinIpfs (cidStr) {
    if (!this._ipfsConfig.enabled) {
      throw new Error('IPFS gateway is disabled')
    }
    if (this._ipfsConfig.mode !== 'helia') {
      throw new Error('Unpin requires embedded Helia')
    }
    const b = this._ipfsHeliaBackend
    if (!b || typeof b.unpin !== 'function') {
      throw new Error('Helia is not ready yet (enable DNS and IPFS, then wait for startup)')
    }
    await b.unpin(String(cidStr || '').trim())
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
        return self.dnsResolveMeshIpv4ForDnsQuery(id)
      },
      resolveCidGatewayA: function () {
        if (!self._ipfsConfig.enabled) return null
        if (!self._ipfsDwebListening || !self._ipfsDwebBindIpv4) return null
        return self._ipfsDwebBindIpv4
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
        const ip = await dnsLoopbackAliases.addLoopbackAlias('', {
          excludeIps: this._manualIpv4sUsedByOtherManualHosts(
            normalizeFqdn('whois')
          )
        })
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
      controlHost:
        this._controlHttpBindAddress != null
          ? this._controlHttpBindAddress
          : '127.0.0.1',
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
   * Tear down the extra browser-net WebSocket listener on the IPFS loopback ({@link BROWSER_NET_DWEB_WS_PORT}).
   * @returns {Promise<void>}
   */
  async _stopBrowserNetDwebService () {
    this._browserNetDwebLastError = null
    if (this._browserNetDwebWss) {
      try {
        this._browserNetDwebWss.close()
      } catch (_) {}
      this._browserNetDwebWss = null
    }
    const srv = this._browserNetDwebHttpServer
    this._browserNetDwebHttpServer = null
    if (srv) {
      await new Promise(function (resolve) {
        srv.close(function () {
          resolve()
        })
      })
    }
    this._browserNetDwebListening = false
    this._browserNetDwebBindIpv4 = null
  }

  /**
   * Same loopback IPv4 as the CID gateway, separate port — WebSocket only for pages hosted at `http://&lt;cid&gt;/`.
   * @param {string} bindIpv4
   * @returns {Promise<void>}
   */
  async _startBrowserNetDwebOnIpfsLoopback (bindIpv4) {
    await this._stopBrowserNetDwebService()
    const ip = String(bindIpv4 || '').trim()
    if (!ip || !this._dnsListening) return

    if (!this._browserNetMiddleDefaultRemoved) {
      const midRec = this._dnsManualRegistry.lookup(
        normalizeFqdn(BROWSER_NET_DWEB_DNS_HOST)
      )
      this._dnsManualRegistry.set(BROWSER_NET_DWEB_DNS_HOST, {
        ipv4: ip,
        ipv6: midRec && midRec.ipv6
      })
      await this.probeDnsLoopbackAliases()
    }

    const self = this
    const srv = http.createServer(function (req, res) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('browser-net WebSocket only\n')
    })
    this._browserNetDwebWss = this._browserNetProxy.attachToHttpServer(srv)
    this._browserNetDwebHttpServer = srv

    try {
      await new Promise(function (resolve, reject) {
        srv.once('error', reject)
        srv.listen(BROWSER_NET_DWEB_WS_PORT, ip, function () {
          srv.removeListener('error', reject)
          resolve()
        })
      })
      this._browserNetDwebListening = true
      this._browserNetDwebBindIpv4 = ip
    } catch (e) {
      await self._stopBrowserNetDwebService()
      throw e
    }
  }

  async _stopIpfsDwebService () {
    await this._stopBrowserNetDwebService()
    if (this._ipfsDwebStop) {
      try {
        await this._ipfsDwebStop()
      } catch (_) {}
      this._ipfsDwebStop = null
    }
    this._ipfsHeliaBackend = null
    this._ipfsDwebListening = false
    this._ipfsDwebBindIpv4 = null
  }

  /**
   * Loopback alias + HTTP :80: {@code Host} is a multibase CID → UnixFS via Helia or an external gateway.
   * Manual name `{@link IPFS_DWEB_DNS_HOST}` points at the same IPv4 as DNS A for CID hostnames.
   * @returns {Promise<void>}
   */
  async _syncIpfsDwebService () {
    await this._stopIpfsDwebService()
    this._ipfsDwebLastError = null

    if (!this._ipfsConfig.enabled) return
    if (!this._dnsListening || !this._dnsConfig.enabled) return
    if (this._controlHttpPort == null) return

    if (!dnsLoopbackAliases.platformSupportsLoopbackAliases()) {
      this._ipfsDwebLastError =
        'IPFS dweb HTTP needs loopback aliases (macOS or Linux)'
      return
    }

    let rec = this._dnsManualRegistry.lookup(normalizeFqdn(IPFS_DWEB_DNS_HOST))
    if ((!rec || !rec.ipv4) && !this._ipfsGatewayDefaultRemoved) {
      try {
        const ip = await dnsLoopbackAliases.addLoopbackAlias('', {
          excludeIps: this._manualIpv4sUsedByOtherManualHosts(
            normalizeFqdn(IPFS_DWEB_DNS_HOST)
          )
        })
        this._dnsManualRegistry.set(IPFS_DWEB_DNS_HOST, {
          ipv4: ip,
          ipv6: rec && rec.ipv6
        })
        await this.probeDnsLoopbackAliases()
        rec = this._dnsManualRegistry.lookup(normalizeFqdn(IPFS_DWEB_DNS_HOST))
      } catch (e) {
        this._ipfsDwebLastError = e && e.message ? e.message : String(e)
        return
      }
    }

    if (!rec || !rec.ipv4) return

    const bindIpv4 = rec.ipv4
    const { createIpfsDwebHttpServer } = require('./ipfs-dweb-http')
    const { resolveViaExternalGateway } = require('./ipfs-resolve-content')
    const { createHeliaWorkerBackend } = require('./ipfs-helia-worker-bridge')

    /** @type {(o: object) => Promise<object>} */
    let resolveContent
    try {
      if (this._ipfsConfig.mode === 'external') {
        const base = String(
          this._ipfsConfig.externalGatewayUrl || ''
        ).trim() || 'http://127.0.0.1:8080'
        let parsed
        try {
          parsed = new URL(base.endsWith('/') ? base : base + '/')
        } catch (_) {
          throw new Error('invalid externalGatewayUrl')
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          throw new Error('externalGatewayUrl must be http(s)')
        }
        resolveContent = function (o) {
          return resolveViaExternalGateway(base, o)
        }
      } else {
        const dir =
          String(this._ipfsConfig.dataDir || '').trim() ||
          nodePath.join(os.homedir(), '.nospoon', 'helia')
        this._ipfsHeliaBackend = await createHeliaWorkerBackend(dir)
        const backend = this._ipfsHeliaBackend
        resolveContent = function (o) {
          return backend.resolveContent(o)
        }
      }
    } catch (e) {
      this._ipfsDwebLastError = e && e.message ? e.message : String(e)
      this._ipfsHeliaBackend = null
      return
    }

    const dweb = createIpfsDwebHttpServer({
      bindAddress: bindIpv4,
      port: 80,
      resolveContent
    })

    const self = this
    let httpSrv = dweb
    const heliaBackend = this._ipfsHeliaBackend
    try {
      await dweb.start()
      this._ipfsDwebStop = async function () {
        try {
          await httpSrv.stop()
        } catch (_) {}
        if (heliaBackend) {
          try {
            await heliaBackend.stop()
          } catch (_) {}
        }
        self._ipfsHeliaBackend = null
      }
      this._ipfsDwebListening = true
      this._ipfsDwebBindIpv4 = bindIpv4
      try {
        await this._startBrowserNetDwebOnIpfsLoopback(bindIpv4)
      } catch (e) {
        this._browserNetDwebLastError =
          e && e.message ? e.message : String(e)
      }
    } catch (e) {
      this._ipfsDwebLastError = e && e.message ? e.message : String(e)
      this._ipfsDwebStop = null
      if (heliaBackend) {
        try {
          await heliaBackend.stop()
        } catch (_) {}
      }
      this._ipfsHeliaBackend = null
    }
  }

  /**
   * @param {object} body
   * @returns {Promise<object>}
   */
  async applyIpfsSettings (body) {
    if (!body || typeof body !== 'object') body = {}
    if (typeof body.enabled === 'boolean') this._ipfsConfig.enabled = body.enabled
    if (body.mode === 'helia' || body.mode === 'external') {
      this._ipfsConfig.mode = body.mode
    }
    if (body.dataDir != null) {
      this._ipfsConfig.dataDir = String(body.dataDir).trim()
    }
    if (body.externalGatewayUrl != null) {
      const raw = String(body.externalGatewayUrl).trim()
      if (raw) {
        let parsed
        try {
          parsed = new URL(raw)
        } catch (_) {
          throw new Error('externalGatewayUrl must be a valid URL')
        }
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          throw new Error('externalGatewayUrl must be http(s)')
        }
        this._ipfsConfig.externalGatewayUrl = raw.endsWith('/')
          ? raw.slice(0, -1)
          : raw
      } else {
        this._ipfsConfig.externalGatewayUrl = 'http://127.0.0.1:8080'
      }
    }
    await this._syncIpfsDwebService()
    this._emitStatus()
    return this.getIpfsDwebStatus()
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
    await this._syncWhoisAuthService()
    await this._syncIpfsDwebService()
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
      allocatedLoopbackIpv4 = await dnsLoopbackAliases.addLoopbackAlias('', {
        excludeIps: this._manualIpv4sUsedByOtherManualHosts(normalizeFqdn(host))
      })
      ipv4 = allocatedLoopbackIpv4
    }
    this._dnsManualRegistry.set(host, { ipv4, ipv6 })
    const manual = this._dnsManualRegistry.list()
    if (allocatedLoopbackIpv4) {
      await this.probeDnsLoopbackAliases()
    }
    await this._syncWhoisAuthService()
    await this._syncIpfsDwebService()
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
    if (n === normalizeFqdn(IPFS_DWEB_DNS_HOST)) {
      this._ipfsGatewayDefaultRemoved = true
    }
    if (n === normalizeFqdn(BROWSER_NET_DWEB_DNS_HOST)) {
      this._browserNetMiddleDefaultRemoved = true
    }
    const ok = this._dnsManualRegistry.delete(String(hostname || '').trim())
    await this._syncWhoisAuthService()
    await this._syncIpfsDwebService()
    this._emitStatus()
    return ok
  }

  /**
   * IPv4s already tied to other manual hostnames (not {@code forHostname}), so auto loopback pick
   * does not assign the same address to e.g. `nospoon` and `whois`.
   * @param {string} forHostnameNormalized
   * @returns {string[]}
   */
  _manualIpv4sUsedByOtherManualHosts (forHostnameNormalized) {
    const self = normalizeFqdn(forHostnameNormalized)
    const out = []
    for (const row of this._dnsManualRegistry.list()) {
      if (normalizeFqdn(row.hostname) === self) continue
      if (row.ipv4 && net.isIPv4(row.ipv4)) out.push(row.ipv4)
    }
    return out
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
    const ip = await dnsLoopbackAliases.addLoopbackAlias('', {
      excludeIps: this._manualIpv4sUsedByOtherManualHosts(name)
    })
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
    const { createSpoonHelloServer } = require('../examples/spoon-hello/server')
    const bindAddresses = [row.localTunIp]
    const primaryIp =
      this._directPool && this._directPool.localTunIp
        ? String(this._directPool.localTunIp).trim()
        : ''
    if (primaryIp && primaryIp !== String(row.localTunIp).trim()) {
      bindAddresses.push(primaryIp)
    }
    const srv = createSpoonHelloServer({
      bindAddresses,
      port: SPOON_HELLO_HTTP_PORT,
      myPublicKeyZ32: this._clientPublicKeyZ32,
      secretKey: this._clientKeyPair.secretKey,
      fetchVisitorKeyLine: function (ip) {
        return self._fetchWhoisLineForVisitorIp(ip)
      },
      getHtmlEmbedConfig: function () {
        const host = self._controlHttpBindAddress || '127.0.0.1'
        const p =
          self._controlHttpPort != null ? Number(self._controlHttpPort) : 80
        const h = net.isIPv6(host) ? `[${host}]` : String(host)
        const origin = p === 80 ? `http://${h}` : `http://${h}:${p}`
        return {
          controlPanelOrigin: origin,
          primaryMeshZ32: self._clientPublicKeyZ32
        }
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
        'nospoon: ingress full tunnel:',
        e && e.message ? e.message : e
      )
    }
    try {
      this._syncPrimaryEgressClient()
    } catch (e) {
      console.error(
        'nospoon: egress full tunnel:',
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
            'nospoon: disable server forwarding:',
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
      console.error('nospoon: enable server forwarding:', msg)
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
            'nospoon: disable client full tunnel:',
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
      console.error('nospoon: enable client full tunnel:', msg)
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
      // NoiseSecretStream emits `error` (e.g. ECONNRESET); must not be uncaught while routing is async.
      conn.on('error', function () {})
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
      topicFirstFrameAuth,
      inboundConn: conn,
      tryBrowserProxy: function (packet, ctx) {
        return self._browserNetProxy.tryConsumeInboundPacket(packet, ctx)
      }
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
    await this._stopIpfsDwebService()
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

const MAX_IPFS_UPLOAD_BYTES = 64 * 1024 * 1024

/**
 * @param {import('http').IncomingMessage} req
 * @param {number} maxLen
 * @returns {Promise<Buffer>}
 */
function readRawBody (req, maxLen) {
  return new Promise(function (resolve, reject) {
    const chunks = []
    let len = 0
    req.on('data', function (c) {
      len += c.length
      if (len > maxLen) {
        reject(new Error('upload too large (max ' + maxLen + ' bytes)'))
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', function () {
      resolve(Buffer.concat(chunks))
    })
    req.on('error', reject)
  })
}

/**
 * Parse multipart/form-data: one file per part. Prefer the field name as the relative path
 * (browsers often repeat basename in filename= for every part).
 * @param {import('http').IncomingMessage} req
 * @param {number} maxTotal
 * @returns {Promise<Array<{ path: string, content: Buffer }>>}
 */
function readMultipartIpfsDirectory (req, maxTotal) {
  return new Promise(function (resolve, reject) {
    const ct = String(req.headers['content-type'] || '').toLowerCase()
    if (ct.indexOf('multipart/form-data') !== 0) {
      reject(new Error('Content-Type must be multipart/form-data'))
      return
    }
    /** @type {Array<{ path: string, content: Buffer }>} */
    const entries = []
    let total = 0
    let settled = false
    function fail (err) {
      if (settled) return
      settled = true
      reject(err)
    }
    const bb = busboy({
      headers: req.headers,
      limits: { files: 100_000 }
    })
    bb.on('file', function (fieldname, file, info) {
      let name = String(fieldname || '').trim()
      if (name === 'f' || name === '') {
        name = info && info.filename ? String(info.filename).trim() : ''
      }
      if (!name) {
        file.resume()
        return
      }
      const chunks = []
      file.on('data', function (d) {
        if (settled) return
        total += d.length
        if (total > maxTotal) {
          fail(new Error('upload too large (max ' + maxTotal + ' bytes)'))
          file.resume()
          return
        }
        chunks.push(d)
      })
      file.on('limit', function () {
        fail(new Error('upload too large (max ' + maxTotal + ' bytes)'))
      })
      file.on('end', function () {
        if (settled) return
        entries.push({ path: name, content: Buffer.concat(chunks) })
      })
    })
    bb.on('error', function (err) {
      fail(err || new Error('multipart parse error'))
    })
    bb.on('close', function () {
      if (settled) return
      settled = true
      resolve(entries)
    })
    req.on('error', fail)
    req.pipe(bb)
  })
}

function sendJson (res, code, obj) {
  res.writeHead(code, JSON_TYPE)
  res.end(JSON.stringify(obj))
}

function sendPlainText (res, code, text, extraHeaders) {
  const headers = Object.assign({}, TEXT_PLAIN_UTF8, extraHeaders || {})
  res.writeHead(code, headers)
  res.end(text)
}

const WEB_BUNDLE_JS = nodePath.join(__dirname, 'web.bundle.js')
const WEB_BUNDLE_CSS = nodePath.join(__dirname, 'web.bundle.css')
const BROWSER_NET_SHIM_JS = nodePath.join(__dirname, 'browser-net-shim.bundle.js')
const V86_LIBV86_MJS = nodePath.join(__dirname, 'v86', 'libv86.mjs')
const V86_WASM = nodePath.join(__dirname, 'v86', 'v86.wasm')
const V86_HELLO_DEMO_MJS = nodePath.join(__dirname, 'v86', 'hello-demo.mjs')
const V86_GUEST_SEABIOS = nodePath.join(__dirname, 'v86', 'guest', 'seabios.bin')
const V86_GUEST_VGABIOS = nodePath.join(__dirname, 'v86', 'guest', 'vgabios.bin')
const V86_GUEST_FREEBSD_META = nodePath.join(__dirname, 'v86', 'guest', 'freebsd-meta.json')
const V86_GUEST_FREEBSD_STATE_ZST = nodePath.join(
  __dirname,
  'v86',
  'guest',
  'freebsd_state-v2.bin.zst'
)
const V86_GUEST_FREEBSD_DIR = nodePath.join(__dirname, 'v86', 'guest', 'freebsd')

function isV86GuestUrlPath (pathname) {
  return (
    pathname === '/v86/guest/seabios.bin' ||
    pathname === '/v86/guest/vgabios.bin' ||
    pathname === '/v86/guest/freebsd-meta.json' ||
    pathname === '/v86/guest/freebsd_state-v2.bin.zst' ||
    /^\/v86\/guest\/freebsd\/[0-9]+-[0-9]+\.img$/.test(pathname)
  )
}

/**
 * v86 loads large images with Range requests; plain readFile would break that.
 */
function sendV86GuestFile (req, res, filePath, extraHeaders) {
  fs.stat(filePath, function (err, st) {
    if (err || !st.isFile()) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end(
        'v86 guest asset missing. From the nospoon package root run npm run build once (network: seabios/vgabios; optional FreeBSD: npm run fetch-freebsd-disk).\n'
      )
      return
    }
    const size = st.size
    const baseHeaders = Object.assign(
      {
        'Content-Type': 'application/octet-stream',
        'Accept-Ranges': 'bytes'
      },
      extraHeaders || {}
    )
    const range = req.headers.range
    if (range) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(String(range).trim())
      if (!m) {
        res.writeHead(416, {
          'Content-Range': 'bytes */' + size,
          'Content-Type': 'text/plain; charset=utf-8'
        })
        res.end()
        return
      }
      let start = m[1] === '' ? NaN : parseInt(m[1], 10)
      let end = m[2] === '' ? NaN : parseInt(m[2], 10)
      if (m[1] === '' && m[2] !== '') {
        const suffix = parseInt(m[2], 10)
        if (Number.isNaN(suffix) || suffix <= 0) {
          res.writeHead(416, {
            'Content-Range': 'bytes */' + size,
            'Content-Type': 'text/plain; charset=utf-8'
          })
          res.end()
          return
        }
        start = Math.max(0, size - suffix)
        end = size - 1
      } else {
        if (Number.isNaN(start)) start = 0
        if (Number.isNaN(end)) end = size - 1
      }
      if (
        Number.isNaN(start) ||
        Number.isNaN(end) ||
        start > end ||
        start >= size
      ) {
        res.writeHead(416, {
          'Content-Range': 'bytes */' + size,
          'Content-Type': 'text/plain; charset=utf-8'
        })
        res.end()
        return
      }
      if (end >= size) end = size - 1
      const chunk = end - start + 1
      res.writeHead(206, {
        ...baseHeaders,
        'Content-Length': String(chunk),
        'Content-Range': 'bytes ' + start + '-' + end + '/' + size
      })
      const stream = fs.createReadStream(filePath, { start, end })
      stream.on('error', function () {
        try {
          res.destroy()
        } catch (_) {}
      })
      stream.pipe(res)
      return
    }
    res.writeHead(200, {
      ...baseHeaders,
      'Content-Length': String(size)
    })
    const stream = fs.createReadStream(filePath)
    stream.on('error', function () {
      try {
        res.destroy()
      } catch (_) {}
    })
    stream.pipe(res)
  })
}

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

function sendWebBundle (res, filePath, contentType, extraHeaders) {
  fs.readFile(filePath, function (err, data) {
    if (err) {
      res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end(
        'Web bundle missing. From the nospoon package root run: npm install && npm run build\n'
      )
      return
    }
    const headers = Object.assign(
      { 'Content-Type': contentType },
      extraHeaders || {}
    )
    res.writeHead(200, headers)
    res.end(data)
  })
}

/**
 * @param {{ port?: number, host?: string, primaryCidr?: string | null }} [opts] — omit `host` to bind on an auto loopback alias with manual name {@link CONTROL_PANEL_DNS_HOST} (port defaults to 80)
 * @returns {Promise<{ server: import('http').Server, sessions: ControlPlaneSessionManager, port: number, closeHttpServer: function(): Promise<void>, controlPanelBaseUrl: string, controlPanelRunningOnDisplay: string, keyLinkUrl: string, keyLinkDisplay: string }>}
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
      if (req.method === 'OPTIONS' && path === '/browser-net-shim.js') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        })
        res.end()
        return
      }

      if (
        req.method === 'OPTIONS' &&
        (path === '/v86/libv86.mjs' ||
          path === '/v86/v86.wasm' ||
          path === '/v86/hello-demo.mjs' ||
          isV86GuestUrlPath(path))
      ) {
        res.writeHead(204, {
          ...CORS_STAR,
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        })
        res.end()
        return
      }

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

      if (req.method === 'GET' && path === '/browser-net-shim.js') {
        sendWebBundle(
          res,
          BROWSER_NET_SHIM_JS,
          'application/javascript; charset=utf-8',
          { 'Access-Control-Allow-Origin': '*' }
        )
        return
      }

      if (req.method === 'GET' && path === '/v86/libv86.mjs') {
        sendWebBundle(
          res,
          V86_LIBV86_MJS,
          'application/javascript; charset=utf-8',
          { ...CORS_STAR }
        )
        return
      }

      if (req.method === 'GET' && path === '/v86/hello-demo.mjs') {
        sendWebBundle(
          res,
          V86_HELLO_DEMO_MJS,
          'application/javascript; charset=utf-8',
          { ...CORS_STAR }
        )
        return
      }

      if (req.method === 'GET' && path === '/v86/v86.wasm') {
        sendWebBundle(
          res,
          V86_WASM,
          'application/wasm',
          { ...CORS_STAR }
        )
        return
      }

      if (req.method === 'GET' && path === '/v86/guest/seabios.bin') {
        sendV86GuestFile(req, res, V86_GUEST_SEABIOS, { ...CORS_STAR })
        return
      }

      if (req.method === 'GET' && path === '/v86/guest/vgabios.bin') {
        sendV86GuestFile(req, res, V86_GUEST_VGABIOS, { ...CORS_STAR })
        return
      }

      if (req.method === 'GET' && path === '/v86/guest/freebsd-meta.json') {
        fs.readFile(V86_GUEST_FREEBSD_META, function (err, data) {
          if (err) {
            res.writeHead(503, {
              'Content-Type': 'text/plain; charset=utf-8',
              ...CORS_STAR
            })
            res.end(
              'freebsd-meta.json missing. From the nospoon package root run: node scripts/copy-v86-assets.js (or npm run build).\n'
            )
            return
          }
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            ...CORS_STAR
          })
          res.end(data)
        })
        return
      }

      if (req.method === 'GET' && path === '/v86/guest/freebsd_state-v2.bin.zst') {
        sendV86GuestFile(req, res, V86_GUEST_FREEBSD_STATE_ZST, { ...CORS_STAR })
        return
      }

      {
        const m = /^\/v86\/guest\/freebsd\/([0-9]+-[0-9]+\.img)$/.exec(path)
        if (req.method === 'GET' && m) {
          const chunkPath = nodePath.join(V86_GUEST_FREEBSD_DIR, m[1])
          const baseResolved = nodePath.resolve(V86_GUEST_FREEBSD_DIR)
          const resolved = nodePath.resolve(chunkPath)
          if (
            resolved !== baseResolved &&
            !resolved.startsWith(baseResolved + nodePath.sep)
          ) {
            res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
            res.end('bad path\n')
            return
          }
          sendV86GuestFile(req, res, chunkPath, { ...CORS_STAR })
          return
        }
      }

      if (req.method === 'GET' && path === '/web.css') {
        sendWebBundle(res, WEB_BUNDLE_CSS, 'text/css; charset=utf-8')
        return
      }

      if (req.method === 'GET' && path === '/api/status') {
        sendJson(res, 200, sessions.getStatus())
        return
      }

      if (req.method === 'GET' && path === '/api/browser-net/status') {
        sendJson(res, 200, sessions._browserNetProxy.getStatus())
        return
      }

      if (req.method === 'GET' && path === '/api/dns/loopback') {
        const snap = await sessions.probeDnsLoopbackAliases()
        sendJson(res, 200, { loopback: snap })
        return
      }

      if (
        req.method === 'OPTIONS' &&
        (path === '/api/whois' || path.startsWith('/api/whois/'))
      ) {
        res.writeHead(204, {
          ...CORS_STAR,
          'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        })
        res.end()
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
              'Content-Length': Buffer.byteLength(line, 'utf8'),
              ...CORS_STAR
            })
            res.end()
            return
          }
          sendPlainText(res, 200, line, CORS_STAR)
          return
        }
        if (req.method === 'HEAD') {
          sendPlainText(res, 405, 'method not allowed\n', CORS_STAR)
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
            sendPlainText(res, 404, 'not found\n', CORS_STAR)
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
              sendPlainText(res, 500, 'wire format error\n', CORS_STAR)
              return
            }
          }
          sendPlainText(res, 200, line + '\n', CORS_STAR)
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
              sendPlainText(
                res,
                400,
                'bad key.topic (single dot, one topic label)\n',
                CORS_STAR
              )
              return
            }
            out = sessions.whoisKey(keyPart, topicPart)
          }
        } catch (e) {
          sendPlainText(
            res,
            400,
            String(e && e.message ? e.message : e) + '\n',
            CORS_STAR
          )
          return
        }
        if (!out || !out.ip) {
          sendPlainText(res, 404, 'not found\n', CORS_STAR)
          return
        }
        sendPlainText(res, 200, out.ip + '\n', CORS_STAR)
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

      if (req.method === 'GET' && path === '/api/ipfs') {
        sendJson(res, 200, sessions.getIpfsDwebStatus())
        return
      }

      if (req.method === 'GET' && path === '/api/ipfs/pins') {
        sessions
          .listIpfsPins()
          .then(function (out) {
            sendJson(res, 200, out)
          })
          .catch(function (e) {
            const msg = e && e.message ? e.message : String(e)
            sendJson(res, 500, { error: msg })
          })
        return
      }

      if (req.method === 'DELETE' && path.startsWith('/api/ipfs/pins/')) {
        const cid = decodeURIComponent(path.slice('/api/ipfs/pins/'.length).trim())
        if (!cid) {
          sendJson(res, 400, { error: 'missing cid' })
          return
        }
        sessions
          .unpinIpfs(cid)
          .then(function () {
            return sessions.listIpfsPins()
          })
          .then(function (out) {
            sendJson(res, 200, out)
          })
          .catch(function (e) {
            const msg = e && e.message ? e.message : String(e)
            sendJson(res, 400, { error: msg })
          })
        return
      }

      if (req.method === 'POST' && path === '/api/ipfs/add') {
        const ct = String(req.headers['content-type'] || '').toLowerCase()
        if (ct.indexOf('multipart/form-data') === 0) {
          sendJson(res, 415, {
            error:
              'Send raw bytes: Content-Type application/octet-stream, body=file, ?filename= or X-Filename'
          })
          return
        }
        let filename = 'upload'
        try {
          const u = new URL(req.url || '', 'http://127.0.0.1')
          const q = u.searchParams.get('filename')
          if (q) filename = decodeURIComponent(q)
        } catch (_) {}
        const xh = req.headers['x-filename'] || req.headers['X-Filename']
        if (xh) {
          filename = String(xh).trim() || filename
        }
        const buf = await readRawBody(req, MAX_IPFS_UPLOAD_BYTES)
        if (!buf.length) {
          sendJson(res, 400, { error: 'empty body' })
          return
        }
        try {
          const out = await sessions.addIpfsFile(filename, buf)
          sessions._emitStatus()
          sendJson(res, 200, out)
        } catch (e) {
          const msg = e && e.message ? e.message : String(e)
          sendJson(res, 400, { error: msg })
        }
        return
      }

      if (req.method === 'POST' && path === '/api/ipfs/add-directory') {
        const ct = String(req.headers['content-type'] || '').toLowerCase()
        if (ct.indexOf('multipart/form-data') !== 0) {
          sendJson(res, 415, {
            error: 'Use multipart/form-data with file parts (filename = relative path)'
          })
          return
        }
        readMultipartIpfsDirectory(req, MAX_IPFS_UPLOAD_BYTES)
          .then(function (entries) {
            if (!entries.length) {
              throw new Error('no files selected')
            }
            return sessions.addIpfsDirectory(entries)
          })
          .then(function (out) {
            sessions._emitStatus()
            sendJson(res, 200, out)
          })
          .catch(function (e) {
            const msg = e && e.message ? e.message : String(e)
            sendJson(res, 400, { error: msg })
          })
        return
      }

      if (req.method === 'PATCH' && path === '/api/ipfs') {
        const body = await readBody(req)
        const out = await sessions.applyIpfsSettings(body)
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

  sessions._browserNetWss = sessions._browserNetProxy.attachToHttpServer(server)

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
  await sessions._syncIpfsDwebService()
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
    if (sessions._browserNetWss) {
      try {
        sessions._browserNetWss.close()
      } catch (_) {}
      sessions._browserNetWss = null
    }
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

  function computeControlPanelRunningOnDisplay () {
    const primary = computeControlPanelBaseUrl()
    if (primary === 'http://nospoon/') {
      const want = normalizeFqdn(CONTROL_PANEL_DNS_HOST)
      const rec = sessions._dnsManualRegistry.lookup(want)
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

module.exports = {
  ControlPlaneSessionManager,
  startControlHttpServer
}
