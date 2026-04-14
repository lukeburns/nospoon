'use strict'

const net = require('net')
const dnsLoopbackAliases = require('../dns/dns-loopback-aliases')
const { normalizeFqdn } = require('../dns/dns-mesh-name')
const { stripHostFromCidr } = require('../mesh/key-address')
const { CONTROL_PANEL_DNS_HOST } = require('./control-constants')

module.exports = {
  /**
   * After answering mesh DNS, open (or refresh) a primary direct pool session — same idea as
   * spoondns ambient client nudges, using this host’s shared Hyperswarm identity.
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
  },
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
  },
  /**
   * Primary (direct pool) TUN host IPv4 for this process — same address as `z32(local key)` mesh DNS.
   * @returns {string | null}
   */
  _dnsPrimaryTunHostIpv4 () {
    if (this._directPool) return this._directPool.localTunIp
    const cidr = this._meshIpReservations.getPrimaryCidr()
    return cidr ? stripHostFromCidr(cidr) : null
  },
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
  },
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
  },
  getDnsStatus () {
    const fwd =
      this._dnsConfig.forwardEnabled
        ? this._dnsConfig.forwardTarget || '1.1.1.1'
        : null
    /** @type {{ enabled: boolean, active: boolean, lastMessage: string | null, platform: string } | null} */
    let systemDnsOverride = null
    if (this._systemDnsOverride) {
      const o = require('../dns/dns-system-override')
      systemDnsOverride = {
        enabled: true,
        active: o.isActive(),
        lastMessage: o.getLastMessage(),
        platform: process.platform
      }
    }
    return {
      enabled: this._dnsConfig.enabled,
      listening: this._dnsListening,
      port: this._dnsConfig.port,
      address: this._dnsConfig.address,
      forwardEnabled: this._dnsConfig.forwardEnabled,
      forward: fwd,
      lastError: this._dnsLastError,
      systemDnsOverride,
      manual: this._dnsManualRegistry.list(),
      loopback: this._dnsLoopbackSnapshot,
      whoisAuth: {
        listening: this._whoisAuthListening,
        ipv4: this._whoisAuthBindIpv4,
        httpPort: 80,
        lastError: this._whoisAuthLastError
      }
    }
  },
  /**
   * Re-read loopback IPv4 aliases from the OS (requires `ifconfig` or `ip` in PATH; add/remove needs root).
   * @returns {Promise<{ supported: boolean, aliases: string[], error: string | null }>}
   */
  async probeDnsLoopbackAliases () {
    const snap = await dnsLoopbackAliases.probeLoopbackAliases()
    this._dnsLoopbackSnapshot = snap
    this._emitStatus()
    return snap
  },
  /**
   * @param {{ ipv4?: string }} body — omit or empty string to auto-pick from 10.254.0.0/16
   * @returns {Promise<{ loopback: { supported: boolean, aliases: string[], error: string | null }, addedIpv4: string }>}
   */
  async addDnsLoopbackAlias (body) {
    const ipv4 = String(body && body.ipv4 != null ? body.ipv4 : '').trim()
    const addedIpv4 = await dnsLoopbackAliases.addLoopbackAlias(ipv4)
    const loopback = await this.probeDnsLoopbackAliases()
    return { loopback, addedIpv4 }
  },
  /**
   * @param {string} ipv4
   * @returns {Promise<{ supported: boolean, aliases: string[], error: string | null }>}
   */
  async removeDnsLoopbackAlias (ipv4) {
    await dnsLoopbackAliases.removeLoopbackAlias(String(ipv4 || '').trim())
    return this.probeDnsLoopbackAliases()
  },
  async _stopDnsServer () {
    if (this._systemDnsOverride) {
      const dnsOverride = require('../dns/dns-system-override')
      let restoreOpts
      if (dnsOverride.isActive()) {
        const { parseForwardTarget } = require('../dns/dns-server')
        const spec = this._dnsConfig.forwardEnabled
          ? this._dnsConfig.forwardTarget || '1.1.1.1'
          : '1.1.1.1'
        let addr = '1.1.1.1'
        try {
          addr = parseForwardTarget(spec).address
        } catch (_) {}
        restoreOpts = { dnsServers: [addr] }
      }
      dnsOverride.restore(restoreOpts)
    }
    if (!this._dnsServer) return
    const h = this._dnsServer
    this._dnsServer = null
    try {
      await h.stop()
    } catch (_) {}
    this._dnsListening = false
  },
  async _syncDnsServer () {
    await this._stopDnsServer()
    this._dnsLastError = null
    if (!this._dnsConfig.enabled) return

    const { createDnsServer, parseForwardTarget } = require('../dns/dns-server')
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
      if (this._systemDnsOverride) {
        const { apply } = require('../dns/dns-system-override')
        const r = apply({
          port: this._dnsConfig.port,
          address: this._dnsConfig.address
        })
        if (r.message) {
          const log = r.applied ? console.log : console.warn
          log('[nospoon]', r.message)
        }
      }
      const { flushSystemDnsCache } = require('../dns/dns-cache-flush')
      flushSystemDnsCache()
    } catch (e) {
      this._dnsLastError = e && e.message ? e.message : String(e)
      this._dnsServer = null
      this._dnsListening = false
      this._dnsConfig.enabled = false
    }
  },
  async _stopWhoisAuthProxy () {
    if (this._whoisAuthProxyStop) {
      try {
        await this._whoisAuthProxyStop()
      } catch (_) {}
      this._whoisAuthProxyStop = null
    }
    this._whoisAuthListening = false
    this._whoisAuthBindIpv4 = null
  },
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
    const { createWhoisAuthProxy } = require('../dns/whois-auth-proxy')
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
  },
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
  },
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
    this._emitStatus()
    return allocatedLoopbackIpv4
      ? { manual, allocatedLoopbackIpv4 }
      : { manual }
  },
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
  },
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
  },
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
}
