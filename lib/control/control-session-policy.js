'use strict'

const rp = require('../route/routing-policy')
const {
  enableServerForwarding,
  disableServerForwarding,
  enableClientFullTunnel,
  addHostExemption,
  disableClientFullTunnel
} = require('../tun/full-tunnel')
const { natSourceCidrFromDirectPool } = require('./control-helpers')

module.exports = {

  _resolvePrimaryPeerPolicy (keyHex) {
    const h = String(keyHex || '').trim().toLowerCase()
    return rp.resolvePeerPolicy(this._primaryPolicy, this._primaryPeerPolicies.get(h))
  },
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
  },
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
  },
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
  },
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
  },
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
  },
  _relayStoredHint () {
    return {
      state: 'stored',
      text: 'Not wired on the network yet (flag stored only).'
    }
  },
  _ftOsLine (state, text) {
    return { state, text }
  },
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
  },
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
  },
  setPrimaryPolicy (body) {
    this._primaryPolicy = rp.applyPolicyUpdate(this._primaryPolicy, body)
    this._syncPrimaryFullTunnelPolicy()
    this._emitStatus()
    return rp.clonePolicy(this._primaryPolicy)
  },
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
  },
  setTopicInterfacePolicy (topicId, body) {
    const row = this._topics.get(String(topicId))
    if (!row) throw new Error('topic session not found')
    row._ifacePolicy = rp.applyPolicyUpdate(row._ifacePolicy, body)
    this._emitStatus()
    return rp.clonePolicy(row._ifacePolicy)
  },
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
  },
  _topicPeerSnapshotPolicy (row, peerKeyHex) {
    const h = String(peerKeyHex).toLowerCase()
    return {
      policy: rp.resolvePeerPolicy(row._ifacePolicy, row._peerPolicies.get(h)),
      policyPatch: row._peerPolicies.has(h) ? row._peerPolicies.get(h) : null
    }
  }
}
