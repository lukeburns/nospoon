'use strict'

const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const { createTunDevice } = require('./tun')
const { encode, createDecoder, startKeepalive } = require('./framing')
const {
  createKeyAddressTable,
  stripHostFromCidr,
  wrapTunnelPayload,
  unwrapTunnelPayload,
  coerceIpv4SourceForMeshEncode
} = require('./key-address')
const {
  createRouter,
  readDestinationIp,
  tunnelSourceAllowedForPeerStream
} = require('./routing')
const { createPeerIpAllocator } = require('./ip-subnet')
const { isDirectoryFrame } = require('./hub-directory')
const { meshIdentifierStorageKey } = require('./mesh-identifier')
const { encodeZ32 } = require('./key-encoding')

/**
 * One TUN + one IPv4 pool: Hyperswarm {@link Hyperswarm#joinPeer} for direct key dials
 * (same wire as {@link createClient} / hub open mode). Uses {@link Hyperswarm#listen} so
 * peers can connect to this public key.
 *
 * @param {object} opts
 * @param {string} opts.seed — 64 hex, local Noise identity
 * @param {string} opts.ipv4 — CIDR for the shared interface (host is local TUN address)
 * @param {object} [opts.ipv6]
 * @param {number} [opts.mtu=1400]
 * @param {function(): void} [opts.onPeersChange] — called when the direct peer list or status changes (inbound dials have no per-peer hooks; use this for UI refresh)
 * @param {ReturnType<typeof createKeyAddressTable>} [opts.keyAddress] — shared id↔IP table (e.g. control plane); local + peers are registered into it; caller must not pass `localIp`/`localKey` via table ctor
 * @param {import('hyperswarm')} [opts.swarm] — shared Hyperswarm; caller owns listen/destroy and must route connections to {@link DirectPool#acceptConnection}
 * @param {{ onStreamOpen?: function(keyHex: string, conn: import('stream').Duplex): void, onStreamClose?: function(keyHex: string, conn: import('stream').Duplex): void }} [opts.policyHooks] — called for every peer stream (inbound + outbound), in addition to per-joinPeer hooks
 */
function createDirectPool (opts) {
  const onPeersChange =
    opts.onPeersChange && typeof opts.onPeersChange === 'function' ? opts.onPeersChange : null

  function notifyPeersChange () {
    if (onPeersChange) {
      try {
        onPeersChange()
      } catch (_) {}
    }
  }
  const seedHex = String(opts.seed || '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(seedHex)) {
    throw new Error('createDirectPool: seed must be 64 hex characters')
  }
  const ipv4 = opts.ipv4 != null ? String(opts.ipv4).trim() : '10.0.0.1/24'
  const mtu = opts.mtu != null ? Number(opts.mtu) : 1400
  const ipv6 = opts.ipv6

  const ownSwarm = opts.swarm == null
  let keyPair
  if (ownSwarm) {
    keyPair = HyperDHT.keyPair(Buffer.from(seedHex, 'hex'))
  } else {
    keyPair = opts.swarm.keyPair
    if (!keyPair || !keyPair.publicKey) {
      throw new Error('createDirectPool: opts.swarm must have keyPair')
    }
    const derived = HyperDHT.keyPair(Buffer.from(seedHex, 'hex'))
    if (!derived.publicKey.equals(keyPair.publicKey)) {
      throw new Error('createDirectPool: seed does not match swarm.keyPair.publicKey')
    }
  }
  const localKeyHex = keyPair.publicKey.toString('hex')
  const localMeshId = { kind: 'key', keyHex: localKeyHex }

  const swarm = ownSwarm
    ? new Hyperswarm({
        keyPair,
        maxPeers: 512
      })
    : opts.swarm

  const tun = createTunDevice({ ipv4, ipv6, mtu })
  const router = createRouter({ silent: true })
  const localTunIp = stripHostFromCidr(ipv4)
  const ka =
    opts.keyAddress != null
      ? opts.keyAddress
      : createKeyAddressTable({
          localKey: keyPair.publicKey,
          localIp: localTunIp,
          localMeshId
        })
  if (opts.keyAddress != null) {
    ka.register(localTunIp, keyPair.publicKey, localMeshId)
  }
  if (typeof ka.setMeshIpv4LiteralGuardCidr === 'function') {
    ka.setMeshIpv4LiteralGuardCidr(ipv4)
  }
  const peerIpAllocator = createPeerIpAllocator(ipv4, {
    initialUsed: new Set([localTunIp])
  })

  const routingCtx = {
    localKey: keyPair.publicKey,
    ka,
    ipToKeyHex: null
  }

  /** @type {Map<string, PeerState>} */
  const peers = new Map()

  /**
   * When set (by the control plane), IPv4/IPv6 packets from TUN whose destination is not a known
   * mesh peer IP are forwarded to this peer’s stream — same behavior as {@link createClient} for
   * full-tunnel egress. Without this, internet-bound packets are dropped because they do not
   * resolve in the key-address table.
   */
  let internetExitKeyHex = null

  function setInternetExitKeyHex (hex) {
    internetExitKeyHex =
      hex != null && String(hex).trim()
        ? String(hex).trim().toLowerCase()
        : null
  }

  function vpnDestinationRegistered (destIp) {
    if (!destIp || !ka) return false
    try {
      ka.ipToKey(destIp)
      return true
    } catch {
      return false
    }
  }

  /**
   * @typedef {object} PeerState
   * @property {string} keyHex
   * @property {string} peerIp
   * @property {import('stream').Duplex | null} connection
   * @property {boolean} leaving
   * @property {string} status
   * @property {string | null} err
   * @property {{ onStreamOpen?: function(import('stream').Duplex): void, onStreamClose?: function(import('stream').Duplex): void, onStreamError?: function(import('stream').Duplex, Error): void } | null} hooks
   */

  const localMeshIpStr = localTunIp

  tun.on('data', function (packet) {
    if (packet.length < 1) return
    const destIp = readDestinationIp(packet)
    let connection =
      destIp != null
        ? router.getConnectionForDestination(destIp, routingCtx)
        : null

    if (!connection || connection.destroyed) {
      if (internetExitKeyHex && destIp != null) {
        const isVpnIp = vpnDestinationRegistered(destIp)
        if (!isVpnIp) {
          const st = peers.get(internetExitKeyHex)
          if (st && st.connection && !st.connection.destroyed) {
            connection = st.connection
          }
        }
      }
    }

    if (!connection || connection.destroyed) return
    const ver = (packet[0] >>> 4) & 0x0f
    const p =
      ver === 4
        ? coerceIpv4SourceForMeshEncode(packet, ka, localMeshIpStr)
        : packet
    try {
      connection.write(encode(wrapTunnelPayload(ka, p)))
    } catch (_) {}
  })

  function safeRemovePeer (keyHex) {
    router.removePeer(keyHex)
  }

  /**
   * @param {import('stream').Duplex} conn
   * @param {{ primedFramedChunks?: Buffer[] }} [primeOpts] — raw stream bytes (length-prefix + payload) to feed before socket `data`
   */
  function acceptConnection (conn, primeOpts) {
    const remotePk = conn.remotePublicKey
    if (!remotePk) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }
    const rh = remotePk.toString('hex')

    let st = peers.get(rh)
    if (!st) {
      let peerIp
      try {
        peerIp = peerIpAllocator.allocate()
      } catch (_) {
        try {
          conn.destroy()
        } catch (_) {}
        return
      }
      const meshId = { kind: 'key', keyHex: rh }
      try {
        ka.register(peerIp, remotePk, meshId)
      } catch (_) {
        peerIpAllocator.release(peerIp)
        try {
          conn.destroy()
        } catch (_) {}
        return
      }
      st = {
        keyHex: rh,
        peerIp,
        connection: null,
        leaving: false,
        status: 'connecting',
        err: null,
        hooks: null
      }
      peers.set(rh, st)
      notifyPeersChange()
    }

    if (st.leaving) {
      try {
        conn.destroy()
      } catch (_) {}
      return
    }

    attachSwarmConnection(st, conn, primeOpts)
  }

  /**
   * @param {PeerState} st
   * @param {import('stream').Duplex} conn
   * @param {{ primedFramedChunks?: Buffer[] }} [primeOpts]
   */
  function attachSwarmConnection (st, conn, primeOpts) {
    const keyHex = st.keyHex

    conn.on('error', function () {})
    conn.on('error', function (err) {
      if (st.connection !== conn) return
      st.err = err && err.message ? err.message : 'error'
      st.status = 'error'
      if (st.hooks && typeof st.hooks.onStreamError === 'function') {
        try {
          st.hooks.onStreamError(conn, err instanceof Error ? err : new Error(String(err)))
        } catch (_) {}
      }
      notifyPeersChange()
    })

    conn.opened.then(function () {
      if (st.leaving || conn.destroyed) return

      st.err = null
      st.status = 'connected'
      st.connection = conn
      router.addPeer(conn.remotePublicKey, conn)

      const decode = createDecoder(function (framedPayload) {
        if (st.connection !== conn) return
        if (framedPayload.length === 0) return
        if (isDirectoryFrame(framedPayload)) return
        const packet = unwrapTunnelPayload(ka, framedPayload)
        if (!packet) return
        const destIp = readDestinationIp(packet)
        const peerConn = router.getConnectionForDestination(destIp, routingCtx)
        if (peerConn && !peerConn.destroyed) {
          if (!tunnelSourceAllowedForPeerStream(packet, st.peerIp, st.keyHex, ka)) return
          try {
            peerConn.write(encode(wrapTunnelPayload(ka, packet)))
          } catch (_) {}
        } else {
          // To local TUN (internet egress/replies): inner src is arbitrary (NAT return path).
          try {
            tun.write(packet)
          } catch (_) {}
        }
      })

      for (const chunk of primeOpts && primeOpts.primedFramedChunks ? primeOpts.primedFramedChunks : []) {
        decode(chunk)
      }

      conn.on('data', function (data) {
        if (st.connection !== conn) return
        decode(data)
      })

      conn.on('close', function () {
        if (st.connection !== conn) return
        st.connection = null
        safeRemovePeer(keyHex)
        if (st.leaving) return
        st.status = 'connecting'
        st.err = null
        if (st.hooks && typeof st.hooks.onStreamClose === 'function') {
          try {
            st.hooks.onStreamClose(conn)
          } catch (_) {}
        }
        if (opts.policyHooks && typeof opts.policyHooks.onStreamClose === 'function') {
          try {
            opts.policyHooks.onStreamClose(keyHex, conn)
          } catch (_) {}
        }
        notifyPeersChange()
      })

      startKeepalive(conn)
      if (st.hooks && typeof st.hooks.onStreamOpen === 'function') {
        try {
          st.hooks.onStreamOpen(conn)
        } catch (_) {}
      }
      if (opts.policyHooks && typeof opts.policyHooks.onStreamOpen === 'function') {
        try {
          opts.policyHooks.onStreamOpen(keyHex, conn)
        } catch (_) {}
      }
      notifyPeersChange()
    }).catch(function () {})
  }

  if (ownSwarm) {
    swarm.on('connection', acceptConnection)
    swarm.listen().catch(function (err) {
      const msg = err && err.message ? err.message : String(err)
      console.error('createDirectPool: Hyperswarm listen failed:', msg)
    })
  }

  /**
   * @param {string} keyHex — 64 lowercase hex
   * @param {{ onStreamOpen?: function(import('stream').Duplex): void, onStreamClose?: function(import('stream').Duplex): void, onStreamError?: function(import('stream').Duplex, Error): void }} [hooks]
   */
  function joinPeer (keyHex, hooks) {
    const h = String(keyHex || '').trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('joinPeer: expected 64 hex key')
    if (h === localKeyHex) throw new Error('joinPeer: cannot add self')

    if (peers.has(h)) {
      const st = peers.get(h)
      if (st.leaving) throw new Error('joinPeer: peer is being removed')
      st.hooks = hooks != null ? hooks : st.hooks
      swarm.joinPeer(Buffer.from(h, 'hex'))
      const meshId = { kind: 'key', keyHex: h }
      return {
        keyHex: h,
        peerIp: st.peerIp,
        meshIdKey: meshIdentifierStorageKey(meshId),
        keyZ32: encodeZ32(Buffer.from(h, 'hex'))
      }
    }

    let peerIp
    try {
      peerIp = peerIpAllocator.allocate()
    } catch (e) {
      throw new Error(e.message || 'no free IP in direct pool')
    }

    const remotePk = Buffer.from(h, 'hex')
    const meshId = { kind: 'key', keyHex: h }
    ka.register(peerIp, remotePk, meshId)

    const st = {
      keyHex: h,
      peerIp,
      connection: null,
      leaving: false,
      status: 'connecting',
      err: null,
      hooks: hooks || null
    }
    peers.set(h, st)
    swarm.joinPeer(remotePk)
    return {
      keyHex: h,
      peerIp,
      meshIdKey: meshIdentifierStorageKey(meshId),
      keyZ32: encodeZ32(remotePk)
    }
  }

  function leavePeer (keyHex) {
    const h = String(keyHex || '').trim().toLowerCase()
    const st = peers.get(h)
    if (!st) return
    st.leaving = true
    swarm.leavePeer(Buffer.from(h, 'hex'))
    safeRemovePeer(h)
    if (st.connection && !st.connection.destroyed) {
      try {
        st.connection.destroy()
      } catch (_) {}
    }
    ka.unregister(st.peerIp)
    peerIpAllocator.release(st.peerIp)
    peers.delete(h)
  }

  function listPeers () {
    const out = []
    for (const st of peers.values()) {
      const meshId = { kind: 'key', keyHex: st.keyHex }
      const conn = st.connection
      const raw = conn && conn.rawStream
      const remoteDialHost =
        raw && raw.remoteHost != null && String(raw.remoteHost).trim()
          ? String(raw.remoteHost).trim()
          : null
      out.push({
        keyHex: st.keyHex,
        keyZ32: encodeZ32(Buffer.from(st.keyHex, 'hex')),
        peerAliasIp: st.peerIp,
        meshIdKey: meshIdentifierStorageKey(meshId),
        status: st.status,
        err: st.err,
        remoteDialHost
      })
    }
    return out
  }

  async function shutdown () {
    internetExitKeyHex = null
    if (ownSwarm) {
      swarm.removeListener('connection', acceptConnection)
    }
    for (const h of [...peers.keys()]) {
      leavePeer(h)
    }
    if (opts.keyAddress != null) {
      try {
        ka.unregister(localTunIp)
      } catch (_) {}
    }
    try {
      tun.release()
    } catch (_) {}
    if (ownSwarm) {
      try {
        await swarm.destroy()
      } catch (_) {}
    }
  }

  return {
    tun,
    router,
    ka,
    swarm,
    keyPair,
    ipv4Cidr: ipv4,
    localTunIp,
    localMeshIdKey: meshIdentifierStorageKey(localMeshId),
    setInternetExitKeyHex,
    joinPeer,
    leavePeer,
    listPeers,
    acceptConnection,
    shutdown
  }
}

module.exports = { createDirectPool }
