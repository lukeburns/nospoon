'use strict'

const dgram = require('dgram')
const net = require('net')
const dnsPacket = require('dns-packet')
const { normalizeFqdn, parseMeshDnsName } = require('./dns-mesh-name')
const { parseIpfsCidHostname } = require('./ipfs-cid-dns')

const TTL = 60
const FORWARD_TIMEOUT_MS = 8000

/**
 * @param {{ type?: string|number }} q
 * @returns {'A'|'AAAA'|string}
 */
function qtypeNorm (q) {
  const t = q.type
  if (t === 1 || t === 'A') return 'A'
  if (t === 28 || t === 'AAAA') return 'AAAA'
  return String(t == null ? '' : t).toUpperCase()
}

/**
 * @param {string} str
 * @returns {{ address: string, port: number }}
 */
function parseForwardTarget (str) {
  const trimmed = String(str).trim()
  if (!trimmed) throw new Error('empty forward target')

  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']')
    if (end === -1) throw new Error('invalid IPv6 in forward target')
    const addr = trimmed.slice(1, end)
    const rest = trimmed.slice(end + 1)
    if (!net.isIPv6(addr)) throw new Error('invalid IPv6 in forward target')
    let port = 53
    if (rest.startsWith(':')) {
      port = parseInt(rest.slice(1), 10)
      if (Number.isNaN(port) || port < 1 || port > 65535) {
        throw new Error('invalid port in forward target')
      }
    }
    return { address: addr, port }
  }

  const lastColon = trimmed.lastIndexOf(':')
  if (lastColon > 0 && net.isIPv4(trimmed.slice(0, lastColon))) {
    const host = trimmed.slice(0, lastColon)
    const p = parseInt(trimmed.slice(lastColon + 1), 10)
    if (Number.isNaN(p) || p < 1 || p > 65535) {
      throw new Error('invalid port in forward target')
    }
    return { address: host, port: p }
  }

  if (net.isIPv4(trimmed)) return { address: trimmed, port: 53 }
  if (net.isIPv6(trimmed)) return { address: trimmed, port: 53 }

  throw new Error('forward target must be an IPv4 or IPv6 address (optional :port)')
}

/**
 * @param {object} opts
 * @param {function(string): { ipv4?: string, ipv6?: string } | null} opts.lookupManual — normalized FQDN; for a given name, manual A/AAAA wins over mesh when both exist
 * @param {function({ kind: 'key', keyHex: string } | { kind: 'keyTopic', keyHex: string, topicRef: string }): string | null} [opts.resolveMeshA] — returns IPv4 string or null (used when manual has no matching RR for that qtype)
 * @param {function(string): string | null} [opts.resolveCidGatewayA] — normalized FQDN; if name is a CID hostname and service is up, return gateway IPv4
 * @param {number} [opts.port=53]
 * @param {string} [opts.address='0.0.0.0']
 * @param {false|null|{ address: string, port: number }} [opts.forward] — default Cloudflare; null/false disables
 * @param {function(Error): void} [opts.onError]
 */
function createDnsServer (opts) {
  const lookupManual = opts.lookupManual
  if (typeof lookupManual !== 'function') {
    throw new Error('createDnsServer: lookupManual is required')
  }
  const resolveMeshA = opts.resolveMeshA
  const resolveCidGatewayA = opts.resolveCidGatewayA

  const port = opts.port != null ? Number(opts.port) : 53
  const address = opts.address || '0.0.0.0'

  let forwardTarget = null
  if (opts.forward === false || opts.forward === null) {
    forwardTarget = null
  } else if (opts.forward && typeof opts.forward === 'object' && opts.forward.address) {
    forwardTarget = {
      address: opts.forward.address,
      port: opts.forward.port != null ? Number(opts.forward.port) : 53
    }
  } else {
    forwardTarget = { address: '1.1.1.1', port: 53 }
  }

  /** @type {import('dgram').Socket | null} */
  let socket = null
  /** @type {import('dgram').Socket | null} */
  let forwardSocket = null

  /** @type {Map<number, { port: number, address: string, timer: NodeJS.Timeout }>} */
  const pending = new Map()

  function clearPending (id) {
    const p = pending.get(id)
    if (p) {
      clearTimeout(p.timer)
      pending.delete(id)
    }
  }

  function forwardToUpstream (msg, rinfo) {
    if (!forwardSocket || !forwardTarget) return false

    let query
    try {
      query = dnsPacket.decode(msg)
    } catch {
      return false
    }
    const id = query.id

    clearPending(id)

    const timer = setTimeout(function () {
      clearPending(id)
    }, FORWARD_TIMEOUT_MS)

    pending.set(id, { port: rinfo.port, address: rinfo.address, timer })

    forwardSocket.send(msg, forwardTarget.port, forwardTarget.address, function (err) {
      if (err) {
        clearPending(id)
        if (opts.onError) opts.onError(err)
      }
    })
    return true
  }

  function onUpstreamMessage (msg) {
    if (!socket) return
    let decoded
    try {
      decoded = dnsPacket.decode(msg)
    } catch {
      return
    }
    const id = decoded.id
    const p = pending.get(id)
    if (!p) return
    clearTimeout(p.timer)
    pending.delete(id)
    socket.send(msg, p.port, p.address, function (err) {
      if (err && opts.onError) opts.onError(err)
    })
  }

  function onMessage (msg, rinfo) {
    let query
    try {
      query = dnsPacket.decode(msg)
    } catch {
      return
    }
    if (query.type !== 'query' || !query.questions || query.questions.length === 0) {
      return
    }

    const q = query.questions[0]
    const name = normalizeFqdn(q.name)
    const qtype = qtypeNorm(q)

    let meshIpv4 = null
    let isMeshQuery = false
    if (typeof resolveMeshA === 'function' && qtype === 'A') {
      const meshId = parseMeshDnsName(name)
      if (meshId) {
        isMeshQuery = true
        try {
          meshIpv4 = resolveMeshA(meshId)
        } catch (e) {
          if (opts.onError) opts.onError(e instanceof Error ? e : new Error(String(e)))
          meshIpv4 = null
        }
      }
    }

    let cidIpv4 = null
    let isCidQuery = false
    if (typeof resolveCidGatewayA === 'function' && qtype === 'A') {
      if (parseIpfsCidHostname(name)) {
        isCidQuery = true
        try {
          cidIpv4 = resolveCidGatewayA(name)
        } catch (e) {
          if (opts.onError) opts.onError(e instanceof Error ? e : new Error(String(e)))
          cidIpv4 = null
        }
      }
    }

    const rec = lookupManual(name)

    if (
      qtype === 'AAAA' &&
      parseIpfsCidHostname(name) &&
      !(rec && rec.ipv6)
    ) {
      sendNoErrorEmptyAnswers()
      return
    }

    const hasMeshA = Boolean(meshIpv4)
    const hasCidA = Boolean(cidIpv4)
    const hasLocalA = qtype === 'A' && rec && rec.ipv4
    const hasLocalAAAA = qtype === 'AAAA' && rec && rec.ipv6

    function sendNoErrorEmptyAnswers () {
      const flags = dnsPacket.RECURSION_AVAILABLE
      const response = dnsPacket.encode({
        type: 'response',
        id: query.id,
        flags,
        questions: query.questions,
        answers: []
      })
      socket.send(response, rinfo.port, rinfo.address, function (err) {
        if (err && opts.onError) opts.onError(err)
      })
    }

    // Manual name exists but this qtype has no RR: NODATA (NOERROR + empty), not NXDOMAIN.
    if (rec && rec.ipv4 && !rec.ipv6 && qtype === 'AAAA') {
      sendNoErrorEmptyAnswers()
      return
    }
    if (rec && rec.ipv6 && !rec.ipv4 && qtype === 'A') {
      sendNoErrorEmptyAnswers()
      return
    }

    if (!hasMeshA && !hasLocalA && !hasLocalAAAA && !hasCidA) {
      if (isMeshQuery && !meshIpv4) {
        const flags = dnsPacket.RECURSION_AVAILABLE | (3 & 0xf)
        const response = dnsPacket.encode({
          type: 'response',
          id: query.id,
          flags,
          questions: query.questions,
          answers: []
        })
        socket.send(response, rinfo.port, rinfo.address, function (err) {
          if (err && opts.onError) opts.onError(err)
        })
        return
      }
      if (isCidQuery && !cidIpv4) {
        const flags = dnsPacket.RECURSION_AVAILABLE | (3 & 0xf)
        const response = dnsPacket.encode({
          type: 'response',
          id: query.id,
          flags,
          questions: query.questions,
          answers: []
        })
        socket.send(response, rinfo.port, rinfo.address, function (err) {
          if (err && opts.onError) opts.onError(err)
        })
        return
      }
      if (forwardTarget && forwardSocket) {
        forwardToUpstream(msg, rinfo)
      } else {
        let rcode = 3
        if (qtype !== 'A' && qtype !== 'AAAA') rcode = 4
        const flags = dnsPacket.RECURSION_AVAILABLE | (rcode & 0xf)
        const response = dnsPacket.encode({
          type: 'response',
          id: query.id,
          flags,
          questions: query.questions,
          answers: []
        })
        socket.send(response, rinfo.port, rinfo.address, function (err) {
          if (err && opts.onError) opts.onError(err)
        })
      }
      return
    }

    const answers = []
    if (hasLocalA) {
      answers.push({
        type: 'A',
        name: q.name,
        ttl: TTL,
        data: rec.ipv4
      })
    } else if (hasMeshA) {
      answers.push({
        type: 'A',
        name: q.name,
        ttl: TTL,
        data: meshIpv4
      })
    } else if (hasCidA) {
      answers.push({
        type: 'A',
        name: q.name,
        ttl: TTL,
        data: cidIpv4
      })
    } else {
      answers.push({
        type: 'AAAA',
        name: q.name,
        ttl: TTL,
        data: rec.ipv6
      })
    }

    const flags = dnsPacket.RECURSION_AVAILABLE

    const response = dnsPacket.encode({
      type: 'response',
      id: query.id,
      flags,
      questions: query.questions,
      answers
    })

    socket.send(response, rinfo.port, rinfo.address, function (err) {
      if (err && opts.onError) opts.onError(err)
    })
  }

  function start () {
    return new Promise(function (resolve, reject) {
      if (socket) {
        resolve({ port, address, forward: forwardTarget })
        return
      }
      const socketType = net.isIPv6(address) ? 'udp6' : 'udp4'
      const s = dgram.createSocket(socketType)
      s.on('message', onMessage)

      if (forwardTarget) {
        const fsType = net.isIPv6(forwardTarget.address) ? 'udp6' : 'udp4'
        forwardSocket = dgram.createSocket(fsType)
        forwardSocket.on('message', onUpstreamMessage)
        forwardSocket.on('error', function (err) {
          if (opts.onError) opts.onError(err)
        })
      }

      function onBindError (err) {
        s.removeListener('error', onBindError)
        try {
          s.close()
        } catch (_) {}
        if (forwardSocket) {
          try {
            forwardSocket.close()
          } catch (_) {}
          forwardSocket = null
        }
        if (err.code === 'EADDRINUSE') {
          reject(
            new Error(
              `bind EADDRINUSE ${address}:${port} — pick another port in the control UI or CLI.`
            )
          )
        } else {
          reject(err)
        }
      }

      function bindForwardThenListen () {
        if (!forwardTarget || !forwardSocket) {
          doListen()
          return
        }
        function onFwdBindErr (err) {
          forwardSocket.removeListener('error', onFwdBindErr)
          try {
            s.close()
          } catch (_) {}
          reject(err)
        }
        forwardSocket.once('error', onFwdBindErr)
        forwardSocket.bind(0, function () {
          forwardSocket.removeListener('error', onFwdBindErr)
          doListen()
        })
      }

      function doListen () {
        s.once('error', onBindError)
        s.bind(port, address, function () {
          s.removeListener('error', onBindError)
          s.on('error', function (err) {
            if (opts.onError) opts.onError(err)
          })
          socket = s
          try {
            const a = s.address()
            resolve({ port: a.port, address: a.address, forward: forwardTarget })
          } catch (e) {
            reject(e)
          }
        })
      }

      bindForwardThenListen()
    })
  }

  function stop () {
    return new Promise(function (resolve) {
      for (const [, p] of pending) clearTimeout(p.timer)
      pending.clear()

      if (forwardSocket) {
        try {
          forwardSocket.close()
        } catch (_) {}
        forwardSocket = null
      }

      if (!socket) {
        resolve()
        return
      }
      const s = socket
      socket = null
      try {
        s.close(function () {
          resolve()
        })
      } catch {
        resolve()
      }
    })
  }

  return { start, stop, get port () { return port }, get address () { return address } }
}

module.exports = {
  createDnsServer,
  parseForwardTarget,
  normalizeFqdn,
  parseMeshDnsName
}
