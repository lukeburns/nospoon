import { useCallback, useEffect, useState } from 'react'
import z32 from 'z32'

const emptyStatus = {
  clientPublicKeyZ32: '',
  topics: [],
  directPool: null,
  directPeers: [],
  meshReservations: {
    primaryCidr: null,
    primary: [],
    topicSubnets: {},
    topics: {}
  },
  primaryCidrOverride: null,
  dns: {
    enabled: false,
    listening: false,
    port: 53,
    address: '127.0.0.1',
    forwardEnabled: true,
    forward: '1.1.1.1',
    lastError: null,
    manual: [],
    loopback: { supported: false, aliases: [], error: null }
  }
}

/** Fallback when the server omits `policy` (older builds); keeps controls on-screen. */
const DEFAULT_INTERFACE_POLICY = {
  ingress: { fullTunnel: false, relay: false },
  egress: { fullTunnel: false, relay: false }
}

function policyIn (p) {
  if (!p) return { fullTunnel: false, relay: false }
  return p.ingress || { fullTunnel: false, relay: false }
}

function policyEg (p) {
  if (!p) return { fullTunnel: false, relay: false }
  return p.egress || { fullTunnel: false, relay: false }
}

async function readJson (res) {
  const j = await res.json()
  if (!res.ok) throw new Error(j.error || String(res.status))
  return j
}

async function patchJson (url, body) {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  })
  return readJson(res)
}

async function postMeshReservation (body) {
  const res = await fetch('/api/mesh-reservations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  return readJson(res)
}

/** @param {string} sk */
function keyHexFromPrimaryMeshIdKey (sk) {
  if (typeof sk !== 'string' || !sk.startsWith('k:')) return null
  const h = sk.slice(2)
  return /^[0-9a-f]{64}$/i.test(h) ? h.toLowerCase() : null
}

/** @param {string} sk */
function keyHexFromTopicMeshIdKey (sk) {
  const m = /^kt:([0-9a-f]{64}):/i.exec(String(sk || ''))
  return m ? m[1].toLowerCase() : null
}

/** @param {string} hex */
function displayZ32FromHex64 (hex) {
  if (!hex || hex.length !== 64) return hex || '—'
  try {
    const u = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      u[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }
    return z32.encode(u)
  } catch {
    return hex.slice(0, 12) + '…'
  }
}

function afterPolicyPatch (onChanged) {
  return () => { onChanged?.() }
}

function policyOsClass (state) {
  if (state === 'ok') return 'ok'
  if (state === 'error') return 'bad'
  return 'dim'
}

/** One line of OS / debug status under a checkbox. */
function PolicyOsLine ({ line }) {
  if (!line || !line.text) return null
  return (
    <div className={'policy-os-line ' + policyOsClass(line.state)}>
      {line.text}
    </div>
  )
}

/** Topic interfaces: policy stored only; no OS hooks on topic TUN yet. */
const TOPIC_FULL_TUNNEL_OS = {
  ingress: {
    fullTunnel: { state: 'na', text: 'Stored only (no OS apply).' },
    relay: { state: 'stored', text: 'Stored only.' }
  },
  egress: {
    fullTunnel: { state: 'na', text: 'Stored only (no OS apply).' },
    relay: { state: 'stored', text: 'Stored only.' }
  }
}

function PolicyToggles ({ policy, patchUrl, onChanged, fullTunnelOs }) {
  const p = policy || DEFAULT_INTERFACE_POLICY
  const ing = policyIn(p)
  const eg = policyEg(p)
  const done = afterPolicyPatch(onChanged)
  const os = fullTunnelOs
  return (
    <div className="policy-toggles">
      <div className="policy-group">
        <div className="policy-group-head">Ingress</div>
        <div className="policy-group-rows">
          <label className="policy-toggle-row">
            <span className="policy-toggle-input">
              <input type="checkbox" checked={ing.fullTunnel} onChange={(e) => patchJson(patchUrl, { ingress: { fullTunnel: e.target.checked } }).then(done)} />
            </span>
            <span className="policy-toggle-body">
              Full tunnel
              {os ? <PolicyOsLine line={os.ingress.fullTunnel} /> : null}
            </span>
          </label>
          <label className="policy-toggle-row">
            <span className="policy-toggle-input">
              <input type="checkbox" checked={ing.relay} onChange={(e) => patchJson(patchUrl, { ingress: { relay: e.target.checked } }).then(done)} />
            </span>
            <span className="policy-toggle-body">
              Relay
              {os ? <PolicyOsLine line={os.ingress.relay} /> : null}
            </span>
          </label>
        </div>
      </div>
      <div className="policy-group">
        <div className="policy-group-head">Egress</div>
        <div className="policy-group-rows">
          <label className="policy-toggle-row">
            <span className="policy-toggle-input">
              <input type="checkbox" checked={eg.fullTunnel} onChange={(e) => patchJson(patchUrl, { egress: { fullTunnel: e.target.checked } }).then(done)} />
            </span>
            <span className="policy-toggle-body">
              Full tunnel
              {os ? <PolicyOsLine line={os.egress.fullTunnel} /> : null}
            </span>
          </label>
          <label className="policy-toggle-row">
            <span className="policy-toggle-input">
              <input type="checkbox" checked={eg.relay} onChange={(e) => patchJson(patchUrl, { egress: { relay: e.target.checked } }).then(done)} />
            </span>
            <span className="policy-toggle-body">
              Relay
              {os ? <PolicyOsLine line={os.egress.relay} /> : null}
            </span>
          </label>
        </div>
      </div>
    </div>
  )
}

/**
 * Collapsible policy block; uses <details> for a11y. Chevron rotates when open.
 * @param {'interface'|'peer'} variant
 */
function PolicyDisclosure ({ title, variant, defaultOpen = false, children }) {
  const [open, setOpen] = useState(() => Boolean(defaultOpen))
  const cls = 'policy-disclosure' + (variant === 'peer' ? ' policy-disclosure-peer' : '')
  return (
    <details
      className={cls}
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary className="policy-disclosure-summary">
        <span className="policy-disclosure-chevron" aria-hidden="true">
          ▸
        </span>
        <span className="policy-disclosure-title">{title}</span>
      </summary>
      <div className="policy-disclosure-body">{children}</div>
    </details>
  )
}

function InterfaceRoutingBlock ({ policy, apiPath, onChanged, blurb, fullTunnelOs, defaultOpen = false }) {
  return (
    <div className="policy-controls">
      <PolicyDisclosure title="Interface policy" variant="interface" defaultOpen={defaultOpen}>
        {blurb ? <p className="policy-blurb dim">{blurb}</p> : null}
        <PolicyToggles policy={policy || DEFAULT_INTERFACE_POLICY} patchUrl={apiPath} onChanged={onChanged} fullTunnelOs={fullTunnelOs} />
      </PolicyDisclosure>
    </div>
  )
}

/**
 * @param {object} props
 * @param {string} props.blurb
 * @param {boolean} props.defaultOpen
 * @param {Array<{ meshIdKey: string, ipv4: string }>} props.rows
 * @param {function(string): string|null} props.parseKeyHex
 * @param {(keyHex: string) => void} props.onConnect
 * @param {(keyHex: string) => void} props.onRelease
 * @param {(e: { preventDefault: function(), currentTarget: HTMLFormElement }) => void} props.onReserveSubmit
 * @param {boolean} props.reserveBusy
 * @param {{ kind?: string, text?: string } | null} props.reserveMsg
 * @param {string} props.reserveInputName
 */
function InterfaceReservationsBlock ({
  blurb,
  defaultOpen = false,
  rows,
  parseKeyHex,
  onConnect,
  onRelease,
  onReserveSubmit,
  reserveBusy,
  reserveMsg,
  reserveInputName = 'resKey'
}) {
  const list = rows || []
  return (
    <div className="policy-controls">
      <PolicyDisclosure title="Interface reservations" variant="interface" defaultOpen={defaultOpen}>
        {blurb ? <p className="policy-blurb dim">{blurb}</p> : null}
        <form className="reservation-form" onSubmit={onReserveSubmit}>
          <label>
            Peer public key
            <input
              name={reserveInputName}
              placeholder="z32 or 64 hex"
              required
              autoComplete="off"
              disabled={reserveBusy}
            />
          </label>
          <button type="submit" disabled={reserveBusy}>
            {reserveBusy ? 'Reserving…' : 'Reserve peer'}
          </button>
        </form>
        <FormStatus kind={reserveMsg?.kind} text={reserveMsg?.text} />
        {list.length === 0 ? (
          <p className="dim meta-tight">(no reserved peers)</p>
        ) : (
          list.map((r) => {
            const keyHex = parseKeyHex(r.meshIdKey)
            const label = keyHex ? displayZ32FromHex64(keyHex) : r.meshIdKey
            return (
              <div key={r.meshIdKey} className="row reserved-peer-row">
                <div className="peer-row-head">
                  <span>
                    <strong className="peer-key-z32">{label}</strong>
                    <span className="dim"> reserved</span>
                    {' → '}
                    <IpLink ip={r.ipv4} className="dim" />
                  </span>
                  <span className="peer-row-actions">
                    <button
                      type="button"
                      className="small"
                      disabled={!keyHex}
                      onClick={() => keyHex && onConnect(keyHex)}
                    >
                      Connect
                    </button>
                    <button
                      type="button"
                      className="small"
                      disabled={!keyHex}
                      onClick={() => keyHex && onRelease(keyHex)}
                    >
                      Release
                    </button>
                  </span>
                </div>
              </div>
            )
          })
        )}
      </PolicyDisclosure>
    </div>
  )
}

function peerPolicyUrl (apiPath, peerKeyHex, pathSuffix) {
  return `${apiPath}/${encodeURIComponent(peerKeyHex)}${pathSuffix || ''}`
}

function PeerRoutingBlock ({ peerKeyHex, policy, apiPath, pathSuffix = '', fullTunnelOs }) {
  const url = peerPolicyUrl(apiPath, peerKeyHex, pathSuffix)
  return (
    <div className="policy-controls peer-policy">
      <PolicyDisclosure title="Peer policy" variant="peer" defaultOpen={false}>
        <PolicyToggles policy={policy || DEFAULT_INTERFACE_POLICY} patchUrl={url} fullTunnelOs={fullTunnelOs} />
      </PolicyDisclosure>
    </div>
  )
}

/** IPv4 host as http://… link, styled like status (ok / bad / dim). */
function IpLink ({ ip, className = 'ok' }) {
  if (ip == null || ip === '') return '—'
  const s = String(ip).trim()
  if (!s) return '—'
  return (
    <a href={`http://${s}`} target="_blank" rel="noopener noreferrer" className={className}>
      {s}
    </a>
  )
}

/** CIDR string: link the host part, keep /prefix as plain text. */
function CidrLink ({ cidr }) {
  if (cidr == null || cidr === '') return '—'
  const s = String(cidr)
  const i = s.indexOf('/')
  if (i === -1) return <IpLink ip={s.trim()} />
  const host = s.slice(0, i).trim()
  const suffix = s.slice(i)
  if (!host) return s
  return (
    <>
      <IpLink ip={host} />
      {suffix}
    </>
  )
}

/** When mesh DNS is on, peer keys become `http://<meshDnsWireName>/` (primary = z32 key; topic = z32.topic). */
function PeerMeshKeyLink ({ z32, meshDnsWireName, dnsEnabled, strongClass }) {
  const safe =
    dnsEnabled &&
    meshDnsWireName &&
    /^[a-z0-9][a-z0-9.-]{0,251}$/i.test(String(meshDnsWireName))
  if (safe) {
    const label = strongClass ? <strong className={strongClass}>{z32}</strong> : z32
    return (
      <a href={`http://${meshDnsWireName}/`} target="_blank" rel="noopener noreferrer" className="peer-key-link">
        {label}
      </a>
    )
  }
  if (strongClass) return <strong className={strongClass}>{z32}</strong>
  return z32
}

function FormStatus ({ kind, text }) {
  if (!text) return null
  return (
    <p className={'form-status' + (kind ? ' ' + kind : '')} role="status" aria-live="polite">
      {text}
    </p>
  )
}

function TopicCard ({ topic, onLeave, reservationRows = [], dnsEnabled = false }) {
  const peers = topic.peers || []
  const topicPolicyPath = `/api/topics/${encodeURIComponent(topic.id)}/policy`
  const topicPeersPolicyBase = `/api/topics/${encodeURIComponent(topic.id)}/peers`
  const [resBusy, setResBusy] = useState(false)
  const [resMsg, setResMsg] = useState(null)

  const onTopicReserveSubmit = useCallback(
    (e) => {
      e.preventDefault()
      const form = e.currentTarget
      const key = String(new FormData(form).get('reserveKey') || '').trim()
      if (!key || resBusy) return
      setResBusy(true)
      setResMsg({ kind: 'pending', text: 'Reserving address…' })
      postMeshReservation({ op: 'reserveTopic', topicId: topic.id, key })
        .then(() => {
          form.reset()
          setResMsg({ kind: 'ok', text: 'Reserved.' })
          window.setTimeout(() => setResMsg(null), 2200)
        })
        .catch((err) => {
          setResMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(() => setResBusy(false))
    },
    [topic.id, resBusy]
  )

  const connectTopicReserved = useCallback((keyHex) => {
    fetch('/api/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: keyHex })
    })
      .then((r) => readJson(r))
      .catch((err) => {
        setResMsg({ kind: 'err', text: err.message || String(err) })
      })
  }, [])

  const releaseTopicReserved = useCallback(
    (keyHex) => {
      postMeshReservation({
        op: 'releaseTopic',
        topicId: topic.id,
        key: keyHex
      })
        .then(() => {
          setResMsg({ kind: 'ok', text: 'Released.' })
          window.setTimeout(() => setResMsg(null), 2200)
        })
        .catch((err) => {
          setResMsg({ kind: 'err', text: err.message || String(err) })
        })
    },
    [topic.id]
  )

  return (
    <div className="card interface-card">
      <div className="interface-card-head">
        <span className="interface-card-title">
          <strong>{topic.topic}</strong>
          {' · '}
          <CidrLink cidr={topic.cidr} />
        </span>
        <button type="button" className="small card-leave" onClick={() => onLeave(topic.id)}>
          Leave topic
        </button>
      </div>
      <InterfaceReservationsBlock
        blurb="Reserve the next free IPv4 in this topic subnet before a peer is on the mesh. Connect also joins the primary direct pool for that key (helps discovery paths)."
        defaultOpen={false}
        rows={reservationRows}
        parseKeyHex={keyHexFromTopicMeshIdKey}
        onConnect={connectTopicReserved}
        onRelease={releaseTopicReserved}
        onReserveSubmit={onTopicReserveSubmit}
        reserveBusy={resBusy}
        reserveMsg={resMsg}
        reserveInputName="reserveKey"
      />
      <InterfaceRoutingBlock
        policy={topic.policy}
        apiPath={topicPolicyPath}
        fullTunnelOs={TOPIC_FULL_TUNNEL_OS}
        defaultOpen={false}
      />
      {/* <div className="dim meta-tight">discovery {topic.discoveryKeyZ32}</div> */}
      {/* <div className="dim meta-tight">
        Address <IpLink ip={topic.localTunIp} /> · you {topic.publicKeyZ32}
      </div> */}
      {peers.length === 0 ? (
        <div className="dim meta-tight">(no peers yet)</div>
      ) : (
        peers.map((p) => (
          <div key={p.peerKeyHex} className="row">
            <div className="peer-row-head">
              <span>
                <PeerMeshKeyLink
                  z32={p.peerKeyZ32}
                  meshDnsWireName={p.meshDnsWireName}
                  dnsEnabled={dnsEnabled}
                />{' '}
                → <IpLink ip={p.ipv4} />
              </span>
            </div>
            <PeerRoutingBlock
              peerKeyHex={p.peerKeyHex}
              policy={p.policy}
              apiPath={topicPeersPolicyBase}
              pathSuffix="/policy"
              fullTunnelOs={TOPIC_FULL_TUNNEL_OS}
            />
          </div>
        ))
      )}
    </div>
  )
}

function PrimaryInterfaceCard ({
  directPool,
  directPeers,
  leavePeer,
  primaryReservationRows,
  onPrimaryReserveSubmit,
  primaryResBusy,
  primaryResMsg,
  onReleasePrimaryReservation,
  onConnectReservedPeer,
  dnsEnabled = false
}) {
  if (!directPool) {
    return (
      <p className="dim">
        Primary TUN is not available yet. Routing controls show up once the direct pool is initialized.
      </p>
    )
  }
  return (
    <div className="card interface-card">
      <div className="interface-card-head">
        <span className="interface-card-title">
          {/* Local address <IpLink ip={directPool.localTunIp} />
          {' · '} */}
          <CidrLink cidr={directPool.cidr} />
        </span>
      </div>
      <InterfaceReservationsBlock
        blurb="Reserve the next free IPv4 in the primary subnet before a HyperDHT stream exists. Connect opens a direct peer session using the reserved address."
        defaultOpen={false}
        rows={primaryReservationRows}
        parseKeyHex={keyHexFromPrimaryMeshIdKey}
        onConnect={onConnectReservedPeer}
        onRelease={onReleasePrimaryReservation}
        onReserveSubmit={onPrimaryReserveSubmit}
        reserveBusy={primaryResBusy}
        reserveMsg={primaryResMsg}
        reserveInputName="primaryReserveKey"
      />
      <InterfaceRoutingBlock
        policy={directPool.policy}
        apiPath="/api/policy/primary"
        fullTunnelOs={directPool.fullTunnelOsInterface}
      />
      {directPeers.length === 0 ? (
        <p className="dim meta-tight">(no peers on this interface yet)</p>
      ) : (
        directPeers.map((d) => {
          const st = d.status === 'connected' ? 'ok' : d.status === 'error' ? 'bad' : 'dim'
          return (
            <div key={d.keyHex} className="row">
              <div className="peer-row-head">
                <span>
                  <PeerMeshKeyLink
                    z32={d.keyZ32}
                    meshDnsWireName={d.meshDnsWireName}
                    dnsEnabled={dnsEnabled}
                    strongClass="peer-key-z32"
                  />
                  {' → '}
                  <IpLink ip={d.peerAliasIp} className={st} />
                  {d.err ? <span className="bad"> {d.err}</span> : null}
                </span>
                <button type="button" className="small" onClick={() => leavePeer(d.keyHex)}>
                  Leave peer
                </button>
              </div>
              <PeerRoutingBlock
                peerKeyHex={d.keyHex}
                policy={d.policy}
                apiPath="/api/policy/primary/peers"
                fullTunnelOs={d.fullTunnelOs}
              />
            </div>
          )
        })
      )}
    </div>
  )
}

function DnsInterfaceCard ({ dns, onPatchDns }) {
  const d = dns || {}
  const [portStr, setPortStr] = useState(String(d.port ?? 53))
  const [addrStr, setAddrStr] = useState(d.address || '127.0.0.1')
  const [fwdStr, setFwdStr] = useState(d.forward || '1.1.1.1')
  const [fwdEn, setFwdEn] = useState(d.forwardEnabled !== false)
  const [applyBusy, setApplyBusy] = useState(false)
  const [manualMsg, setManualMsg] = useState(null)
  const [loopbackMsg, setLoopbackMsg] = useState(null)
  const [loopbackRefreshBusy, setLoopbackRefreshBusy] = useState(false)
  const [loopbackAddBusy, setLoopbackAddBusy] = useState(false)

  const lb = d.loopback || { supported: false, aliases: [], error: null }

  useEffect(
    function () {
      if (!dns) return
      setPortStr(String(dns.port ?? 53))
      setAddrStr(dns.address || '127.0.0.1')
      setFwdStr(dns.forward || '1.1.1.1')
      setFwdEn(dns.forwardEnabled !== false)
    },
    [dns, dns?.port, dns?.address, dns?.forward, dns?.forwardEnabled]
  )

  const toggleEnabled = useCallback(
    function (checked) {
      onPatchDns({ enabled: checked }).catch(function (err) {
        setManualMsg({ kind: 'err', text: err.message || String(err) })
      })
    },
    [onPatchDns]
  )

  const applySettings = useCallback(
    function (e) {
      e.preventDefault()
      const p = parseInt(portStr, 10)
      if (Number.isNaN(p) || p < 1 || p > 65535) {
        setManualMsg({ kind: 'err', text: 'Port must be 1–65535' })
        return
      }
      setApplyBusy(true)
      setManualMsg(null)
      onPatchDns({
        port: p,
        address: addrStr.trim(),
        forwardEnabled: fwdEn,
        forward: fwdEn ? fwdStr.trim() : null
      })
        .then(function () {
          setManualMsg({ kind: 'ok', text: 'DNS settings applied.' })
          window.setTimeout(function () {
            setManualMsg(null)
          }, 2200)
        })
        .catch(function (err) {
          setManualMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(function () {
          setApplyBusy(false)
        })
    },
    [onPatchDns, portStr, addrStr, fwdEn, fwdStr]
  )

  const onManualSubmit = useCallback(
    function (e) {
      e.preventDefault()
      const form = e.currentTarget
      const fd = new FormData(form)
      const hostname = String(fd.get('dnsHost') || '').trim()
      const ipv4 = String(fd.get('dnsIpv4') || '').trim()
      const ipv6 = String(fd.get('dnsIpv6') || '').trim()
      if (!hostname) return
      fetch('/api/dns/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname,
          ipv4: ipv4 || undefined,
          ipv6: ipv6 || undefined
        })
      })
        .then(function (r) {
          return readJson(r)
        })
        .then(function (j) {
          form.reset()
          const alloc = j && j.allocatedLoopbackIpv4 ? String(j.allocatedLoopbackIpv4) : ''
          setManualMsg({
            kind: 'ok',
            text: alloc
              ? `Manual record added (loopback ${alloc}).`
              : 'Manual record added.'
          })
          window.setTimeout(function () {
            setManualMsg(null)
          }, 2200)
        })
        .catch(function (err) {
          setManualMsg({ kind: 'err', text: err.message || String(err) })
        })
    },
    []
  )

  const deleteManual = useCallback(function (hostname) {
    fetch('/api/dns/manual/' + encodeURIComponent(hostname), { method: 'DELETE' })
      .then(function (r) {
        return readJson(r)
      })
      .catch(function (err) {
        setManualMsg({ kind: 'err', text: err.message || String(err) })
      })
  }, [])

  const refreshLoopback = useCallback(function () {
    setLoopbackRefreshBusy(true)
    setLoopbackMsg(null)
    fetch('/api/dns/loopback')
      .then(function (r) {
        return readJson(r)
      })
      .then(function () {
        setLoopbackMsg({ kind: 'ok', text: 'Loopback list refreshed.' })
        window.setTimeout(function () {
          setLoopbackMsg(null)
        }, 1800)
      })
      .catch(function (err) {
        setLoopbackMsg({ kind: 'err', text: err.message || String(err) })
      })
      .finally(function () {
        setLoopbackRefreshBusy(false)
      })
  }, [])

  const onLoopbackAdd = useCallback(function (e) {
    e.preventDefault()
    const form = e.currentTarget
    const fd = new FormData(form)
    const ipv4 = String(fd.get('loopIpv4') || '').trim()
    setLoopbackAddBusy(true)
    setLoopbackMsg(null)
    fetch('/api/dns/loopback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ipv4 ? { ipv4 } : {})
    })
      .then(function (r) {
        return readJson(r)
      })
      .then(function (j) {
        form.reset()
        const added = j && j.addedIpv4 ? String(j.addedIpv4) : ''
        setLoopbackMsg({
          kind: 'ok',
          text: added ? `Loopback alias added (${added}).` : 'Loopback alias added.'
        })
        window.setTimeout(function () {
          setLoopbackMsg(null)
        }, 2200)
      })
      .catch(function (err) {
        setLoopbackMsg({ kind: 'err', text: err.message || String(err) })
      })
      .finally(function () {
        setLoopbackAddBusy(false)
      })
  }, [])

  const removeLoopback = useCallback(function (ip) {
    setLoopbackMsg(null)
    fetch('/api/dns/loopback/' + encodeURIComponent(ip), { method: 'DELETE' })
      .then(function (r) {
        return readJson(r)
      })
      .catch(function (err) {
        setLoopbackMsg({ kind: 'err', text: err.message || String(err) })
      })
  }, [])

  const manual = d.manual || []

  return (
    <div className="card interface-card dns-interface-card">
      <div className="interface-card-head">
        <span className="interface-card-title">
          <strong>DNS</strong>
          {' · '}
          <span className="dim">
            {d.listening
              ? `listening ${d.address}:${d.port}`
              : d.enabled
                ? 'enabled (not bound — see error)'
                : 'off'}
          </span>
        </span>
      </div>
      <div className="policy-controls">
        <PolicyDisclosure title="DNS interface" variant="interface" defaultOpen={false}>
          <p className="policy-blurb dim">
            UDP DNS for this control plane: <strong>z32(key)</strong> and{' '}
            <strong>z32(key).topicRef</strong> (topic UUID or topic name) resolve to mesh IPv4 using
            the same reservations and tunnels as the web UI. Other names use the manual table or
            upstream forwarding.
          </p>
          {d.lastError ? (
            <p className="form-status err" role="alert">
              {d.lastError}
            </p>
          ) : null}
          <label className="policy-toggle-row dns-toggle-spaced">
            <span className="policy-toggle-input">
              <input
                type="checkbox"
                checked={Boolean(d.enabled)}
                onChange={function (e) {
                  toggleEnabled(e.target.checked)
                }}
              />
            </span>
            <span className="policy-toggle-body">DNS server enabled</span>
          </label>
          <form className="dns-settings-form" onSubmit={applySettings}>
            <label>
              Bind address
              <input
                value={addrStr}
                onChange={function (e) {
                  setAddrStr(e.target.value)
                }}
                autoComplete="off"
                disabled={applyBusy}
              />
            </label>
            <label>
              Port
              <input
                value={portStr}
                onChange={function (e) {
                  setPortStr(e.target.value)
                }}
                autoComplete="off"
                disabled={applyBusy}
              />
            </label>
            <label className="dns-forward-check">
              <input
                type="checkbox"
                checked={fwdEn}
                onChange={function (e) {
                  setFwdEn(e.target.checked)
                }}
                disabled={applyBusy}
              />{' '}
              Forward other queries upstream
            </label>
            <label>
              Upstream
              <input
                value={fwdStr}
                onChange={function (e) {
                  setFwdStr(e.target.value)
                }}
                placeholder="1.1.1.1"
                autoComplete="off"
                disabled={applyBusy || !fwdEn}
              />
            </label>
            <button type="submit" disabled={applyBusy}>
              {applyBusy ? 'Applying…' : 'Apply bind / forward'}
            </button>
          </form>
          <FormStatus kind={manualMsg?.kind} text={manualMsg?.text} />
          <div className="dns-loopback-section">
            <p className="policy-group-head">Loopback reservation</p>
            <p className="policy-blurb dim meta-tight">
              Add another IPv4 on loopback so you can bind a service (e.g. HTTP on port 80) on that
              address without using <code>127.0.0.1</code>. Add a manual hostname below pointing at
              the same IP so this DNS server answers for it.
            </p>
            {!lb.supported ? (
              <p className="dim meta-tight">Loopback alias control is only available on macOS and Linux.</p>
            ) : (
              <>
                {lb.error ? (
                  <p className="form-status err" role="alert">
                    {lb.error}
                  </p>
                ) : null}
                <div className="dns-loopback-toolbar">
                  <button
                    type="button"
                    className="small"
                    disabled={loopbackRefreshBusy}
                    onClick={refreshLoopback}
                  >
                    {loopbackRefreshBusy ? 'Refreshing…' : 'Refresh list'}
                  </button>
                </div>
                <FormStatus kind={loopbackMsg?.kind} text={loopbackMsg?.text} />
                <form className="dns-loopback-form" onSubmit={onLoopbackAdd}>
                  <label>
                    IPv4 (optional)
                    <input
                      name="loopIpv4"
                      placeholder="auto from 10.254.0.0/16"
                      autoComplete="off"
                      disabled={loopbackAddBusy}
                    />
                  </label>
                  <button type="submit" disabled={loopbackAddBusy}>
                    {loopbackAddBusy ? 'Adding…' : 'Add alias'}
                  </button>
                </form>
                {lb.aliases.length === 0 ? (
                  <p className="dim meta-tight">(no extra loopback IPv4)</p>
                ) : (
                  lb.aliases.map(function (ip) {
                    return (
                      <div key={ip} className="row dns-loopback-row">
                        <div className="peer-row-head">
                          <span>
                            <IpLink ip={ip} />
                          </span>
                          <button
                            type="button"
                            className="small"
                            onClick={function () {
                              removeLoopback(ip)
                            }}
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    )
                  })
                )}
                <p className="dim meta-tight dns-loopback-foot">
                  Leave IPv4 empty to pick the first unused address in <code>10.254.0.0/16</code>{' '}
                  (skips addresses in use on any interface). Otherwise use private IPv4 or{' '}
                  <code>127.0.0.0/8</code> except <code>127.0.0.1</code>. Runs <code>ifconfig</code>{' '}
                  (macOS) or <code>ip</code> (Linux); typically requires root.
                </p>
              </>
            )}
          </div>
          <p className="policy-group-head dns-manual-head">Manual hostnames</p>
          <p className="policy-blurb dim meta-tight">
            With no IPv4 and no IPv6, a loopback alias is allocated (same rules as above) and used
            as the A record.
          </p>
          <form className="dns-manual-form" onSubmit={onManualSubmit}>
            <label>
              Hostname
              <input name="dnsHost" placeholder="app.lan" required autoComplete="off" />
            </label>
            <label>
              IPv4
              <input name="dnsIpv4" placeholder="optional" autoComplete="off" />
            </label>
            <label>
              IPv6
              <input name="dnsIpv6" placeholder="optional" autoComplete="off" />
            </label>
            <button type="submit">Add</button>
          </form>
          {manual.length === 0 ? (
            <p className="dim meta-tight">(no manual records)</p>
          ) : (
            manual.map(function (row) {
              return (
                <div key={row.hostname} className="row dns-manual-row">
                  <div className="peer-row-head">
                    <span>
                      <strong>{row.hostname}</strong>
                      {row.ipv4 ? (
                        <>
                          {' → '}
                          <IpLink ip={row.ipv4} />
                        </>
                      ) : null}
                      {row.ipv6 ? (
                        <>
                          {' · '}
                          <span className="dim">{row.ipv6}</span>
                        </>
                      ) : null}
                    </span>
                    <button
                      type="button"
                      className="small"
                      onClick={function () {
                        deleteManual(row.hostname)
                      }}
                    >
                      Remove
                    </button>
                  </div>
                </div>
              )
            })
          )}
        </PolicyDisclosure>
      </div>
    </div>
  )
}

export default function App () {
  const [status, setStatus] = useState(null)
  const [sseState, setSseState] = useState('connecting')
  const [topicBusy, setTopicBusy] = useState(false)
  const [topicMsg, setTopicMsg] = useState(null)
  const [peerBusy, setPeerBusy] = useState(false)
  const [peerMsg, setPeerMsg] = useState(null)
  const [primaryResBusy, setPrimaryResBusy] = useState(false)
  const [primaryResMsg, setPrimaryResMsg] = useState(null)

  useEffect(() => {
    fetch('/api/status')
      .then((r) => r.json())
      .then(setStatus)
      .catch(() => setStatus(emptyStatus))

    const es = new EventSource('/api/events')
    es.onopen = () => setSseState('open')
    es.onmessage = (ev) => {
      try {
        setStatus(JSON.parse(ev.data))
      } catch (_) {}
    }
    es.onerror = () => setSseState('error')
    return () => es.close()
  }, [])

  const leaveTopic = useCallback((id) => {
    fetch('/api/topics/' + encodeURIComponent(id), { method: 'DELETE' }).catch(() => {})
  }, [])

  const leavePeer = useCallback((keyHex) => {
    fetch('/api/peers/' + keyHex, { method: 'DELETE' }).catch(() => {})
  }, [])

  const onPrimaryReserveSubmit = useCallback(
    (e) => {
      e.preventDefault()
      const form = e.currentTarget
      const key = String(new FormData(form).get('primaryReserveKey') || '').trim()
      if (!key || primaryResBusy) return
      setPrimaryResBusy(true)
      setPrimaryResMsg({ kind: 'pending', text: 'Reserving address…' })
      postMeshReservation({ op: 'reservePrimary', key })
        .then(() => {
          form.reset()
          setPrimaryResMsg({ kind: 'ok', text: 'Reserved.' })
          window.setTimeout(() => setPrimaryResMsg(null), 2200)
        })
        .catch((err) => {
          setPrimaryResMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(() => setPrimaryResBusy(false))
    },
    [primaryResBusy]
  )

  const onReleasePrimaryReservation = useCallback((keyHex) => {
    postMeshReservation({ op: 'releasePrimary', key: keyHex })
      .then(() => {
        setPrimaryResMsg({ kind: 'ok', text: 'Released.' })
        window.setTimeout(() => setPrimaryResMsg(null), 2200)
      })
      .catch((err) => {
        setPrimaryResMsg({ kind: 'err', text: err.message || String(err) })
      })
  }, [])

  const onConnectReservedPeer = useCallback((keyHex) => {
    fetch('/api/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: keyHex })
    })
      .then((r) => readJson(r))
      .then(() => {
        setPrimaryResMsg({ kind: 'ok', text: 'Connect started.' })
        window.setTimeout(() => setPrimaryResMsg(null), 2200)
      })
      .catch((err) => {
        setPrimaryResMsg({ kind: 'err', text: err.message || String(err) })
      })
  }, [])

  const onTopicSubmit = useCallback((e) => {
    e.preventDefault()
    const form = e.currentTarget
    const topic = String(form.topic.value || '').trim()
    if (!topic || topicBusy) return
    setTopicBusy(true)
    setTopicMsg({ kind: 'pending', text: `Setting up TUN and swarm for "${topic}"…` })
    fetch('/api/topics', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ topic: form.topic.value, ip: undefined })
    })
      .then((r) => readJson(r))
      .then(() => {
        form.reset()
        setTopicMsg({ kind: 'ok', text: 'Joined.' })
        window.setTimeout(() => setTopicMsg(null), 2500)
      })
      .catch((err) => {
        setTopicMsg({ kind: 'err', text: err.message || String(err) })
      })
      .finally(() => setTopicBusy(false))
  }, [topicBusy])

  const onPeerSubmit = useCallback((e) => {
    e.preventDefault()
    const form = e.currentTarget
    if (peerBusy) return
    setPeerBusy(true)
    setPeerMsg({ kind: 'pending', text: 'Opening HyperDHT stream to peer…' })
    fetch('/api/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: form.key.value })
    })
      .then((r) => readJson(r))
      .then(() => {
        form.reset()
        setPeerMsg({ kind: 'ok', text: 'Peer added.' })
        window.setTimeout(() => setPeerMsg(null), 2500)
      })
      .catch((err) => {
        setPeerMsg({ kind: 'err', text: err.message || String(err) })
      })
      .finally(() => setPeerBusy(false))
  }, [peerBusy])

  const patchDns = useCallback(function (body) {
    return fetch('/api/dns', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return readJson(r)
    })
  }, [])

  const s = status || emptyStatus
  const topics = s.topics || []
  const directPeers = s.directPeers || []
  const meshRes = s.meshReservations || emptyStatus.meshReservations
  const topicReservationMap = meshRes.topics || {}
  const dns = s.dns || emptyStatus.dns

  return (
    <>
      <h1>nospoon control</h1>
      {/* <p className="meta">HTTP API + live status (SSE). Bind defaults to loopback — expose with care.</p> */}
      <p className="meta" id="live-line" aria-live="polite">
        <span className={'sse-dot ' + (sseState === 'open' ? 'on' : 'off')} />
        <span>
          {sseState === 'open' ? 'Connected' : sseState === 'connecting' ? 'Live updates: connecting…' : 'Reconnecting…'}
        </span>
      </p>
      <p className="meta">Public key: {s.clientPublicKeyZ32 || '—'}</p>

      <h2>Primary interface</h2>
      <form onSubmit={onPeerSubmit}>
        <label>
          Peer public key
          <input name="key" placeholder="Public key" required autoComplete="off" disabled={peerBusy} />
        </label>
        <button type="submit" disabled={peerBusy}>
          {peerBusy ? 'Joining…' : 'Join peer'}
        </button>
      </form>
      <FormStatus kind={peerMsg?.kind} text={peerMsg?.text} />
      <PrimaryInterfaceCard
        directPool={s.directPool}
        directPeers={directPeers}
        leavePeer={leavePeer}
        primaryReservationRows={meshRes.primary || []}
        onPrimaryReserveSubmit={onPrimaryReserveSubmit}
        primaryResBusy={primaryResBusy}
        primaryResMsg={primaryResMsg}
        onReleasePrimaryReservation={onReleasePrimaryReservation}
        onConnectReservedPeer={onConnectReservedPeer}
        dnsEnabled={Boolean(dns.enabled)}
      />

      <h2>DNS interface</h2>
      <DnsInterfaceCard dns={dns} onPatchDns={patchDns} />

      <h2>Topic interfaces</h2>
      <form onSubmit={onTopicSubmit}>
        <label>
          Topic
          <input name="topic" placeholder="Secret topic name" required autoComplete="off" disabled={topicBusy} />
        </label>
        <button type="submit" disabled={topicBusy}>
          {topicBusy ? 'Joining…' : 'Join topic'}
        </button>
      </form>
      <FormStatus kind={topicMsg?.kind} text={topicMsg?.text} />
      {topics.length === 0 ? (
        <p className="dim">(no topic interfaces yet)</p>
      ) : (
        topics.map((t) => (
          <TopicCard
            key={t.id}
            topic={t}
            onLeave={leaveTopic}
            reservationRows={topicReservationMap[t.id] || []}
            dnsEnabled={Boolean(dns.enabled)}
          />
        ))
      )}
    </>
  )
}
