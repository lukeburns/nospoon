import { useCallback, useEffect, useRef, useState } from 'react'
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
    enabled: true,
    listening: false,
    port: 53,
    address: '127.0.0.1',
    forwardEnabled: true,
    forward: '1.1.1.1',
    lastError: null,
    manual: [],
    loopback: { supported: false, aliases: [], error: null },
    whoisAuth: {
      listening: false,
      ipv4: null,
      httpPort: 80,
      lastError: null
    },
    ipfsDweb: {
      enabled: true,
      mode: 'helia',
      dataDir: '',
      externalGatewayUrl: 'http://127.0.0.1:8080',
      listening: false,
      ipv4: null,
      httpPort: 80,
      lastError: null,
      canUpload: false
    }
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

/** http://(cid)/ for the DNS dweb gateway. Avoid new URL / hostname setter — it lowercases hosts and breaks case-sensitive base58 CIDs (Qm…). */
function cidToDwebHttpHref (cid) {
  const c = String(cid || '').trim()
  if (!c) return '#'
  return encodeURI('http://' + c + '/')
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

/**
 * @param {{ ipfs: object, dnsEnabled: boolean, dnsListening: boolean, onApplied?: function(object): void }} props
 */
function IpfsGatewayCard ({ ipfs, dnsEnabled, dnsListening, onApplied }) {
  const i = ipfs || emptyStatus.dns.ipfsDweb
  const uploadInputRef = useRef(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null)
  const [uploadBusy, setUploadBusy] = useState(false)
  const [seeds, setSeeds] = useState([])
  const [seedsLoading, setSeedsLoading] = useState(false)
  const [seedsErr, setSeedsErr] = useState(null)
  const [unseedingCid, setUnseedingCid] = useState(null)
  const [en, setEn] = useState(true)
  const [mode, setMode] = useState('helia')
  const [gateway, setGateway] = useState('http://127.0.0.1:8080')
  const [dataDir, setDataDir] = useState('')

  useEffect(
    function () {
      if (!ipfs) return
      setEn(ipfs.enabled !== false)
      setMode(ipfs.mode === 'external' ? 'external' : 'helia')
      setGateway(ipfs.externalGatewayUrl || 'http://127.0.0.1:8080')
      setDataDir(ipfs.dataDir || '')
    },
    [ipfs]
  )

  const loadSeeds = useCallback(function () {
    if (i.mode !== 'helia' || !i.canUpload) {
      setSeeds([])
      setSeedsErr(null)
      return
    }
    setSeedsLoading(true)
    setSeedsErr(null)
    fetch('/api/ipfs/pins')
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.error || String(r.status))
          return j
        })
      })
      .then(function (j) {
        const rows = Array.isArray(j.pins)
          ? j.pins
          : Array.isArray(j.seeds)
            ? j.seeds
            : []
        setSeeds(rows)
      })
      .catch(function (err) {
        setSeedsErr(err.message || String(err))
        setSeeds([])
      })
      .finally(function () {
        setSeedsLoading(false)
      })
  }, [i.mode, i.canUpload])

  useEffect(
    function () {
      loadSeeds()
    },
    [loadSeeds]
  )

  const apply = useCallback(
    function (e) {
      e.preventDefault()
      setBusy(true)
      setMsg(null)
      patchJson('/api/ipfs', {
        enabled: en,
        mode,
        externalGatewayUrl: gateway.trim(),
        dataDir: dataDir.trim()
      })
        .then(function (j) {
          if (typeof onApplied === 'function') onApplied(j)
          setMsg({ kind: 'ok', text: 'IPFS settings applied.' })
          window.setTimeout(function () {
            setMsg(null)
          }, 2200)
        })
        .catch(function (err) {
          setMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(function () {
          setBusy(false)
        })
    },
    [en, mode, gateway, dataDir, onApplied]
  )

  const uploadFile = useCallback(
    function (e) {
      e.preventDefault()
      const input = uploadInputRef.current
      const file = input && input.files && input.files[0]
      if (!file) {
        setMsg({ kind: 'err', text: 'Choose a file first.' })
        return
      }
      setUploadBusy(true)
      setMsg(null)
      const url = '/api/ipfs/add?filename=' + encodeURIComponent(file.name)
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: file
      })
        .then(function (r) {
          return r.json().then(function (j) {
            if (!r.ok) throw new Error(j.error || String(r.status))
            return j
          })
        })
        .then(function (j) {
          if (input) input.value = ''
          loadSeeds()
          return fetch('/api/ipfs').then(function (r) {
            return r.json()
          })
        })
        .then(function (st) {
          if (typeof onApplied === 'function') onApplied(st)
          setMsg({
            kind: 'ok',
            text: 'Stored in local Helia; other peers can fetch blocks as your node advertises them.'
          })
          window.setTimeout(function () {
            setMsg(null)
          }, 3800)
        })
        .catch(function (err) {
          setMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(function () {
          setUploadBusy(false)
        })
    },
    [onApplied, loadSeeds]
  )

  const unseed = useCallback(
    function (cid) {
      setUnseedingCid(cid)
      setMsg(null)
      fetch('/api/ipfs/pins/' + encodeURIComponent(cid), { method: 'DELETE' })
        .then(function (r) {
          return r.json().then(function (j) {
            if (!r.ok) throw new Error(j.error || String(r.status))
            return j
          })
        })
        .then(function () {
          loadSeeds()
          if (typeof onApplied === 'function') {
            return fetch('/api/ipfs').then(function (r) {
              return r.json()
            })
          }
          return null
        })
        .then(function (st) {
          if (st && typeof onApplied === 'function') onApplied(st)
        })
        .catch(function (err) {
          setMsg({ kind: 'err', text: err.message || String(err) })
        })
        .finally(function () {
          setUnseedingCid(null)
        })
    },
    [loadSeeds, onApplied]
  )

  let stateLabel = '—'
  let stateClass = 'dim'
  if (i.enabled === false) {
    stateLabel = 'Disabled'
    stateClass = 'dim'
  } else if (i.lastError) {
    stateLabel = 'Error'
    stateClass = 'bad'
  } else if (i.listening) {
    stateLabel = 'Listening'
    stateClass = 'ok'
  } else {
    stateLabel = 'Off or starting'
    stateClass = 'dim'
  }

  return (
    <div className="card interface-card ipfs-gateway-card">
      <div className="interface-card-head">
        <span className="interface-card-title">
          <strong>IPFS</strong>
          {' · '}
          <span className={'ipfs-gateway-state ' + stateClass}>{stateLabel}</span>
        </span>
      </div>
      <div className="policy-controls">
        {!dnsEnabled || !dnsListening ? (
          <p className="form-status err" role="alert">
            Turn on the DNS server (above) and ensure it is listening so CID hostnames resolve to this
            gateway.
          </p>
        ) : null}
        <div className="ipfs-status-grid">
          <div className="ipfs-status-row">
            <span className="dim">HTTP</span>
            <span>
              port {i.httpPort ?? 80}
              {i.ipv4 ? (
                <>
                  {' '}
                  on <code className="ipfs-bind-ip">{i.ipv4}</code>
                </>
              ) : (
                <span className="dim"> — </span>
              )}
            </span>
          </div>
          <div className="ipfs-status-row">
            <span className="dim">Backend</span>
            <span>
              {i.mode === 'external' ? (
                <>
                  External gateway{' '}
                  <code className="ipfs-config-detail">{i.externalGatewayUrl || '—'}</code>
                </>
              ) : (
                <>
                  Embedded Helia —{' '}
                  <code className="ipfs-config-detail" title={i.dataDir || ''}>
                    {i.dataDir || '~/.nospoon/helia'}
                  </code>
                </>
              )}
            </span>
          </div>
          {i.lastError ? (
            <p className="form-status err ipfs-status-err" role="alert">
              {i.lastError}
            </p>
          ) : null}
        </div>
        <p className="policy-blurb dim meta-tight">
          DNS answers <code>A</code> for multibase CID labels (e.g. <code>bafy…</code>) to this address.
          Browsers send <code>Host: &lt;cid&gt;</code>; manual name <code>ipfs</code> points here too.
        </p>
        <div className="ipfs-upload-block">
          <p className="policy-group-head dns-manual-head">Upload / seed locally</p>
          {i.mode === 'external' ? (
            <p className="dim meta-tight">
              Panel upload uses embedded Helia only. For an external gateway, run <code>ipfs add</code> on that
              machine, or switch backend to Helia above.
            </p>
          ) : !i.canUpload ? (
            <p className="dim meta-tight">
              Start the gateway (enable IPFS + DNS above); when Helia is ready, upload unlocks.
            </p>
          ) : (
            <form className="ipfs-upload-form" onSubmit={uploadFile}>
              <label className="ipfs-upload-label">
                <span className="dim">File</span>
                <input ref={uploadInputRef} type="file" disabled={uploadBusy} />
              </label>
              <button type="submit" disabled={uploadBusy}>
                {uploadBusy ? 'Uploading…' : 'Upload'}
              </button>
            </form>
          )}
          {i.mode === 'helia' && i.canUpload ? (
            <div className="ipfs-seeds-block">
              <p className="policy-group-head dns-manual-head">Local seeds (pinned roots)</p>
              {seedsLoading ? (
                <p className="dim meta-tight">Loading…</p>
              ) : seedsErr ? (
                <p className="form-status err meta-tight" role="alert">
                  {seedsErr}
                </p>
              ) : seeds.length === 0 ? (
                <p className="dim meta-tight">No pinned roots yet. Upload a file above to seed it.</p>
              ) : (
                <ul className="ipfs-recent-adds ipfs-seeds-list">
                  {seeds.map(function (row) {
                    const href = cidToDwebHttpHref(row.cid)
                    const name = row.filename || '—'
                    return (
                      <li key={row.cid}>
                        <a className="ipfs-recent-cid" href={href} title={href} target="_blank" rel="noopener noreferrer">
                          <code>{row.cid}</code>
                        </a>
                        <span className="dim ipfs-recent-name">{name}</span>
                        <button
                          type="button"
                          className="small ipfs-unseed-btn"
                          disabled={unseedingCid != null}
                          onClick={function () {
                            unseed(row.cid)
                          }}
                        >
                          {unseedingCid === row.cid ? '…' : 'Unseed'}
                        </button>
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          ) : null}
        </div>
        {msg ? (
          <p
            className={'form-status ' + (msg.kind === 'err' ? 'err' : 'ok')}
            role={msg.kind === 'err' ? 'alert' : undefined}
          >
            {msg.text}
          </p>
        ) : null}
        <form className="dns-settings-form ipfs-settings-form" onSubmit={apply}>
          <p className="policy-group-head dns-manual-head">Configuration</p>
          <label className="policy-toggle-row dns-toggle-spaced">
            <span className="policy-toggle-input">
              <input
                type="checkbox"
                checked={Boolean(en)}
                onChange={function (e) {
                  setEn(e.target.checked)
                }}
                disabled={busy}
              />
            </span>
            <span className="policy-toggle-body">IPFS gateway enabled</span>
          </label>
          <label>
            Backend
            <select
              value={mode}
              onChange={function (e) {
                setMode(e.target.value)
              }}
              disabled={busy}
            >
              <option value="helia">Embedded Helia (local blockstore)</option>
              <option value="external">Existing gateway (HTTP URL)</option>
            </select>
          </label>
          {mode === 'external' ? (
            <label>
              Gateway base URL
              <input
                value={gateway}
                onChange={function (e) {
                  setGateway(e.target.value)
                }}
                placeholder="http://127.0.0.1:8080"
                autoComplete="off"
                disabled={busy}
              />
            </label>
          ) : (
            <label>
              Helia data directory (optional)
              <input
                value={dataDir}
                onChange={function (e) {
                  setDataDir(e.target.value)
                }}
                placeholder="Default: ~/.nospoon/helia"
                autoComplete="off"
                disabled={busy}
              />
            </label>
          )}
          <button type="submit" disabled={busy}>
            {busy ? 'Applying…' : 'Apply'}
          </button>
        </form>
      </div>
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
          {d.whoisAuth &&
          (d.whoisAuth.listening || d.whoisAuth.lastError) ? (
            <p className="dim meta-tight">
              Whois-only HTTP (port {d.whoisAuth.httpPort ?? 80})
              {d.whoisAuth.listening && d.whoisAuth.ipv4
                ? ` on ${d.whoisAuth.ipv4} — curl http://${d.whoisAuth.ipv4}/<z32-or-key.topic>`
                : null}
              {d.whoisAuth.lastError ? ` — ${d.whoisAuth.lastError}` : null}
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

/** @param {{ data: object | null, error: string | null }} props */
function BrowserNetProxySection ({ data, error }) {
  if (error) {
    return (
      <p className="dim browser-net-proxy-error" role="alert">
        Virtual interfaces status: {error}
      </p>
    )
  }
  if (!data) {
    return <p className="dim meta-tight">Loading virtual interfaces status…</p>
  }
  const ip = data.primaryTunIp || data.defaultListenIpv4
  const listeners = data.listeners || []
  const streams = data.streams || []
  return (
    <div className="browser-net-proxy-card virtual-interfaces-card">
      <p className="meta-tight dim">
        Default mesh bind IP for <code>listen()</code> (no host):{' '}
        <strong className="browser-net-ip">{ip || '—'}</strong>
      </p>
      <div className="policy-group browser-net-group">
        <p className="policy-group-head">Virtual listeners</p>
        <p className="meta-tight dim browser-net-blurb">
          <code>host:port</code> sockets forwarded to a browser tab over the WebSocket proxy (one registration per address).
        </p>
        {listeners.length === 0 ? (
          <p className="dim meta-tight">(none — use browser-net <code>listen</code> from a page)</p>
        ) : (
          <ul className="browser-net-list">
            {listeners.map(function (row, i) {
              return (
                <li key={i} className="browser-net-list-row">
                  <code className="browser-net-addr">
                    {row.bind}:{row.port}
                  </code>
                  <span className="dim browser-net-cid" title={row.clientId}>
                    tab {row.clientId ? row.clientId.slice(0, 8) + '…' : '—'}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </div>
      <div className="policy-group browser-net-group">
        <p className="policy-group-head">Active streams</p>
        {streams.length === 0 ? (
          <p className="dim meta-tight">(no proxied TCP sessions)</p>
        ) : (
          <ul className="browser-net-streams">
            {streams.map(function (s, si) {
              const loc = s.local
                ? `${s.local.ip}:${s.local.port}`
                : '—'
              const rem = s.remote
                ? `${s.remote.ip}:${s.remote.port}`
                : '—'
              const dir = s.outbound ? 'out' : 'in'
              return (
                <li key={si} className="browser-net-stream-row">
                  <span className="browser-net-stream-dir" title={dir === 'out' ? 'Outbound' : 'Inbound'}>
                    {dir}
                  </span>
                  <code className="browser-net-stream-addr">{loc}</code>
                  <span className="dim">↔</span>
                  <code className="browser-net-stream-addr">{rem}</code>
                  <span className="dim browser-net-stream-state">{s.state || '—'}</span>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}

export default function App () {
  const [status, setStatus] = useState(null)
  const [browserNetStatus, setBrowserNetStatus] = useState(null)
  const [browserNetError, setBrowserNetError] = useState(null)
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

  useEffect(() => {
    let cancelled = false
    function fetchBrowserNet () {
      fetch('/api/browser-net/status')
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status)
          return r.json()
        })
        .then(function (j) {
          if (!cancelled) {
            setBrowserNetStatus(j)
            setBrowserNetError(null)
          }
        })
        .catch(function (e) {
          if (!cancelled) {
            setBrowserNetError(e.message || String(e))
          }
        })
    }
    fetchBrowserNet()
    const id = window.setInterval(fetchBrowserNet, 2000)
    return function () {
      cancelled = true
      window.clearInterval(id)
    }
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

  const mergeIpfsStatus = useCallback(function (next) {
    setStatus(function (prev) {
      const base = prev || emptyStatus
      const prevDns = base.dns || emptyStatus.dns
      return {
        ...base,
        dns: { ...prevDns, ipfsDweb: next }
      }
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
      <p className="meta">Public key: <a href={`http://${s.clientPublicKeyZ32}/`} target="_blank" rel="noopener noreferrer" className="peer-key-link">{s.clientPublicKeyZ32 || '—'}</a></p>

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

      <h2>Virtual interfaces</h2>
      <p className="meta dim">
        Virtual TCP listeners and streams bridged to browser tabs via the{' '}
        <code>/api/browser-net</code> WebSocket (mesh middleman).
      </p>
      <BrowserNetProxySection data={browserNetStatus} error={browserNetError} />

      <h2>DNS interface</h2>
      <DnsInterfaceCard dns={dns} onPatchDns={patchDns} />

      <h2>IPFS gateway</h2>
      <p className="meta dim">
        Serves UnixFS by <code>Host</code> (multibase CID) on a loopback alias; DNS must be on so{' '}
        <code>A</code> queries resolve. See manual hostname <code>ipfs</code> in DNS.
      </p>
      <IpfsGatewayCard
        ipfs={dns.ipfsDweb}
        dnsEnabled={Boolean(dns.enabled)}
        dnsListening={Boolean(dns.listening)}
        onApplied={mergeIpfsStatus}
      />
    </>
  )
}
