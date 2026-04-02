import { useCallback, useEffect, useState } from 'react'

const emptyStatus = {
  clientPublicKeyZ32: '',
  topics: [],
  directPool: null,
  directPeers: []
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

async function patchJson (url, body) {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  })
  return readJson(res)
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
function PolicyDisclosure ({ title, variant, defaultOpen, children }) {
  const cls = 'policy-disclosure' + (variant === 'peer' ? ' policy-disclosure-peer' : '')
  return (
    <details className={cls} defaultOpen={defaultOpen}>
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

function InterfaceRoutingBlock ({ policy, apiPath, onChanged, blurb, fullTunnelOs, defaultOpen = true }) {
  return (
    <div className="policy-controls">
      <PolicyDisclosure title="Interface policy" variant="interface" defaultOpen={defaultOpen}>
        {blurb ? <p className="policy-blurb dim">{blurb}</p> : null}
        <PolicyToggles policy={policy || DEFAULT_INTERFACE_POLICY} patchUrl={apiPath} onChanged={onChanged} fullTunnelOs={fullTunnelOs} />
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

function FormStatus ({ kind, text }) {
  if (!text) return null
  return (
    <p className={'form-status' + (kind ? ' ' + kind : '')} role="status" aria-live="polite">
      {text}
    </p>
  )
}

function TopicCard ({ topic, onLeave }) {
  const peers = topic.peers || []
  const topicPolicyPath = `/api/topics/${encodeURIComponent(topic.id)}/policy`
  const topicPeersPolicyBase = `/api/topics/${encodeURIComponent(topic.id)}/peers`
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
                {p.peerKeyZ32} → <IpLink ip={p.ipv4} /> 
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

function PrimaryInterfaceCard ({ directPool, directPeers, leavePeer }) {
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
                  <strong className="peer-key-z32">{d.keyZ32}</strong>
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

async function readJson (res) {
  const j = await res.json()
  if (!res.ok) throw new Error(j.error || String(res.status))
  return j
}

export default function App () {
  const [status, setStatus] = useState(null)
  const [sseState, setSseState] = useState('connecting')
  const [topicBusy, setTopicBusy] = useState(false)
  const [topicMsg, setTopicMsg] = useState(null)
  const [peerBusy, setPeerBusy] = useState(false)
  const [peerMsg, setPeerMsg] = useState(null)

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

  const s = status || emptyStatus
  const topics = s.topics || []
  const directPeers = s.directPeers || []

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
      <PrimaryInterfaceCard directPool={s.directPool} directPeers={directPeers} leavePeer={leavePeer} />

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
        topics.map((t) => <TopicCard key={t.id} topic={t} onLeave={leaveTopic} />)
      )}
    </>
  )
}
