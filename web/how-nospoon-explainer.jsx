import { useEffect, useState } from 'react'
import './explainer.css'

const KEY_LEN = 32
const IPV4_PREFIX_LEN = 12
const FLAG_SRC = 0x01
const FLAG_DST = 0x02

function wireHeaderLen (flags) {
  const srcLen = flags & FLAG_SRC ? KEY_LEN : 4
  const dstLen = flags & FLAG_DST ? KEY_LEN : 4
  return IPV4_PREFIX_LEN + 1 + srcLen + dstLen
}

/** @param {{ flags: number }} props */
function WireHeaderDiagram ({ flags }) {
  const srcKeyed = (flags & FLAG_SRC) !== 0
  const dstKeyed = (flags & FLAG_DST) !== 0
  const srcLen = srcKeyed ? KEY_LEN : 4
  const dstLen = dstKeyed ? KEY_LEN : 4
  const total = wireHeaderLen(flags)
  return (
    <div className="exp-wire-wrap" aria-hidden="true">
      <div className="exp-wire-bar">
        <span className="exp-seg exp-seg-prefix" style={{ flex: IPV4_PREFIX_LEN }}>
          <span className="exp-seg-label">12 B prefix</span>
        </span>
        <span className="exp-seg exp-seg-flags" style={{ flex: 1 }}>
          <span className="exp-seg-label">flags</span>
        </span>
        <span className={'exp-seg ' + (srcKeyed ? 'exp-seg-key' : 'exp-seg-lit')} style={{ flex: srcLen }}>
          <span className="exp-seg-label">{srcKeyed ? '32 B src id' : '4 B src'}</span>
        </span>
        <span className={'exp-seg ' + (dstKeyed ? 'exp-seg-key' : 'exp-seg-lit')} style={{ flex: dstLen }}>
          <span className="exp-seg-label">{dstKeyed ? '32 B dst id' : '4 B dst'}</span>
        </span>
      </div>
      <p className="exp-wire-meta">Header: <strong>{total}</strong> bytes before payload.</p>
    </div>
  )
}

function WirePlayground () {
  const [flags, setFlags] = useState(FLAG_SRC | FLAG_DST)
  return (
    <section className="exp-section exp-wire-section">
      <h3 className="exp-section-title">Tweak the IPv4 wire header</h3>
      <p className="exp-muted">
        Keyed slots carry a 32-byte endpoint id; off means a literal IPv4 in that slot.
      </p>
      <div className="exp-toggles">
        <label className="exp-toggle">
          <input
            type="checkbox"
            checked={(flags & FLAG_SRC) !== 0}
            onChange={function () {
              setFlags(flags ^ FLAG_SRC)
            }}
          />
          <span>Source keyed</span>
        </label>
        <label className="exp-toggle">
          <input
            type="checkbox"
            checked={(flags & FLAG_DST) !== 0}
            onChange={function () {
              setFlags(flags ^ FLAG_DST)
            }}
          />
          <span>Dest keyed</span>
        </label>
      </div>
      <WireHeaderDiagram flags={flags} />
    </section>
  )
}

const KEY_ALICE = 'm7vk2xq5na8alice9qh2bogusz32placeholder4nospoondemo'
const KEY_BOB = 'w9vk2xq5nb8b0b0b0bogusz32placeholder4nospoondemo'
const KEY_CHAN = 'c3vk2xq5nc8chan9bogusz32placeholder4nospoon'

function shortKey (z) {
  if (z.length <= 14) return z
  return z.slice(0, 7) + '…' + z.slice(-5)
}

/** Global consensus: one agreed IPv4 per identity on the whole mesh (Alice & Bob coordinated). */
const GLOBAL_ROW_ALICE = { id: 'alice', ip: '10.0.0.1', key: KEY_ALICE, label: 'Alice' }
const GLOBAL_ROW_BOB = { id: 'bob', ip: '10.0.0.2', key: KEY_BOB, label: 'Bob' }
const GLOBAL_ROW_CHAN = { id: 'chan', ip: '10.0.0.3', key: KEY_CHAN, label: 'Chan' }
const GLOBAL_MESH_BY_IP = [GLOBAL_ROW_ALICE, GLOBAL_ROW_BOB, GLOBAL_ROW_CHAN]

/** Local nospoon: each TUN uses 10.0.0.1 for “self”; peer numbers are chosen independently per machine. */
const ALICE_SELF = { id: 'self', ip: '10.0.0.1', key: KEY_ALICE, label: 'Alice' }
const BOB_SELF = { id: 'self', ip: '10.0.0.1', key: KEY_BOB, label: 'Bob' }

const ALICE_ROW_BOB = { id: 'bob', ip: '10.0.0.2', key: KEY_BOB, label: 'Bob' }
const ALICE_ROW_CHAN = { id: 'chan', ip: '10.0.0.3', key: KEY_CHAN, label: 'Chan' }
const BOB_ROW_CHAN = { id: 'chan', ip: '10.0.0.2', key: KEY_CHAN, label: 'Chan' }
const BOB_ROW_ALICE = { id: 'alice', ip: '10.0.0.3', key: KEY_ALICE, label: 'Alice' }

/** First view: rows sorted by local IPv4 ascending (.1, .2, .3 on each machine — same numerals, different keys per row). */
const ALICE_BY_IP = [ALICE_SELF, ALICE_ROW_BOB, ALICE_ROW_CHAN]
const BOB_BY_IP = [BOB_SELF, BOB_ROW_CHAN, BOB_ROW_ALICE]

/** Lexicographic on key material — same sequence on both sides so row N is the same public key. */
const KEYS_SORTED = [KEY_CHAN, KEY_ALICE, KEY_BOB]

function aliceRowForKey (k) {
  if (k === KEY_ALICE) return ALICE_SELF
  if (k === KEY_BOB) return ALICE_ROW_BOB
  return ALICE_ROW_CHAN
}

function bobRowForKey (k) {
  if (k === KEY_BOB) return BOB_SELF
  if (k === KEY_ALICE) return BOB_ROW_ALICE
  return BOB_ROW_CHAN
}

const ALICE_BY_KEY = KEYS_SORTED.map(aliceRowForKey)
const BOB_BY_KEY = KEYS_SORTED.map(bobRowForKey)

function rowIsSelf (row, selfKey) {
  if (selfKey != null) return row.key === selfKey
  return row.id === 'self'
}

/**
 * @param {{
 *   aliceRows: typeof ALICE_BY_IP,
 *   bobRows: typeof BOB_BY_IP,
 *   aliceSub: string,
 *   bobSub: string,
 *   gutterCap?: string,
 *   aliceSelfKey?: string,
 *   bobSelfKey?: string
 * }} props
 */
function KatPairTables ({
  aliceRows,
  bobRows,
  aliceSub,
  bobSub,
  gutterCap,
  aliceSelfKey,
  bobSelfKey
}) {
  const cap = gutterCap != null ? gutterCap : 'local only'
  return (
    <div className="exp-two-col">
      <div className="exp-peer exp-peer-alice">
        <div className="exp-peer-label">Alice</div>
        <div className="exp-key-hero">
          <span className="exp-key-hero-tag">her key</span>
          <code className="exp-key-hero-code">{shortKey(KEY_ALICE)}</code>
        </div>
        <div className="exp-kat">
          <div className="exp-kat-title">Key-address table</div>
          <div className="exp-kat-sub">{aliceSub}</div>
          <table className="exp-table exp-table-alice">
            <thead>
              <tr>
                <th>IPv4</th>
                <th className="exp-arrow-col" aria-hidden="true">
                  ←
                </th>
                <th>Peer key</th>
              </tr>
            </thead>
            <tbody>
              {aliceRows.map(function (row) {
                return (
                  <tr
                    key={'a-' + row.id}
                    className={
                      'exp-row' +
                      (rowIsSelf(row, aliceSelfKey) ? ' exp-row-self' : '')
                    }
                  >
                    <td className="exp-ip">{row.ip}</td>
                    <td className="exp-arrow-col">←</td>
                    <td>
                      <code className="exp-key-cell">{shortKey(row.key)}</code>
                      <span className="exp-peer-tag">{row.label}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="exp-gutter" aria-hidden="true">
        <div className="exp-gutter-line" />
        <span className="exp-gutter-cap">{cap}</span>
        <div className="exp-gutter-line" />
      </div>

      <div className="exp-peer exp-peer-bob">
        <div className="exp-peer-label">Bob</div>
        <div className="exp-key-hero">
          <span className="exp-key-hero-tag">his key</span>
          <code className="exp-key-hero-code">{shortKey(KEY_BOB)}</code>
        </div>
        <div className="exp-kat">
          <div className="exp-kat-title">Key-address table</div>
          <div className="exp-kat-sub">{bobSub}</div>
          <table className="exp-table exp-table-bob">
            <thead>
              <tr>
                <th>Peer key</th>
                <th className="exp-arrow-col" aria-hidden="true">
                  →
                </th>
                <th>IPv4</th>
              </tr>
            </thead>
            <tbody>
              {bobRows.map(function (row) {
                return (
                  <tr
                    key={'b-' + row.id}
                    className={
                      'exp-row' +
                      (rowIsSelf(row, bobSelfKey) ? ' exp-row-self' : '')
                    }
                  >
                    <td>
                      <code className="exp-key-cell">{shortKey(row.key)}</code>
                      <span className="exp-peer-tag">{row.label}</span>
                    </td>
                    <td className="exp-arrow-col">→</td>
                    <td className="exp-ip">{row.ip}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function MeshHubDiagram () {
  return (
    <div className="exp-mesh-hub" aria-hidden="true">
      <div className="exp-mesh-hub-row">
        <div className="exp-mesh-node exp-mesh-node-alice">Alice</div>
        <div className="exp-mesh-edge">
          <span className="exp-mesh-edge-line" />
          <span className="exp-mesh-edge-label">coordination</span>
          <span className="exp-mesh-edge-line" />
        </div>
        <div className="exp-mesh-node exp-mesh-node-bob">Bob</div>
      </div>
      <p className="exp-mesh-hub-note">
        (+ Chan and anyone else who joins — everyone must hear the same assignment.)
      </p>
    </div>
  )
}

function KeyAddressDiorama () {
  return (
    <div className="exp-diorama">
      <p className="exp-diorama-lead">
        If IPv4 labels were <strong>global names</strong> for people, two hubs would have to <strong>agree on one map</strong>{' '}
        that every participant shares. That works in small meshes but costs coordination and a big enough address pool.
        Nospoon flips the tradeoff: <strong>keys</strong> are the global names; <strong>IPs are local nicknames</strong> that
        can collide across machines but stay consistent on each one.
      </p>

      <section className="exp-compare-panel" aria-labelledby="exp-compare-global-heading">
        <h3 className="exp-compare-title" id="exp-compare-global-heading">
          The usual idea: one shared address book (global IPs)
        </h3>
        <p className="exp-compare-blurb">
          Alice and Bob act like coordinators: they pick addresses for each key so <em>both</em> laptops list the same IPv4
          for each person. Chan gets the same number everywhere too.
        </p>
        <MeshHubDiagram />
        <KatPairTables
          aliceRows={GLOBAL_MESH_BY_IP}
          bobRows={GLOBAL_MESH_BY_IP}
          aliceSub="IP ← key (agreed map)"
          bobSub="Key → IP (same map)"
          gutterCap="same map"
          aliceSelfKey={KEY_ALICE}
          bobSelfKey={KEY_BOB}
        />
        <ul className="exp-problem-list" role="list">
          <li>
            <strong>Coordination</strong> — any join, leave, or conflict needs a round of agreement (or a central allocator).
          </li>
          <li>
            <strong>Namespace pressure</strong> — the mesh needs enough distinct addresses for everyone who might ever
            appear; collisions are global failures, not local quirks.
          </li>
        </ul>
      </section>

      <div
        className="exp-reorder-connector exp-reorder-connector-wide"
        role="img"
        aria-label="Nospoon uses local IPv4 aliases instead"
      >
        <span className="exp-reorder-arrow-line" aria-hidden="true" />
        <span className="exp-reorder-arrow-head" aria-hidden="true">
          ↓
        </span>
        <p className="exp-reorder-caption">
          Nospoon allows <strong>global collisions</strong> on IPv4 in exchange for <strong>local consistency</strong>: each
          machine builds its own table. <strong>Keys</strong> stay the stable, global identities.
        </p>
      </div>

      <section className="exp-compare-panel" aria-labelledby="exp-compare-ip-heading">
        <h3 className="exp-compare-title" id="exp-compare-ip-heading">
          Local naming: by IP on each laptop (same keys, different tables)
        </h3>
        <KatPairTables
          aliceRows={ALICE_BY_IP}
          bobRows={BOB_BY_IP}
          aliceSub="IP ← key"
          bobSub="Key → IP"
        />
        <p className="exp-callout" role="note">
          Both sides only use <strong>10.0.0.1–.3</strong>, but <strong>10.0.0.2</strong> is Bob on Alice&apos;s laptop
          and Chan on Bob&apos;s — same numeral, different keys. Read the key column, not the digit alone.
        </p>
      </section>

      <div
        className="exp-reorder-connector"
        role="img"
        aria-label="Reorder rows by public key to align the same identities on each row"
      >
        <span className="exp-reorder-arrow-line" aria-hidden="true" />
        <span className="exp-reorder-arrow-head" aria-hidden="true">
          ↓
        </span>
        <p className="exp-reorder-caption">
          Reorder by public key so row <em>n</em> is the same peer on the left and on the right.
        </p>
      </div>

      <section className="exp-compare-panel" aria-labelledby="exp-compare-key-heading">
        <h3 className="exp-compare-title" id="exp-compare-key-heading">
          Same local tables, sorted by public key (compare across each row)
        </h3>
        <KatPairTables
          aliceRows={ALICE_BY_KEY}
          bobRows={BOB_BY_KEY}
          aliceSub="IP ← key (same key order as Bob)"
          bobSub="Key → IP (same key order as Alice)"
        />
      </section>
    </div>
  )
}

export default function HowNospoonExplainerPage () {
  useEffect(function () {
    document.title = 'How nospoon works · key-address'
    document.body.classList.add('explainer-body')
    return function () {
      document.body.classList.remove('explainer-body')
    }
  }, [])

  return (
    <div className="explainer-page">
      <nav className="exp-nav">
        <a className="exp-back" href="/">
          ← Control panel
        </a>
      </nav>

      <header className="exp-header">
        <h1 className="exp-title">How nospoon works</h1>
        <p className="exp-deck">
          Explorable notes — starting with how <strong>keys</strong> become <strong>local IP aliases</strong>{' '}
          differently on every machine.
        </p>
      </header>

      <KeyAddressDiorama />

      <article className="exp-article">
        <h2 className="exp-article-title">Why the tables look different</h2>
        <p>
          The diagram above contrasts a <strong>single shared IPv4 registry</strong> (everyone agrees on the same
          numbers) with nospoon&apos;s approach: your OS still talks to a <strong>TUN</strong> in normal IPv4, but
          nospoon keeps a <strong>key-address table</strong> on <em>each</em> node — including a row for{' '}
          <em>yourself</em> (often <strong>10.0.0.1</strong> on that interface: same numeral on every machine, meaningful
          only locally). There is no single global “the IP of Bob on the internet” — only <em>your</em> alias for
          Bob&apos;s endpoint id on <em>your</em> subnet, from reservations / pool allocation / topic mesh rules.
        </p>
        <p>
          On the wire (inside Noise), packets often use <strong>endpoint ids</strong> (32-byte hashes of key ±
          topic) instead of repeating raw IPs. Same identity, many possible local numbers.
        </p>

        <h3 className="exp-h3">Endpoint id</h3>
        <pre className="exp-formula" role="figure">
          BLAKE2b( &quot;nospoon/key-address-endpoint&quot; ∥ <span className="exp-fk">ed25519 public key</span> ∥{' '}
          <span className="exp-ft">topic bytes</span> )
        </pre>
        <ul className="exp-ul">
          <li>
            <strong>Primary / direct</strong> — empty topic bytes: id is keyed only by the Noise public key.
          </li>
          <li>
            <strong>Topic mesh</strong> — same device key on another topic ⇒ different id ⇒ room for another
            alias without collision.
          </li>
        </ul>

        <WirePlayground />

        <p className="exp-foot">
          Routing and DNS in the control panel ( <code>z32</code>, <code>z32.topic</code> ) all hang off these
          same tables. More chapters later: Hyperswarm streams, framing, DNS glue…
        </p>
      </article>
    </div>
  )
}
