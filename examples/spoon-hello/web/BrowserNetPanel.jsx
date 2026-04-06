import { useCallback, useEffect, useRef, useState } from 'react'
import {
  setBrowserNetProxy,
  defaultBrowserNetWsUrl,
  BrowserNetServer
} from 'browser-net-shim'

const NL = '\n'

export function BrowserNetPanel ({
  controlPanelOrigin,
  primaryMeshZ32,
  onShimError
}) {
  const [bindHost, setBindHost] = useState(primaryMeshZ32 || '')
  const [listenPort, setListenPort] = useState('23')
  const [log, setLog] = useState('')
  const [fromPeers, setFromPeers] = useState('')
  const [toPeers, setToPeers] = useState('')

  const serverRef = useRef(null)
  const activeSocksRef = useRef(new Set())
  const peerDecRef = useRef(new WeakMap())
  const labeledPeersRef = useRef(new WeakSet())
  const awaitingWhoisRef = useRef(new WeakMap())
  const lastFromSockRef = useRef(null)
  const lastBrowserValueRef = useRef('')

  useEffect(() => {
    if (primaryMeshZ32) setBindHost(primaryMeshZ32)
  }, [primaryMeshZ32])

  useEffect(() => {
    let cancelled = false
    ;(async function loadShim () {
      try {
        const o =
          controlPanelOrigin.indexOf('://') !== -1
            ? controlPanelOrigin
            : `http://${controlPanelOrigin}`
        const cu = new URL(o)
        setBrowserNetProxy({
          hostname: cu.hostname,
          port: cu.port ? Number(cu.port) : undefined,
          pathname: '/api/browser-net'
        })
        if (cancelled) return
      } catch (e) {
        onShimError?.(e)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [controlPanelOrigin, onShimError])

  const appendLog = useCallback((line) => {
    setLog((prev) => prev + line + NL)
  }, [])

  const broadcastBytes = useCallback((u8) => {
    for (const sock of activeSocksRef.current) {
      try {
        sock.write(u8)
      } catch (_) {}
    }
  }, [])

  const delBytesForString = useCallback(
    (removedJs) => {
      const enc = new TextEncoder()
      const n = enc.encode(removedJs).byteLength
      if (!n) return
      const u = new Uint8Array(n)
      u.fill(127)
      broadcastBytes(u)
    },
    [broadcastBytes]
  )

  const onToPeersInput = useCallback(
    (v) => {
      setToPeers(v)
      const prev = lastBrowserValueRef.current
      if (v === prev) return
      const server = serverRef.current
      if (server && activeSocksRef.current.size > 0) {
        let p = 0
        const min = Math.min(v.length, prev.length)
        while (p < min && v.charCodeAt(p) === prev.charCodeAt(p)) p++
        const del = prev.slice(p)
        const ins = v.slice(p)
        if (del.length) delBytesForString(del)
        if (ins.length) broadcastBytes(new TextEncoder().encode(ins))
      }
      lastBrowserValueRef.current = v
    },
    [broadcastBytes, delBytesForString]
  )

  const startListen = useCallback(async () => {
    if (serverRef.current) {
      appendLog('already listening — stop first')
      return
    }
    const enc = new TextEncoder()
    const o =
      controlPanelOrigin.indexOf('://') !== -1
        ? controlPanelOrigin
        : `http://${controlPanelOrigin}`
    const wsUrl = defaultBrowserNetWsUrl(window.location.href)
    try {
      const server = new BrowserNetServer({ url: wsUrl })
      server.addEventListener('connection', function (ev) {
        const sock = ev.detail
        activeSocksRef.current.add(sock)
        peerDecRef.current.set(sock, new TextDecoder('utf-8', { fatal: false }))
        appendLog(
          `[session] open ${sock.remoteAddress}:${sock.remotePort}`
        )
        sock.addEventListener('data', function (e) {
          const u8 = new Uint8Array(e.data)
          function flushPending (label) {
            const pending = awaitingWhoisRef.current.get(sock)
            if (!pending) return
            awaitingWhoisRef.current.delete(sock)
            labeledPeersRef.current.add(sock)
            setFromPeers((prev) => {
              let next = prev + `[${label}] `
              const dec = peerDecRef.current.get(sock)
              for (let i = 0; i < pending.length; i++) {
                next += dec.decode(pending[i], { stream: true })
              }
              return next
            })
          }
          if (!labeledPeersRef.current.has(sock)) {
            if (!awaitingWhoisRef.current.has(sock)) {
              awaitingWhoisRef.current.set(sock, [])
              setFromPeers((prev) => (prev.length ? prev + NL : prev))
              lastFromSockRef.current = sock
              const ip = sock.remoteAddress
              const whoisUrl = new URL(
                `/api/whois/${encodeURIComponent(ip)}`,
                o
              ).href
              fetch(whoisUrl)
                .then(function (r) {
                  return r.ok ? r.text() : ''
                })
                .then(function (raw) {
                  if (!activeSocksRef.current.has(sock)) return
                  const line = raw.trim()
                  const label = line || `${ip}:${sock.remotePort}`
                  flushPending(label)
                })
                .catch(function () {
                  if (!activeSocksRef.current.has(sock)) return
                  flushPending(`${ip}:${sock.remotePort}`)
                })
            }
            awaitingWhoisRef.current.get(sock).push(u8)
            return
          }
          if (lastFromSockRef.current !== sock) {
            setFromPeers((prev) => (prev.length ? prev + NL : prev))
            lastFromSockRef.current = sock
          }
          const dec = peerDecRef.current.get(sock)
          setFromPeers((prev) => prev + dec.decode(u8, { stream: true }))
        })
        sock.addEventListener('close', function () {
          activeSocksRef.current.delete(sock)
          if (lastFromSockRef.current === sock) lastFromSockRef.current = null
          appendLog(
            `[session] close ${sock.remoteAddress}:${sock.remotePort}`
          )
        })
      })
      const port = Number(listenPort) || 23
      const bh = bindHost.trim()
      if (bh) await server.listen({ port, host: bh })
      else await server.listen(port)
      serverRef.current = server
      appendLog(`listening (nc-style) ${bh || 'primary'}:${port}`)
    } catch (err) {
      appendLog(
        `error: ${err && err.message ? err.message : String(err)}`
      )
      serverRef.current = null
    }
  }, [appendLog, bindHost, controlPanelOrigin, listenPort])

  const stopListen = useCallback(() => {
    const server = serverRef.current
    if (server) {
      server.close()
      serverRef.current = null
      activeSocksRef.current.clear()
      lastFromSockRef.current = null
      appendLog('stopped')
    }
  }, [appendLog])

  return (
    <section>
      <h2>Browser-net (netcat-style)</h2>
      <p>
        Loads <code>web/net</code> <code>browser-net-client</code> (cross-origin). From a mesh peer run{' '}
        <code>nc &lt;mesh-host&gt; &lt;port&gt;</code> (or similar). Bytes from clients show below as they arrive;
        what you type in the box is sent to <strong>all</strong> connected sessions immediately (UTF-8, edits
        become DEL + insert on the wire). Each peer line is tagged using{' '}
        <code>/api/whois/&lt;ip&gt;</code> on the control host — the same plain-text line as{' '}
        <code>http://whois/&lt;ip&gt;</code> when mesh DNS exposes <code>whois</code>. If lookup fails, the tag falls back to{' '}
        <code>ip:port</code>. Bind host defaults to your primary mesh DNS label (z32); override with a local mesh IPv4 or{' '}
        <code>z32.topic</code>.
      </p>
      <p>
        <label>
          Bind host{' '}
          <input
            type="text"
            size={52}
            value={bindHost}
            onChange={(e) => setBindHost(e.target.value)}
          />
        </label>
      </p>
      <p>
        <label>
          Port{' '}
          <input
            type="number"
            value={listenPort}
            min={1}
            max={65535}
            onChange={(e) => setListenPort(e.target.value)}
          />
        </label>
      </p>
      <p>
        <button type="button" onClick={startListen}>
          Listen
        </button>
        <button type="button" onClick={stopListen}>
          Stop
        </button>
      </p>
      <p><strong>From peers</strong></p>
      <pre className="from-peers">{fromPeers}</pre>
      <p><strong>To peers</strong> (type here — broadcast to every session)</p>
      <textarea
        className="to-peers"
        rows={4}
        spellCheck={false}
        placeholder="Listening… type to send."
        value={toPeers}
        onChange={(e) => onToPeersInput(e.target.value)}
      />
      <p><strong>Log</strong></p>
      <pre className="log">{log}</pre>
    </section>
  )
}
