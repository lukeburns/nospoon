# Refactor notes (shared swarm / multi-interface)

We have one Hyperswarm stream per remote key, one framed inbound pipeline per stream, and multiple logical meshes (primary + topics). Each mesh still has its own small `router` (key → stream) and its own TUN; **routing** resolves `destIp` via the shared key-address table (`ka`) before it can use that map.

What we fixed in practice: mirroring `router.addPeer` was necessary but not sufficient—**`ka` must hold every alias you send on** (primary `kind: 'key'`, topic `kind: 'keyTopic'`) or `getConnectionForDestination` bails before it ever looks up the stream. The control plane now “fills in” missing rows when the stream attached on the other path (`ensureSharedPeerKeyAddress`, `syncSharedInboundToPrimary` / primary slot + `attachSharedStreamToPeerState`).

**Parsimonious direction (if we revisit this):**

- One outbound helper used by every TUN: `resolveStreamForMeshPacket(destIp)` = shared `ka` + one place that knows the live `conn` per remote key (instead of N routers to keep in sync).
- Or keep N routers but drive them from a single “bind stream for key” primitive that always does `router.addPeer` **and** the right `ka.register` for each mesh context, with one close path.

Until then, the duplication (sync calls in control-http + mesh/direct helpers) is the honest expression of “one wire, many logical interfaces.”

## Browser `net` (WebSocket proxy)

**Done (incremental):** `lib/browser-net-proxy.js` terminates TCP for registered `(local mesh IPv4, port)` and multiplexes over `/api/browser-net`. The shim in `web/browser-net-shim.js` exposes `BrowserNetServer`, optional `setBrowserNetProxy({ hostname, port })` for the WS URL (same *idea* as [net-browserify](https://github.com/emersion/net-browserify)), and `listen({ port, host })` where `host` is primary by default or a local mesh IP / mesh DNS name for this key.

**TODO:** A true **`net` polyfill** (Browserify/Webpack alias): `net.connect` to mesh destinations, `createServer` wrapping the same protocol, `Socket`/`Server` parity with Node enough for existing apps — not only `BrowserNetServer`.
