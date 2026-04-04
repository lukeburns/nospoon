# Refactor notes (shared swarm / multi-interface)

We have one Hyperswarm stream per remote key, one framed inbound pipeline per stream, and multiple logical meshes (primary + topics). Each mesh still has its own small `router` (key → stream) and its own TUN; **routing** resolves `destIp` via the shared key-address table (`ka`) before it can use that map.

What we fixed in practice: mirroring `router.addPeer` was necessary but not sufficient—**`ka` must hold every alias you send on** (primary `kind: 'key'`, topic `kind: 'keyTopic'`) or `getConnectionForDestination` bails before it ever looks up the stream. The control plane now “fills in” missing rows when the stream attached on the other path (`ensureSharedPeerKeyAddress`, `syncSharedInboundToPrimary` / primary slot + `attachSharedStreamToPeerState`).

**Parsimonious direction (if we revisit this):**

- One outbound helper used by every TUN: `resolveStreamForMeshPacket(destIp)` = shared `ka` + one place that knows the live `conn` per remote key (instead of N routers to keep in sync).
- Or keep N routers but drive them from a single “bind stream for key” primitive that always does `router.addPeer` **and** the right `ka.register` for each mesh context, with one close path.

Until then, the duplication (sync calls in control-http + mesh/direct helpers) is the honest expression of “one wire, many logical interfaces.”
