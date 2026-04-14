# nospoon

> *"There is no spoon."* — The Matrix (1999)

A peer-to-peer VPN that **does not require a publicly reachable coordinator**. Peers find each other with [HyperDHT](https://github.com/holepunchto/hyperdht) and [Hyperswarm](https://github.com/holepunchto/hyperswarm), punch through NAT, and carry IP packets over **Noise-encrypted** streams. No public IP, no port forwarding, no central infra — only keys and (for topic overlays) a **topic** you share out of band.

**This branch focuses on:**

| Mode | Command | Idea |
|------|---------|------|
| **HTTP control plane** | `nospoon` (default) or `nospoon web` | Join Hyperswarm topics and direct peers, mesh DNS, TUN — browser UI on `/`. Same topic string ⇒ same overlay; pairwise tunnels only. |

IPv4 on the wire uses **key-address** encoding (IPs ↔ public keys inside the tunnel). IPv6 passes through without that layer. More detail: [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

```bash
sudo npm install -g nospoon
```

Requires Linux or macOS and a recent Node.js. Root (or equivalent) is often needed for TUN creation, routes, and optional system DNS override.

## Topic mesh (via control plane)

Everyone shares the **same topic bytes** (string or UTF-8). **Discovery** uses a 32-byte **discovery key** (BLAKE2b over a domain label + topic bytes — same style as Hypercore), so passive DHT observers do not see the raw topic on the wire. **After Noise**, each side proves possession of the topic **preimage** with a hypercore-style capability; a mismatch drops the connection. Traffic is **pairwise** (no application-level relay of tun frames through a third peer in the current implementation). You join and leave topics from the HTTP control plane (default command below), not a separate CLI subcommand.

See [ARCHITECTURE.md](ARCHITECTURE.md) for trust, primary TUN addressing, and bind-surface considerations.

## HTTP control plane (default)

```bash
sudo nospoon
# or explicit:
sudo nospoon web --port 80
```

Mesh DNS, direct pool, topic joins, and static control UI. Options include `--host`, `--primary-cidr`, `--seed` (control Noise identity), and `--no-system-dns`. From the repo, `npm run dev` runs the control server plus Vite (see `scripts/dev-web.mjs`).

## Command reference

### Default / `nospoon web` / `nospoon control`

| Flag | Default | Description |
|------|---------|-------------|
| `--port <num>` | `80` | HTTP listen port |
| `--host <addr>` | auto loopback alias | Bind address (`nospoon` DNS name when mesh DNS is on) |
| `--primary-cidr <cidr>` | auto `10.0.x.1/24` | Primary (direct pool) IPv4 CIDR |
| `--seed <z32|hex>` | `~/.nospoon/identity.json` | Control-plane Noise seed |
| `--no-system-dns` | off | Skip OS resolver override |

### `nospoon genkey`

Print a random seed and public key (**z32**). No root. Legacy **64 hex** strings are still accepted anywhere a key or seed is parsed.

## How it works (short)

1. Peers discover each other via **Hyperswarm** + topic or via the **control plane** (direct pool + shared swarm).
2. UDP hole-punching (and optional relays at the DHT layer) help establish a **Noise** stream.
3. IPv4 frames are **key-address**-encoded where applicable; length-prefixed frames carry payloads over the stream.
4. The kernel sees a normal TUN; applications use normal sockets.

**Swarm** membership is **who knows the topic preimage** (verified after Noise); bind services only to the TUN (or be deliberate with `0.0.0.0`) — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Limitations

- **Symmetric NAT** — both sides behind symmetric NAT may fail to connect.
- **macOS** — tested on Apple Silicon and recent macOS; Linux is the primary target.

## License

GPL-3.0 — See [LICENSE](LICENSE)

## Credits

- [HyperDHT](https://github.com/holepunchto/hyperdht) — DHT and hole-punching
- [Hyperswarm](https://github.com/holepunchto/hyperswarm) — Topic-based peer discovery
- [koffi](https://koffi.dev/) — FFI for TUN on Linux / macOS
- [Noise Protocol](https://noiseprotocol.org/) — Encryption framework
- [HoleSail](https://holesail.io/) — Layer-4 inspiration
