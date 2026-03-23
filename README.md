# nospoon

> *"There is no spoon."* — The Matrix (1999)

A peer-to-peer VPN that **does not require a publicly reachable server**. Peers find each other with [HyperDHT](https://github.com/holepunchto/hyperdht) (and optionally [Hyperswarm](https://github.com/holepunchto/hyperswarm) for topic meshes), punch through NAT, and carry IP packets over **Noise-encrypted** streams. No public IP, no port forwarding, no central infra — only keys (and, in swarm mode, a **topic** you share).

**Two shapes:**

| Mode | Command | Idea |
|------|---------|------|
| **Hub / spoke** | `server` + `client <hub-key>` | One process is the hub; others dial its public key. Optional `peers.json` or allowlist. |
| **Topic mesh** | `swarm <topic>` | No hub: same topic string ⇒ same overlay; pairwise tunnels only. |

IPv4 on the wire uses **key-address** encoding (IPs ↔ public keys inside the tunnel). IPv6 passes through without that layer. Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

```bash
sudo npm install -g nospoon
```

Requires Linux or macOS and a recent Node.js. Root (or equivalent) is needed for TUN creation and routes.

## Use cases

### 1. Reach a machine through NAT (hub / spoke)

Like [HoleSail](https://holesail.io/) but at layer 3: a TUN interface so **any** service bound on the VPN side is reachable by IP.

```bash
nospoon genkey
# Save seed and public key
```

`peers.json` on the **hub** (recommended):

```json
{
  "peers": {
    "<client-public-key>": "10.0.0.2"
  }
}
```

```bash
sudo nospoon server --config peers.json
sudo nospoon client <server-public-key> --seed <client-seed>
```

**Addresses:** unless you set **`--ip`**, nospoon picks the first free **`10.0.x.1/24`** on the host (from existing interface addresses) and logs it; **`nospoon server --config …`** without **`--ip`** keeps **`10.0.0.1/24`** so `peers.json` stays aligned. Each side’s TUN is **`.1`** in its chosen `/24`. The client maps the hub at **`--peer-ip`** (with auto subnet, **`10.0.x.2`** for the same `x`). From the client, reach the hub at that alias, not at **`.1`** (that is the client’s own TUN address).

```bash
curl http://10.0.0.2:8080    # service on hub (adjust port)
ssh user@10.0.0.2
ping 10.0.0.2
```

**Open hub** (no `--config`): any client may connect; the hub assigns **10.0.0.2**, **10.0.0.3**, … to peers. The hub can **broadcast a directory** of spoke keys so clients can map **local aliases** to other spokes for spoke-to-spoke traffic.

### 2. Full tunnel — exit via the hub

Route all IPv4 internet traffic through the hub (NAT on the server, split routes + host route on the client so DHT still works).

```bash
sudo nospoon server --full-tunnel --config peers.json
sudo nospoon client <server-key> --seed <seed> --full-tunnel
```

If the tunnel drops, the client’s routes avoid plaintext “leak” to the default route (see [ARCHITECTURE.md](ARCHITECTURE.md)).

### 3. Topic mesh (no hub)

Everyone shares the **same topic bytes** (string or UTF-8). **Discovery** uses a 32-byte **discovery key** (BLAKE2b over a domain label + topic bytes — same style as Hypercore), so passive DHT observers do not see the raw topic on the wire. **After Noise**, each side proves possession of the topic **preimage** with a hypercore-style capability; a mismatch drops the connection. Traffic is **pairwise** (no app-level relay of tun frames through a third peer in the current implementation).

```bash
sudo nospoon swarm my-shared-topic
```

Ephemeral IP assignment in the chosen subnet (default: first free **`10.0.x.1/24`** like server/client, or **`--ip`** to fix); **no** hub directory or `peers.json` in this mode. See [ARCHITECTURE.md](ARCHITECTURE.md) for trust and bind-surface considerations.

## Command reference

### `sudo nospoon server [options] [<peer-key> …]`

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | first free `10.0.x.1/24`* | Hub TUN IPv4; set explicitly to fix e.g. `10.0.0.1/24` |
| `--ipv6 <cidr>` | none | TUN IPv6 |
| `--seed <hex>` | random | Deterministic hub key |
| `--config <path>` | none | `peers.json` fixed IPs |
| `--mtu <num>` | `1400` | TUN MTU |
| `--full-tunnel` | off | NAT for client internet access |
| `--out-interface <if>` | auto | NAT egress interface |

\*Unless **`--config`** is used without **`--ip`**, in which case the implicit default is **`10.0.0.1/24`** (matches typical `peers.json` layouts).

Positional **`peer-key`** values: allowlist-only firewall (same incremental aliases as open mode).

### `sudo nospoon client <hub-public-key> [options]`

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | first free `10.0.x.1/24` | This host’s TUN address; set explicitly to fix e.g. `10.0.0.1/24` |
| `--peer-ip <addr>` | `10.0.x.2` with auto subnet | Local alias for the **hub’s** public key; if you set **`--peer-ip`**, you must also set **`--ip`** |
| `--ipv6 <cidr>` | none | TUN IPv6 |
| `--seed <hex>` | none | Client identity (`--config` / allowlist on server) |
| `--mtu <num>` | `1400` | TUN MTU |
| `--full-tunnel` | off | Route all traffic through VPN |

### `sudo nospoon swarm <topic> [options]`

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | first free `10.0.x.1/24` | This peer’s TUN; set explicitly to fix e.g. `10.0.0.1/24` |
| `--ipv6 <cidr>` | none | TUN IPv6 |
| `--seed <hex>` | random | Deterministic peer key |
| `--mtu <num>` | `1400` | TUN MTU |

### `nospoon genkey`

Print a random seed and public key. No root.

## How it works (short)

1. Peers discover each other via **HyperDHT** (hub/client) or **Hyperswarm** + topic (swarm).
2. UDP hole-punching (and optional relays at the DHT layer) help establish a **Noise** stream.
3. IPv4 frames are **key-address**-encoded; length-prefixed frames carry payloads over the stream.
4. The kernel sees a normal TUN; applications use normal sockets.

Unauthorized peers are rejected in **authenticated** hub mode before useful traffic flows. **Swarm** membership is **who knows the topic preimage** (verified after Noise); bind services only to the TUN (or be deliberate with `0.0.0.0`) — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Limitations

- **Symmetric NAT** — both sides behind symmetric NAT may fail to connect.
- **DNS in full-tunnel** — DNS is pointed at public resolvers when full-tunnel is active; custom DNS / Pi-hole-style setups are not fully integrated yet.
- **macOS** — tested on Apple Silicon (M4) and macOS Tahoe; Linux is the primary target.

## License

GPL-3.0 — See [LICENSE](LICENSE)

## Credits

- [HyperDHT](https://github.com/holepunchto/hyperdht) — DHT and hole-punching
- [Hyperswarm](https://github.com/holepunchto/hyperswarm) — Topic-based peer discovery (swarm mode)
- [koffi](https://koffi.dev/) — FFI for TUN on Linux / macOS
- [Noise Protocol](https://noiseprotocol.org/) — Encryption framework
- [HoleSail](https://holesail.io/) — Layer-4 inspiration
