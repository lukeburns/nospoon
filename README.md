# nospoon

> *"There is no spoon."* — The Matrix (1999)

A peer-to-peer VPN that **eliminates the need for a publicly reachable server**. Built on [HyperDHT](https://github.com/holepunchto/hyperdht) for NAT hole-punching and Noise-encrypted tunnels. No public IP, no port forwarding, no central infrastructure — just a key.

## Install

```bash
sudo npm install -g nospoon
```

Requires Linux or macOS and Node.js 18+. Root needed for TUN device creation.

## Use Cases

### 1. Expose any service through NAT

Like [HoleSail](https://holesail.io/) but at Layer 3 — instead of forwarding a single port, nospoon creates a full network interface. Every service on the server is reachable by IP, as if you were on the same LAN.

```bash
# Generate a client identity
nospoon genkey
# Output: Seed (keep secret): abc123...
#         Public key (share): def456...
```

Create `peers.json` on the server:
```json
{
  "peers": {
    "<client-public-key>": "10.0.0.2"
  }
}
```

```bash
# Server (behind NAT, no port forwarding needed)
sudo nospoon server --config peers.json

# Client (anywhere in the world)
sudo nospoon client <server-key> --seed <client-seed>

# Access anything on the server
curl http://10.0.0.1:8080       # web app
ssh user@10.0.0.1               # SSH
ping 10.0.0.1                   # ICMP
```

Using `--config` is recommended — it authenticates clients and assigns fixed IPs. Open mode (`sudo nospoon server` without `--config`) is available for quick testing but has no authentication and only supports a single client.

### 2. Full tunnel — access the internet from home

Route all your internet traffic through your home connection. When you're abroad, your traffic exits from your home IP — access geo-restricted content, use your home network's DNS, or just browse as if you were home.

```bash
# Server (your home machine)
sudo nospoon server --full-tunnel --config peers.json

# Client (your laptop abroad)
sudo nospoon client <key> --seed <seed> --full-tunnel
```

Kill switch included: if the tunnel drops, traffic fails instead of leaking.

## Command Reference

### `sudo nospoon server [options]`

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | `10.0.0.1/24` | TUN interface IP |
| `--ipv6 <cidr>` | none | TUN IPv6 address |
| `--seed <hex>` | random | Deterministic server key |
| `--config <path>` | none | Path to peers.json |
| `--mtu <num>` | `1400` | TUN MTU |
| `--full-tunnel` | off | Enable NAT for client internet access |
| `--out-interface <if>` | auto | Outgoing interface for NAT |

### `sudo nospoon client <public-key> [options]`

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | `10.0.0.2/24` | TUN interface IP |
| `--ipv6 <cidr>` | none | TUN IPv6 address |
| `--seed <hex>` | none | Client seed (for auth mode) |
| `--mtu <num>` | `1400` | TUN MTU |
| `--full-tunnel` | off | Route all traffic through VPN |

### `nospoon genkey`

Generate a client key pair. No root required.

## How It Works

1. Server announces its public key on the HyperDHT distributed hash table
2. Client looks up the key, HyperDHT performs UDP hole-punching through both NATs
3. A Noise-encrypted stream is established (X25519 + ChaCha20-Poly1305 + BLAKE2b)
4. IP packets flow through TUN devices on both sides, length-framed over the encrypted stream

All traffic is end-to-end encrypted. No data passes through the DHT — it's only used for peer discovery and hole-punching. In authenticated mode, unauthorized peers are rejected during the Noise handshake before a connection is established.

## Limitations

- **Symmetric NAT** — both peers behind symmetric NAT may fail to connect
- **DNS in full-tunnel mode** — DNS is automatically switched to `1.1.1.1` / `8.8.8.8` when full-tunnel is active. Custom DNS servers (e.g. a local Pi-hole) are not yet supported — a `--dns` flag with host route exemption is planned
- **macOS** — tested on Mac mini M4, macOS Tahoe

## License

GPL-3.0 — See [LICENSE](LICENSE)

## Credits

- [HyperDHT](https://github.com/holepunchto/hyperdht) — DHT and hole-punching
- [koffi](https://koffi.dev/) — FFI for TUN device creation
- [Noise Protocol](https://noiseprotocol.org/) — Encryption framework
- [HoleSail](https://holesail.io/) — The original Layer 4 project
