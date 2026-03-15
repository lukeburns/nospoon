# nospoon

> *"There is no spoon."* — The Matrix (1999)

nospoon is named after the iconic scene from The Matrix where young Neo is freed from the illusion of limitations. Just as there is no spoon, there is no need for public IPs, open ports or port forwarding — just a cryptographic key.

<p align="center">
  <strong>The first P2P VPN that works from behind NAT. No port forwarding. No router config. Just a key.</strong>
</p>

<p align="center">
  <a href="https://github.com/jjacke13/nospoon">
    <img src="https://img.shields.io/badge/GitHub-Repository-blue?logo=github" alt="GitHub">
  </a>
  <a href="https://www.npmjs.com/package/nospoon">
    <img src="https://img.shields.io/badge/npm-v0.1.0-red?logo=npm" alt="npm">
  </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0">
    <img src="https://img.shields.io/badge/License-GPL--3.0-blue" alt="License">
  </a>
</p>

---

## Introducing nospoon

nospoon is a revolutionary peer-to-peer VPN that **eliminates the need for a publicly reachable server entirely**. It leverages **HyperDHT** — the same distributed hash table and hole-punching technology that powers Hyperswarm — to create direct encrypted connections between peers.

```
┌─────────┐                           ┌─────────┐
│ Client  │◀───── HyperDHT ──────────▶│ Client  │
│         │   (P2P encrypted tunnel)  │         │
└─────────┘                           └─────────┘
```

### What Makes nospoon Different?

| Feature | Traditional VPN | nospoon |
|---------|-----------------|---------------------|
| Publicly reachable server | Yes | No |
| Port forwarding | Yes | No |
| Monthly cost | $5-10+ | Free |
| Infrastructure | Central server | Peer-to-peer |
| Protocol | WireGuard/OpenVPN | HyperDHT + Noise |

### Key Innovations

1. **No Public IP Needed** — The "server" peer sits behind your home NAT; clients reach in via hole-punching
2. **No Port Forwarding** — No router/firewall configuration required
3. **Automatic NAT Traversal** — Uses UDP hole-punching to pierce through NATs and firewalls
4. **Public Key Addressing** — Peers are identified by cryptographic keys, not IP addresses
5. **End-to-End Encryption** — All traffic is encrypted using the Noise protocol

---

## How It Works

nospoon combines several clever technologies to achieve what was previously impossible:

### 1. HyperDHT: The Magic Behind the Magic

[HyperDHT](https://github.com/holepunchto/hyperdht) is a distributed hash table (DHT) built on the Kademlia algorithm, enhanced with UDP hole-punching capabilities. It's the same technology that enables peer-to-peer connections in apps like [Keet](https://keet.io/) and [Pears](https://pears.com/).

In HyperDHT:
- **Peers are identified by public keys**, not IP addresses
- The DHT maps public keys to network locations (IP:port)
- Anyone can announce their presence under their public key
- Anyone can look up a public key to discover how to connect

### 2. UDP Hole-Punching: Breaking Through NAT

Most devices on the internet sit behind NAT (Network Address Translation) or firewalls. This is why you can't directly connect to your home computer from outside — your router doesn't know which device should receive the incoming connection.

UDP hole-punching solves this:

```
Step 1: Both peers announce to DHT
        Client A ──▶ DHT: "I'm at 1.2.3.4:5000, here's my key"
        Client B ──▶ DHT: "I'm at 5.6.7.8:6000, here's my key"

Step 2: DHT tells each peer about the other
        DHT ──▶ Client A: "Client B is at 5.6.7.8:6000"
        DHT ──▶ Client B: "Client A is at 1.2.3.4:5000"

Step 3: Simultaneous outbound connections punch holes
        Client A ──▶ 5.6.7.8:6000 (UDP packet exits NAT, creates mapping)
        Client B ──▶ 1.2.3.4:5000 (UDP packet exits NAT, creates mapping)

Step 4: NAT mappings now exist in both directions
        Direct P2P connection established! 🎉
```

This happens automatically — neither user needs to configure their router.

### 3. Noise Protocol: Military-Grade Encryption

All connections are encrypted using the [Noise Protocol Framework](https://noiseprotocol.org/). Each peer has a key pair:
- **Public key** — Share this so others can find you
- **Seed (private key)** — Keep this secret

The Noise protocol provides:
- Forward secrecy (compromised keys can't decrypt past sessions)
- Identity hiding (optional)
- Authenticated encryption (AEAD)

### 4. TUN Interface: IP at Layer 3

nospoon creates a virtual network interface (TUN device) at the operating system level:
- IP packets are routed through this virtual interface
- The VPN operates at Layer 3 (network layer), like WireGuard
- Any IP-based protocol works — TCP, UDP, ICMP, etc.
- Standard networking tools (ping, curl, ssh) work out of the box

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet                                 │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    HyperDHT Network                      │   │
│   │                                                          │   │
│   │    Peer Discovery: "Who has public key ABC123...?"      │   │
│   │           ↓                                              │   │
│   │    Response: "They're at 73.45.123.88:49737"           │   │
│   │           ↓                                              │   │
│   │    Hole Punching: UDP packets pierce NAT                │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              ↓                                   │
│   ┌──────────────────┐        ┌──────────────────┐            │
│   │    Client A      │◀──────▶│    Client B      │            │
│   │   10.0.0.2/24    │  Noise  │   10.0.0.1/24   │            │
│   │                  │ encrypt │                  │            │
│   │  ┌────────────┐  │         │  ┌────────────┐  │            │
│   │  │  TUN dev   │  │         │  │  TUN dev   │  │            │
│   │  │   tun0     │  │         │  │   tun0     │  │            │
│   │  └────────────┘  │         │  └────────────┘  │            │
│   └──────────────────┘         └──────────────────┘            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

Local Network A                         Local Network B
┌─────────────────┐                   ┌─────────────────┐
│ 192.168.1.100   │                   │ 192.168.2.50    │
│ (your laptop)   │                   │ (your server)   │
└─────────────────┘                   └─────────────────┘
```

---

## Use Cases

### 1. Personal VPN to Your Home Server

Instead of paying for a VPS to run your services, run them at home:

```bash
# On your home server (Raspberry Pi, old laptop, etc.)
sudo nospoon server
# Output: Public key: a1b2c3d4e5f6...

# On your laptop, anywhere in the world
sudo nospoon client a1b2c3d4e5f6...

# Now access your home services as if you were on the same network
curl http://10.0.0.1:8080      # Home server's web interface
ssh user@10.0.0.1             # SSH into home server
ping 10.0.0.1                 # Test connectivity
```

**Real-world example:** Access your:
- Home Assistant instance
- Media server (Plex/Jellyfin)
- Git self-hosted

### 2. Multi-Client Networking

Connect multiple clients to a single server. All clients can reach each other through the server:

```
       ┌──────────────────┐
       │     Server       │
       │    10.0.0.1      │
       └────────┬─────────┘
                │
       ┌────────┼
       │        │        
       ▼        ▼        
   10.0.0.2   10.0.0.3
   Laptop     Desktop
```

All machines can reach each other via the server. Perfect for accessing multiple devices behind a single home connection.

### 3. Secure IoT Device Access

Connect to devices behind home NAT without exposing them to the public internet:

```
Internet
    │
    │ (nospoon tunnel)
    ▼
┌────────────────────┐
│  Your Laptop      │    ┌────────────────────┐
│  (Client)         │───▶│  Home Network      │
│  10.0.0.2         │    │  IoT Device       │
└────────────────────┘    │  10.0.0.1         │
                          └────────────────────┘
```

The IoT device is never exposed to the public internet — only you can reach it through the encrypted tunnel.

---

## Getting Started

### Prerequisites

- Linux
- Node.js 18+
- sudo access (for TUN device creation)

### Installation

```bash
# Clone the repository
git clone https://github.com/jjacke13/nospoon.git
cd nospoon

# Install dependencies
npm install
```

### Quick Start

#### Option 1: Open Mode (Personal Use)

Best for personal VPN use. Any client with your public key can connect.

**Server side:**
```bash
sudo node bin/cli.js server
```

Output:
```
TUN device tun0 up with 10.0.0.1/24 (MTU 1400)

Server listening
TUN IP:      10.0.0.1
Public key:  9f3a2b7e...

Client command:
  sudo nospoon client 9f3a2b7e...
```

**Client side:**
```bash
sudo node bin/cli.js client 9f3a2b7e...
```

Output:
```
TUN device tun0 up with 10.0.0.2/24 (MTU 1400)
Connected to server
Remote reachable at 10.0.0.1
```

You're connected! Try:
```bash
ping 10.0.0.1
ssh user@10.0.0.1
```

#### Option 2: Authenticated Mode (Multi-User)

For controlled access where you specify which clients can connect.

**Step 1: Generate client keys**
```bash
# On each client machine
node bin/cli.js genkey

# Output:
# Seed (keep secret):   abc123...
# Public key (share):   def456...
```

Give the public key to the server operator.

**Step 2: Create peers.json on server**
```json
{
  "peers": {
    "def456...client-public-key...": "10.0.0.2",
    "789abc...another-client...": "10.0.0.3"
  }
}
```

**Step 3: Start server with config**
```bash
sudo node bin/cli.js server --config peers.json
```

**Step 4: Start clients**
```bash
# Client with seed (for authenticated mode)
sudo node bin/cli.js client <server-public-key> --seed <client-seed> --ip 10.0.0.2/24
```

---

## Command Reference

### Server

```bash
sudo nospoon server [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | `10.0.0.1/24` | TUN interface IP and subnet |
| `--ipv6 <cidr>` | none | TUN IPv6 address (e.g. `fd00::1/64`) |
| `--seed <hex>` | random | 64-char hex seed for deterministic key |
| `--config <path>` | none | Path to peers.json for authentication |
| `--mtu <num>` | `1400` | TUN interface MTU |
| `--full-tunnel` | off | Enable NAT so clients can access the internet |
| `--out-interface <if>` | auto-detect | Outgoing interface for NAT |

### Client

```bash
sudo nospoon client <public-key> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ip <cidr>` | `10.0.0.2/24` | TUN interface IP and subnet |
| `--ipv6 <cidr>` | none | TUN IPv6 address (e.g. `fd00::2/64`) |
| `--seed <hex>` | none | 64-char hex seed (for auth mode) |
| `--mtu <num>` | `1400` | TUN interface MTU |
| `--full-tunnel` | off | Route all internet traffic through the VPN |

### Key Generation

```bash
node bin/cli.js genkey
```

Generates a new client key pair. No root required.

---

## Configuration Examples

### Custom IP Range

Use any private subnet:

```bash
# Server
sudo nospoon server --ip 172.16.0.1/24

# Client
sudo nospoon client <key> --ip 172.16.0.2/24
```

### Deterministic Server Key

Generate a seed once and reuse it so clients always connect to the same identity:

```bash
# Generate a random seed
openssl rand -hex 32

# Use it every time
sudo nospoon server --seed <your-seed>
```

### Lower MTU for Unstable Connections

```bash
sudo nospoon server --mtu 1200
sudo nospoon client <key> --mtu 1200
```

---

## Technical Details

### Encryption

- **Protocol**: Noise Protocol Framework
- **Key Exchange**: X25519 (Curve25519)
- **AEAD Cipher**: ChaCha20-Poly1305 (encrypts all tunnel traffic)
- **Hashing**: BLAKE2b

### Networking

- **Transport**: UDP via UDX (reliable, ordered, congestion-controlled)
- **Addressing**: Public key → IP:port mapping via HyperDHT
- **NAT Traversal**: UDP hole-punching with simultaneous open
- **Interface**: TUN (Layer 3, IP packets)

### Performance

- **Latency**: Same as your direct internet connection (P2P)
- **Throughput**: Limited by your upload/download speeds
- **Overhead**: 4 bytes framing + Noise/UDX/UDP headers per packet

### Compatibility

- **Platforms**: Linux (macOS and Android planned)
- **NAT Types**: Full cone, Address-restricted, Port-restricted (symmetric NAT may require relay)
- **Firewalls**: Works through most firewalls; requires UDP outbound

---

## Troubleshooting

### Connection Hangs

If both peers are on strict symmetric NATs, direct connection may fail. HyperDHT will attempt relay, but it's not guaranteed. Check:
- Both sides have internet access
- No firewall blocks outgoing UDP

### TUN Device Error

```bash
# If "tun0 already exists"
sudo ip link delete tun0
```

### Check Connection Status

```bash
# View TUN interface
ip addr show tun0

# View routing
ip route | grep tun

# Monitor traffic
sudo tcpdump -i tun0 -n
```

### Enable IP Forwarding (for routing)

```bash
sudo sysctl net.ipv4.ip_forward=1
```

---

## Limitations & Known Issues

- **Symmetric NAT**: Both peers behind symmetric NAT may fail to connect (relay not yet implemented)
- **Platform**: Currently Linux only (macOS and Android planned)
- **DNS**: No built-in DNS push; use IP addresses directly or configure DNS manually

---

## License

GPL-3.0 — See [LICENSE](LICENSE) for details.

---

## Credits

- [HyperDHT](https://github.com/holepunchto/hyperdht) — The DHT and hole-punching magic
- [koffi](https://koffi.dev/) — FFI for TUN device creation
- [Noise Protocol](https://noiseprotocol.org/) — Encryption framework

---

## Related Projects

- [HoleSail](https://holesail.io/) — The original HoleSail project (Layer 4)
- [Keet](https://keet.io/) — P2P video chat built on Hyperswarm
- [Hyperswarm](https://hyperswarm.org/) — P2P networking abstraction

---

<p align="center">
  <strong>Connect directly through NAT. No port forwarding. No compromises.</strong>
</p>
