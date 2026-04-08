# nospoon Architecture Guide

A complete walkthrough of how nospoon works, from the big picture down to
every important function. Written for someone who knows networking basics
but not Node.js internals.


## The Big Picture

nospoon is a peer-to-peer VPN. Two machines that can't normally reach each
other (behind NATs, firewalls, etc.) establish a direct encrypted connection
using a DHT (Distributed Hash Table) for discovery and NAT hole-punching.

Once connected, they exchange raw IP packets through a TUN device — a
virtual network interface that the operating system treats like a real one.

Hub/spoke example (illustrative fixed subnet: `--ip 10.0.0.1/24`, client hub alias `10.0.0.2`; without **`--ip`**, the CLI picks the first free **`10.0.x.1/24`** instead).
Each side has its **own** `.1` in the chosen `/24` on `tun0` (this host in the VPN). The
client reaches the hub at the **local alias** for the hub’s public key
(default **10.0.0.2**), not at `10.0.0.1` (that is the client’s address on its
TUN). IPv4 inside the tunnel uses **key-address** encoding on the wire.

```
 Machine A (client)                         Machine B (hub / server)
+------------------+                       +------------------+
| App (e.g. curl)  |                       | App (e.g. nginx) |
| dst 10.0.0.2     |                       | listen 10.0.0.1  |
+--------+---------+                       +--------+---------+
         | normal IPv4 to hub alias                  ^
         | (same /24; .1 = self, .2 = hub key)       | normal socket
+--------v---------+                       +---------+--------+
| tun0             |                       | tun0             |
| address 10.0.0.1 |                       | address 10.0.0.1 |
| (this machine)   |                       | (hub)            |
+--------+---------+                       +---------+--------+
         | raw IP (dst 10.0.0.2)                     | raw IP
         | key-address wrap + length frame           | unwrap → raw IP
+--------v---------+   Noise-encrypted    +---------v--------+
| createClient()   | <===== DHT =========> | startServer()    |
+------------------+     stream           +------------------+
                              ^
         Spokes get .2, .3, … on the hub; hub directory can tell clients
         other spokes’ keys so they can assign more local aliases.
```

When Machine A’s app sends traffic **to the hub alias** (default **10.0.0.2**),
the OS delivers it to `tun0`. nospoon **key-address**-encodes IPv4, adds length
framing, and sends on the **Noise** stream. The hub decodes and writes to its
`tun0` when the destination is the hub (or another path that is not a
forwarded spoke). Replies use the same machinery in reverse.

IPv4 on the wire uses **key-address** encoding (see `key-address.js`): IP
headers are translated to/from public keys inside the tunnel. IPv6 passes
through unchanged on the wire in the current design.


## Operating modes

### Hub / spoke (`startServer` + `createClient`)

One process runs **`startServer()`** from the **`nospoon`** package (the hub). Others run
**`createClient({ key: <hub-public-key-hex>, ... })`** and connect with HyperDHT to that
public key. In **open** mode the hub assigns incremental peer aliases
(`.2`, `.3`, …) in its `--ip` subnet and registers them in a key-address
table. **Authenticated** mode uses `--config` (`peers.json`) or positional
peer keys so only listed keys connect and each has a fixed alias IP.

The hub may **broadcast a directory** (see `hub-directory.js`) listing the
public keys of connected spokes. Clients use that list to assign **local**
aliases and register other spokes for **spoke-to-spoke** traffic—without a
global IP namespace.

### Topic mesh (`swarm`)

**`nospoon swarm <topic>`** joins a **Hyperswarm** topic derived from the
shared topic bytes. **Discovery key:** **`swarmDiscoveryKey`** in `swarm-topic.js`
uses **hypercore-crypto**’s `hash` (BLAKE2b) over a **`nospoon`** domain label plus
the topic bytes — a 32-byte value for **`swarm.join`**, so the **raw topic is not
advertised on the DHT** as UTF-8. **Authentication:** after the **Noise** handshake,
peers exchange a **hypercore-style capability** (keyed by the handshake hash, same
pattern as replicate caps) proving possession of the **topic preimage**; mismatch
destroys the connection. Each pairwise stream is still **Noise-encrypted** for
payloads. There is no separate hub: every participant runs the same mesh logic.
**One topic per process**, **pairwise** IPv4 forwarding only (no application-level
relay of tun frames through a third peer). Mappings from public key to local IPv4
alias are **ephemeral** for now (no persistence across restarts).

### Default IPv4 (`startServer`, `createClient`, `swarm`)

Unless **`ip`** is set, **`cli.js`** (for **`swarm`**) and **`createClient`** read addresses on local interfaces
(`collectAssignedIpv4Addresses`) and pick the first free **`10.0.n.1/24`** in
`10.0.0.0/16`. For **`createClient`**, the hub alias is **`10.0.n.2`** for the same `n`.
**Exception:** **`startServer({ config })`** without **`ip`** skips this scan
and uses **`10.0.0.1/24`** so `peers.json` IPs in that subnet stay valid. **`peerIp`**
without **`ip`** is an error (explicit subnet required).


## File Map

```
bin/
  cli.js              CLI: default control plane, swarm, genkey; default IPv4 pick for swarm; validation

lib/
  server.js           HyperDHT server, TUN, key-address, hub directory broadcast
  client.js           HyperDHT client, TUN, hub directory apply, auto-reconnect
  swarm-topic.js      Discovery key (BLAKE2b) + post-handshake topic capability
  swarm-mesh.js       Hyperswarm topic mesh: TUN, pairwise key-address, topic auth
  key-address.js      IPv4/IPv6 key-address wire encode/decode; key ↔ alias maps
  hub-directory.js    In-band hub peer-list frames (JSON) for spoke discovery
  ip-subnet.js        Subnet math, peer IP allocator, free 10.0.x.1 scan
  framing.js          Length-prefix framing; keepalives
  routing.js          readSourceIp / readDestinationIp; router (key → connection)
  tun.js              Platform dispatcher (tun-linux or tun-darwin)
  tun-linux.js        Linux TUN via /dev/net/tun + ioctl + ip(8)
  tun-darwin.js       macOS utun via PF_SYSTEM + ifconfig + route
  full-tunnel.js      Platform dispatcher (full-tunnel-linux or -darwin)
  full-tunnel-linux.js   Linux: iptables NAT, split routes, rp_filter
  full-tunnel-darwin.js  macOS: pfctl NAT, split routes

test/
  key-address.test.js   Key-address round-trip; unwrap null on stale peer
  hub-directory.test.js Directory frame magic + JSON round-trip
  ip-subnet.test.js     Auto 10.0.x.1 picking
  swarm-mesh.test.js    swarmDiscoveryKey helper
  swarm-topic.test.js   Topic capability role symmetry
```


## How a Connection Works (Step by Step)

### 1. Server starts

```
node hub.js   # script that calls startServer({ config: 'peers.json' })
```

1. Your entrypoint (or tests) calls `startServer(opts)` with optional `ip` / `config` / `seed` / etc.
2. `startServer()` generates a key pair from a random seed (or `opts.seed`)
3. Creates a TUN via `createTunDevice()` — assigns IP, sets MTU
4. Creates a `router` and, in open or allowlist hub mode, a **key-address**
   table plus peer IP allocator / hub directory state as needed
5. Loads `peers.json` if provided — validates IPs against the server subnet
6. Creates a HyperDHT server with a `firewall` callback
7. Listens on the DHT — the server is discoverable by its public key

### 2. Client connects

```
node client.js   # script that calls createClient({ key, seed, ... })
```

1. Your entrypoint calls `createClient(opts)` (or `startClient` for CLI-style signal handling), applying default IPv4 unless `ip` is set
2. Creates a TUN (e.g. first free `10.0.x.1/24` with hub at `10.0.x.2`, or explicit `ip` / `peerIp`)
3. Calls `dht.connect(serverPublicKey)` — NAT traversal, Noise stream
4. The server's `firewall` runs (auth vs open)
5. On `open`, client registers the hub key at the local alias IP, may apply
   hub directory updates for other spokes

### 3. Packets flow

**Client -> Server (IPv4 key-address):**
1. App on client sends packet to the hub alias (e.g. 10.0.0.2 in open mode with `peerIp`)
2. OS routes it to tun0 (because 10.0.0.0/24 is routed there)
3. `tun.on('data')` fires in `client.js` with the raw IPv4 packet
4. Client calls `wrapTunnelPayload(ka, packet)` — replaces IPv4 header src/dst with
   wire key material (`key-address.js`), then `encode()` prepends the 4-byte length
5. Client writes the frame to the DHT connection (Noise-encrypted stream)
6. Server receives data; `createDecoder` reassembles the frame; directory frames
   (if any) are skipped before tunnel decode
7. Server calls `unwrapTunnelPayload` → `ka.decode` to recover a normal IPv4 packet
8. Server validates source IP matches this client's assigned alias (open or auth mode)
9. Server reads the destination IP; `router.getConnectionForDestination` uses the
   key-address table to map dest IP → peer key → live connection:
   - If dest is another client: forward on that connection (re-wrap with `wrapTunnelPayload`)
   - Else: write to the server's TUN (hub or external path)
10. OS on server delivers the packet to the destination app

**Server -> Client:** Same pipeline in reverse: TUN read → map dest IP to client
connection → length frame → client unwraps → TUN write.

**Stale peers:** After a peer disconnects, their key is unregistered. Any in-flight
IPv4 frame that still references that key cannot be decoded; `unwrapTunnelPayload`
returns `null` and the frame is dropped (no process crash).

**IPv6:** Not key-address wrapped; passes through the tunnel as raw IPv6 packets.


## Core Modules in Detail


### framing.js — Length-Prefix Framing

**Why it exists:** DHT streams are byte streams (like TCP). If you write
two 100-byte packets, the other side might receive one 200-byte chunk,
or three chunks of 80+70+50 bytes. Framing ensures each IP packet is
delivered as a complete unit.

**Format:** Each frame is `[4-byte big-endian length][payload]`

```
encode(packet)
```
Takes a Buffer, returns a new Buffer with 4-byte length header prepended.

```
createDecoder(onPacket)
```
Returns a `push(chunk)` function. Feed it arbitrary chunks of data and it
will call `onPacket(packet)` for each complete frame. Handles:
- **Split frames**: a packet arrives in multiple chunks
- **Merged frames**: multiple packets arrive in one chunk
- **Keepalives**: length=0 frames are silently ignored
- **Overflow protection**: if the internal buffer exceeds 256KB, it's reset
- **Invalid lengths**: frames claiming >65535 bytes are dropped

**Multiplexing (hub only):** Frames whose payload is **not** a normal IPv4/IPv6
packet may carry side channels. The hub directory uses a payload that begins
with bytes **`0x00 0x01`** (invalid as IPv4/IPv6 first byte), followed by UTF-8
JSON listing peer public keys (`hub-directory.js`). The server never decodes
these as tunnel traffic; clients consume them to register spoke aliases.

```
startKeepalive(connection)
```
Sends a zero-length frame every 25 seconds to keep the connection alive.
NATs and firewalls drop idle UDP mappings; keepalives prevent that.


### routing.js — Packet Parser + Route Table

**`readSourceIp(packet)`** / **`readDestinationIp(packet)`**

Read the source or destination IP address from a raw IP packet's header.
Works for both IPv4 and IPv6:

```
IPv4 header (20 bytes minimum):
  Byte 0:    Version (4 bits) + Header Length (4 bits)
  Bytes 12-15: Source IP
  Bytes 16-19: Destination IP

IPv6 header (40 bytes minimum):
  Byte 0:    Version (4 bits) + Traffic Class
  Bytes 8-23:  Source IP (16 bytes)
  Bytes 24-39: Destination IP (16 bytes)
```

The version is extracted from the first 4 bits: `(packet[0] >>> 4) & 0x0f`
- Version 4 = IPv4
- Version 6 = IPv6

**`createRouter()`**

Returns an object with a Map **`remotePublicKeyHex → HyperDHT/Noise connection`**:
- `addPeer(publicKey, connection)` — register a client for forwarding
- `removePeer(publicKey)` — unregister when the stream closes
- `getConnectionForDestination(destIp, ctx)` — uses `ctx.ka` (key-address table)
  or `ctx.ipToKeyHex` (auth mode) to resolve destination IP to a peer key, then
  looks up the live connection. Packets to the local key return `null` so they
  are not mistaken for remote peers.
- `activeCount()` — number of routed peers

Subnet math and peer **IP allocation** live in **`ip-subnet.js`**, not here.


### server.js — The Server

**`loadPeers(configPath, serverCidr)`** — Reads peers.json, validates:
- Each key is a 64-char hex public key
- Each IP is valid IPv4 or IPv6
- No duplicate IPs
- No 0.0.0.0, no loopback (127.x.x.x)
- IP must be in server's subnet (not network address, not broadcast, not
  server's own IP)

Returns a `Map<publicKeyHex, ipAddress>`.

**Open mode (`--config` absent and no fixed peer map):** builds a
`createKeyAddressTable` for the hub and a **`createPeerIpAllocator`** from
`ip-subnet.js` to hand out `.2`, `.3`, … in the hub subnet. Each new
connection registers that alias and the client's public key **before** any
tunnel decode. **`broadcastHubDirectory()`** pushes an updated peer list to
all hub connections when someone joins or leaves.

**`startServer(opts)`** — Main flow:

1. **Firewall callback**: HyperDHT handshake filter. Return `true` to reject.
   Open mode allows all; `--config` / allowlist restricts by public key.

2. **Connection handler**:
   - **Auth** (`peers.json` or allowlist with fixed IPs): assign IP from config,
     add to router and key-address path as implemented.
   - **Open**: allocate next free alias IP, `ka.register`, `router.addPeer`,
     join hub directory set, broadcast directory.

3. **Inbound tunnel decoder**: Skip directory frames; `unwrapTunnelPayload`;
   verify source IP equals this connection's assigned alias; forward to peer
   or TUN.

4. **TUN → clients**: `readDestinationIp` + `getConnectionForDestination`;
   `wrapTunnelPayload` + length frame to the right connection.


### client.js — The Client

**Key-address:** On connect, builds a key-address table with local TUN IP and
registers the **hub** at **`peerIp`** (default **`10.0.n.2`** when defaults picked
**`10.0.n.1/24`**, or **`10.0.0.2`** when using explicit **`10.0.0.1/24`**).

**Hub directory:** When a directory frame arrives, `applyHubDirectory`
allocates unused aliases in the same subnet and registers other spokes' keys
so IPv4 can reach them (local aliasing; logs `Hub directory: spoke peer …`).

**Auto-reconnect:** Exponential backoff (1s → 30s cap) with jitter.

**Full DHT restart:** After repeated failures in full-tunnel mode, destroys
the DHT and reconnects so lookups are not stuck behind a dead tunnel route.

### key-address.js — Wire format (summary)

IPv4 on the wire embeds 32-byte Noise public keys for source and destination
instead of raw IPv4 addresses in the outer frame; decode restores a normal
IPv4 packet for the kernel. IPv6 uses a similar key header layout for the
encode path; **tunnel `unwrap` passes IPv6 through without key decode** in
the current hub/client/swarm paths (first nibble `6`).

### hub-directory.js

Encodes/decodes **directory** payloads: magic `0x00 0x01` + JSON
`{ "v": 1, "peers": [ { "k": "<hex>" }, … ] }` (sorted unique keys). Used only
in hub open mode for spoke discovery.

### ip-subnet.js

**`parseSubnet`**, **`ipToInt`**, **`intToIp`**, **`createPeerIpAllocator`**
(lowest free host in subnet, skipping the TUN host address by default), plus
**`collectAssignedIpv4Addresses`** and **`pickFreeTenDotZeroSubnet`** for the
CLI default IPv4 path.

### swarm-mesh.js — Topic mesh

**`startSwarmMesh`** normalizes topic bytes, computes **`discoveryKey` =
`swarmDiscoveryKey(topicSecret)`**, creates **`Hyperswarm`**, **`await swarm.listen()`**,
**`swarm.join(discoveryKey)`**, **`await discovery.flushed()`**. Each **`connection`**
awaits **`handshake`** (for **`handshakeHash`**), runs **topic capability** exchange
on the first framed payload (initiator sends first), then **`router.addPeer`** and
tunnel traffic. Peer IP allocation, **`ka.register`**, length decoder,
**`unwrapTunnelPayload` / `wrapTunnelPayload`**, TUN read/write — **pairwise only**.
Reuses an alias IP when the same peer reconnects. **`attachConnErrorHandler`**
registers an `error` listener on each **`NoiseSecretStream`**. **`safeWrite`**
avoids synchronous throws when forwarding to a closing peer.


## TUN Device — How It Works

A TUN (network TUNnel) device is a virtual network interface. Instead of
being backed by a physical network card, it's backed by a file descriptor.
Programs read/write raw IP packets on that fd, and the OS treats them as if
they came from a real interface.

### Linux (tun-linux.js)

```
Step 1: Open /dev/net/tun
  fd = fs.openSync('/dev/net/tun', 'r+')

Step 2: Create the interface via ioctl
  - Build a struct ifreq (40 bytes):
    - First 16 bytes: interface name (e.g. "tun0", null-padded)
    - Bytes 16-17: flags = IFF_TUN | IFF_NO_PI
  - Call ioctl(fd, TUNSETIFF, &ifreq)
  - The kernel creates the tun0 interface

Step 3: Configure with ip commands
  ip addr add 10.0.0.1/24 dev tun0
  ip link set tun0 mtu 1400
  ip link set tun0 up

Step 4: Read/write packets
  - fs.createReadStream on the fd -> emits IP packets
  - fs.createWriteStream on the fd -> accepts IP packets
```

**IFF_TUN** = Layer 3 (IP packets only, no Ethernet headers)
**IFF_NO_PI** = No "packet information" header (just raw IP)

**koffi** is an FFI (Foreign Function Interface) library. It lets JavaScript
call C functions in shared libraries (like libc). We use it to call `ioctl`
because Node.js doesn't have a built-in way to do that.

### macOS (tun-darwin.js)

macOS doesn't have `/dev/net/tun`. Instead it uses "utun" interfaces
created through a kernel control socket.

```
Step 1: Create a PF_SYSTEM socket
  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)

  PF_SYSTEM (32) is a special socket family for kernel control.
  This is completely different from normal sockets (PF_INET = 2).

Step 2: Get the control ID for utun
  - Build a struct ctl_info (100 bytes):
    - Bytes 0-3: ctl_id (output, filled by kernel)
    - Bytes 4-99: ctl_name = "com.apple.net.utun_control"
  - Call ioctl(fd, CTLIOCGINFO, &ctl_info)
  - The kernel fills in ctl_id (e.g. 5)

  CTLIOCGINFO = 0xc0644e03, computed from:
    _IOWR('N', 3, struct ctl_info)
    = IOC_INOUT | (sizeof(ctl_info) << 16) | ('N' << 8) | 3
    = 0xc0000000 | (100 << 16) | (0x4e << 8) | 3

Step 3: Connect to create the interface
  - Build a struct sockaddr_ctl (32 bytes):
    - Byte 0:  sc_len = 32
    - Byte 1:  sc_family = PF_SYSTEM (32)
    - Bytes 2-3: ss_sysaddr = AF_SYS_CONTROL (2)
    - Bytes 4-7: sc_id = the ctl_id from step 2
    - Bytes 8-11: sc_unit = 0 (auto-assign)
  - Call connect(fd, &addr, 32)
  - The kernel creates utun0 (or utun1, utun2, etc.)

Step 4: Get the assigned name
  getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, nameBuf, &len)

Step 5: Configure with ifconfig
  ifconfig utun0 inet 10.0.0.1 10.0.0.1 netmask 255.255.255.0
  ifconfig utun0 mtu 1400 up
  route add -net 10.0.0.1/24 -interface utun0
```

**The 4-byte AF header:**

macOS utun prepends 4 bytes to every packet indicating the protocol family:
- `00 00 00 02` = AF_INET (IPv4)
- `00 00 00 1e` = AF_INET6 (IPv6)

This is NOT part of the IP packet. nospoon strips it on read and prepends
it on write, so the rest of the code sees the same raw IP packets as Linux.

```
macOS utun packet:  [AF_INET][IP header][payload]
                     4 bytes   20+ bytes
After stripping:    [IP header][payload]
                     20+ bytes
Same as Linux TUN.
```


## Full Tunnel — Routing All Traffic Through the VPN

Without `--full-tunnel`, only traffic to the VPN subnet (e.g. 10.0.0.0/24)
goes through the tunnel. With it, ALL internet traffic goes through.

### The Split Route Trick

You can't just delete the default route and add a new one pointing to the
TUN — that would kill the DHT connection itself (which needs the real
internet to reach the server).

Instead, nospoon uses the same trick as OpenVPN:

```
1. Add a host route for the DHT server via the real gateway
   (most specific route wins — /32 beats everything)

2. Add two routes that together cover all IPv4 addresses:
   0.0.0.0/1     -> tun0   (covers 0.0.0.0 - 127.255.255.255)
   128.0.0.0/1   -> tun0   (covers 128.0.0.0 - 255.255.255.255)

   These /1 routes are more specific than the default route (0.0.0.0/0),
   so they win. But the /32 host route is even more specific, so DHT
   traffic to the server still goes direct.
```

**Kill switch:** If the tunnel drops, the /1 routes still point to tun0.
Traffic can't go anywhere except through the (dead) tunnel. Nothing leaks.
The DHT host route remains, so the client can reconnect.

### Linux (full-tunnel-linux.js)

```
Enable:
  sysctl -w net.ipv4.conf.all.rp_filter=2     # loosen reverse path filter
  ip route add <server-ip>/32 via <gateway> dev <real-interface>
  ip route add 0.0.0.0/1 dev tun0
  ip route add 128.0.0.0/1 dev tun0

Disable (cleanup):
  ip route del 128.0.0.0/1 dev tun0
  ip route del 0.0.0.0/1 dev tun0
  ip route del <server-ip>/32 via <gateway>
  sysctl -w net.ipv4.conf.all.rp_filter=<original-value>

Server NAT (iptables):
  sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
  iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
  iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**rp_filter** (reverse path filtering): Linux checks if an incoming
packet's source IP would be routed back out the same interface. With a
VPN this check fails (packets from 10.0.0.2 arrive on tun0 but the
kernel might think they should come from eth0). Setting it to 2 (loose
mode) fixes this. macOS doesn't have rp_filter.

### macOS (full-tunnel-darwin.js)

```
Enable:
  route add -host <server-ip> <gateway>
  route add -net 0.0.0.0/1 -interface utun0
  route add -net 128.0.0.0/1 -interface utun0

Disable (cleanup):
  route delete -net 128.0.0.0/1 -interface utun0
  route delete -net 0.0.0.0/1 -interface utun0
  route delete -host <server-ip> <gateway>

Server NAT (pfctl):
  sysctl -w net.inet.ip.forwarding=1
  # Inject rules into main pf.conf (see "macOS pfctl gotcha" below)
```

**Gateway detection:**
- Linux: `ip route show default` -> parse "via x.x.x.x dev ethN"
- macOS: `route -n get default` -> parse "gateway: x.x.x.x" and
  "interface: enN"


## Platform Differences Summary

| Feature | Linux | macOS |
|---------|-------|-------|
| TUN creation | `/dev/net/tun` + `ioctl(TUNSETIFF)` | `PF_SYSTEM` socket + `ioctl(CTLIOCGINFO)` + `connect()` |
| TUN name | `tun0` (user-chosen) | `utun0` (kernel-assigned) |
| Packet format | Raw IP | 4-byte AF header + raw IP |
| Interface config | `ip addr`, `ip link` | `ifconfig` |
| Routing | `ip route add/del` | `route add/delete` |
| NAT | `iptables -t nat MASQUERADE` | `pfctl` (main ruleset injection) |
| IP forwarding | `net.ipv4.ip_forward=1` | `net.inet.ip.forwarding=1` |
| Reverse path filter | `rp_filter=2` (must loosen) | Not applicable |
| C library | `libc.so.6` | `libSystem.B.dylib` |
| ioctl call | Regular function | Must be declared variadic (`...`) |
| Struct byte order | Little-endian (x86_64) | Little-endian (both x86_64 and ARM64) |

The platform dispatchers (`tun.js`, `full-tunnel.js`) check `os.platform()`
and load the right module. Everything above them (`server.js`, `client.js`,
`swarm-mesh.js`, `framing.js`, `routing.js`, `key-address.js`) is
platform-independent aside from OS privileges for TUN and routes.


## Bugs We Found on Real macOS Hardware

These three bugs were impossible to catch without testing on a real Mac.
All unit tests passed on Linux.

### Bug 1: ioctl Variadic Calling Convention (ARM64)

**Symptom:** `ioctl(CTLIOCGINFO)` returned EFAULT (errno 14 = bad address)

**Root cause:** On ARM64 (Apple Silicon), the C calling convention for
variadic functions is DIFFERENT from regular functions. Regular function
arguments go in registers (x0-x7). Variadic arguments go on the stack.

`ioctl` is declared as: `int ioctl(int fd, unsigned long request, ...)`

The `...` makes it variadic. When koffi declared it as a regular 3-parameter
function (`void *argp`), it passed the third argument in register x2. But
the ioctl implementation expected it on the stack. The kernel read garbage
from the stack and returned EFAULT.

On x86_64, variadic and non-variadic use the same calling convention, so
this bug would never appear on Intel Macs or Linux.

**Fix:** Declare with `...` and pass the type annotation when calling:
```javascript
// Before (broken on ARM64):
const ioctlFn = libc.func('int ioctl(int fd, unsigned long request, void *argp)')
ioctlFn(fd, CTLIOCGINFO, buffer)

// After (works everywhere):
const ioctlFn = libc.func('int ioctl(int fd, unsigned long request, ...)')
ioctlFn(fd, CTLIOCGINFO, 'void *', buffer)
```

### Bug 2: sockaddr_ctl Endianness

**Symptom:** `connect()` failed after ioctl succeeded

**Root cause:** The code used `writeUInt32BE` (big-endian) to fill the
`sockaddr_ctl` struct, but ARM64 (and x86_64) are little-endian. The
kernel read the ctl_id as 0x05000000 instead of 5.

**Fix:** Use `writeUInt32LE` and `writeUInt16LE` for all struct fields.

### Bug 3: pfctl NAT Anchors Don't Work for Forwarded Packets

**Symptom:** NAT rule loaded, IP forwarding enabled, packets forwarded
to en0, but source IP not translated (still 10.0.0.2 instead of the
server's public IP). No reply packets ever came back.

**Root cause:** macOS pf evaluates the main ruleset anchors (`com.apple/*`)
but custom anchors loaded with `pfctl -a nospoon -f rules` are not in the
forwarding path. The NAT rule matched (high match count in stats) but
never created state entries (inserts: 0).

**Fix:** Instead of using a named anchor, read `/etc/pf.conf`, inject the
NAT and pass rules directly into the main ruleset, and load the modified
version with `pfctl -f`. On shutdown, restore the original `/etc/pf.conf`.


## Security Model

### Encryption
All DHT streams use **Noise** (via HyperDHT / Hyperswarm). Payloads on the
wire are encrypted; no application plaintext crosses the internet on those
streams.

### Authentication (Hub — Authenticated Mode)
- `peers.json` or allowlist maps public keys to fixed alias IPs
- `firewall` rejects unknown keys before the session is useful
- Per-packet source IP must match the assigned alias (spoofing resistance)

### Open Hub Mode
- Anyone who knows the hub **public key** can connect; the hub assigns
  incremental **alias IPs** in its subnet (`.2`, `.3`, …)
- **Hub directory** lists connected spoke keys; clients **trust the hub**
  for those registrations when creating local aliases for other spokes
  (same trust model as “I joined this hub”)

### Topic Mesh (`swarm`)
- **Discovery:** 32-byte **discovery key** (BLAKE2b over domain + topic bytes) is
  what Hyperswarm advertises; passive observers do not see the raw topic string
- **Membership:** after Noise, peers prove possession of the **topic preimage** via
  a keyed capability; wrong preimage drops the connection
- Pairwise streams are still Noise-encrypted for tunnel payloads (no extra allowlist)

### Subnet Validation (`peers.json`)
Peer IPs are validated against the server's CIDR (network/broadcast,
server IP, loopback, etc.); see `loadPeers` in `server.js`.
