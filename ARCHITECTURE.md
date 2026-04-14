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

**Swarm / control plane:** each participating host has a TUN (often first free
**`10.0.x.1/24`** unless **`--ip`** fixes the subnet). IPv4 between peers uses
**key-address** on the wire inside **length-prefixed** frames on **Noise**
streams (pairwise in **`mesh/swarm-mesh`**, or via the shared swarm + direct pool in
**`control/control-http.js`**).

IPv4 on the wire uses **key-address** encoding (see `mesh/key-address.js`): IP
headers are translated to/from public keys inside the tunnel. IPv6 passes
through unchanged on the wire in the current design.


## Operating modes

### Topic mesh

The HTTP control plane joins **Hyperswarm** topics via **`startSwarmMesh`** in
`mesh/swarm-mesh.js` (shared swarm in **`control/control-http.js`**), using the same
crypto as a standalone topic mesh would. **Discovery key:** **`swarmDiscoveryKey`** in
`mesh/swarm-topic.js` uses **hypercore-crypto**’s `hash` (BLAKE2b) over a **`nospoon`**
domain label plus the topic bytes — a 32-byte value for **`swarm.join`**, so the
**raw topic is not advertised on the DHT** as UTF-8. **Authentication:** after the
**Noise** handshake, peers exchange a **hypercore-style capability** (keyed by the
handshake hash, same pattern as replicate caps) proving possession of the **topic
preimage**; mismatch destroys the connection. Each pairwise stream is still
**Noise-encrypted** for payloads. There is no separate hub: every participant runs the
same mesh logic. **Pairwise** IPv4 forwarding only (no application-level relay of tun
frames through a third peer). Mappings from public key to local IPv4 alias are
**ephemeral** for now (no persistence across restarts).

### Default IPv4 (control plane TUN)

The control plane picks a **primary** IPv4 CIDR with **`pickFreeTenDotZeroSubnet`** over
assigned addresses (see **`control/control-http.js`** and **`ip/ip-subnet.js`**), or
**`--primary-cidr`** / reservations override that default.


## File Map

```
bin/
  cli.js              CLI: default control plane, genkey; flag validation

lib/
  index.js            Public package API (re-exports submodules)
  web.bundle.js       Built control-panel UI (esbuild)
  web.bundle.css      Control-panel styles

  control/
    control-http.js        `ControlPlaneSessionManager` + `startControlHttpServer` (core session lifecycle, bind, URLs)
    control-constants.js   Shared control-plane constants (debounce intervals, panel DNS host)
    control-session-dns.js  Prototype mixin: mesh DNS, loopback aliases, whois proxy, manual records
    control-session-policy.js  Prototype mixin: primary full-tunnel OS sync, routing policy helpers
    control-session-swarm.js  Prototype mixin: shared Hyperswarm, topic discovery, inbound demux
    control-helpers.js     Control-only helpers (CIDR validation, seed/DNS opts, swarm discovery checks)
    control-http-io.js     HTTP response helpers, static HTML, web bundle paths, first-frame reader
    control-http-handler.js  `createControlHttpListener` — REST + SSE + whois routes

  mesh/
    swarm-topic.js    Discovery key (BLAKE2b) + post-handshake topic capability
    swarm-mesh.js     Hyperswarm topic mesh: TUN, pairwise key-address, topic auth
    key-address.js    IPv4/IPv6 key-address wire encode/decode; key ↔ alias maps
    shared-swarm-inbound.js  Shared Hyperswarm stream framing + tunnel routing
    mesh-ip-reservations.js  Stable mesh IPv4 reservations per key/topic
    direct-pool.js    Hyperswarm joinPeer + TUN + IPv4 pool (direct key dials)

  wire/
    framing.js        Length-prefix framing; keepalives
    key-encoding.js   Hex / z32 helpers for keys
    mesh-identifier.js Storage keys for mesh identifiers
    tcp-ipv4.js       IPv4 TCP header parse/build (tests / helpers)

  route/
    routing.js        readSourceIp / readDestinationIp; router (key → connection)
    routing-policy.js Interface / peer routing policy presets

  ip/
    ip-subnet.js      Subnet math, peer IP allocator, free 10.0.x.1 scan

  tun/
    tun.js            Platform dispatcher (tun-linux or tun-darwin)
    tun-linux.js      Linux TUN via /dev/net/tun + ioctl + ip(8)
    tun-darwin.js     macOS utun via PF_SYSTEM + ifconfig + route
    full-tunnel.js    Platform dispatcher (full-tunnel-linux or -darwin)
    full-tunnel-linux.js   Linux: iptables NAT, split routes, rp_filter
    full-tunnel-darwin.js  macOS: pfctl NAT, split routes

  dns/
    dns-server.js     Embedded DNS for mesh names + forwarding
    dns-mesh-name.js  FQDN ↔ key / topic DNS labels
    dns-manual-registry.js  Static manual records
    dns-loopback-aliases.js Loopback alias setup for control panel host
    dns-system-override.js (+ -darwin / -linux)  Temporary resolver override
    dns-restore-merge.js   Merge resolv.conf backups
    dns-cache-flush.js       Flush OS resolver cache
    whois-auth-proxy.js      HTTP proxy for whois API paths

  identity/
    identity.js  Persisted client seed (control plane Noise identity)

test/
  key-address.test.js   Key-address round-trip; unwrap null on stale peer / non-IP nibble
  ip-subnet.test.js     Auto 10.0.x.1 picking
  swarm-mesh.test.js    swarmDiscoveryKey helper
  swarm-topic.test.js   Topic capability role symmetry
```


## How a Connection Works

Step-by-step **hub (`server`) / spoke (`client`)** flows lived in older trees (`lib/server.js`, `lib/client.js`). **Swarm** and the **HTTP control plane** still use the same **length framing**, **key-address** IPv4 encoding (`mesh/key-address.js`), and **TUN** pipeline described under **Core Modules** below. For swarm, see `mesh/swarm-mesh.js` and the topic capability in `mesh/swarm-topic.js`.


## Core Modules in Detail


### wire/framing.js — Length-Prefix Framing

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

```
startKeepalive(connection)
```
Sends a zero-length frame every 25 seconds to keep the connection alive.
NATs and firewalls drop idle UDP mappings; keepalives prevent that.


### route/routing.js — Packet Parser + Route Table

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

Subnet math and peer **IP allocation** live in **`ip/ip-subnet.js`**, not here.


### mesh/key-address.js — Wire format (summary)

IPv4 on the wire embeds 32-byte Noise public keys for source and destination
instead of raw IPv4 addresses in the outer frame; decode restores a normal
IPv4 packet for the kernel. IPv6 uses a similar key header layout for the
encode path; **tunnel `unwrap` passes IPv6 through without key decode** in
the current swarm / control-plane paths (first nibble `6`). Buffers whose first
nibble is neither IPv4 nor IPv6 (in-band control, legacy frames) return **`null`**
from **`unwrapTunnelPayload`** so callers do not **`tun.write`** them (Linux **`EINVAL`**).

### ip/ip-subnet.js

**`parseSubnet`**, **`ipToInt`**, **`intToIp`**, **`createPeerIpAllocator`**
(lowest free host in subnet, skipping the TUN host address by default), plus
**`collectAssignedIpv4Addresses`** and **`pickFreeTenDotZeroSubnet`** for the
CLI default IPv4 path.

### mesh/swarm-mesh.js — Topic mesh

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
  - Writes use fs.writeSync in a loop (not WriteStream) so a kernel EINVAL on
    bad payloads does not surface as an unhandled stream error
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

The platform dispatchers (`tun/tun.js`, `tun/full-tunnel.js`) check `os.platform()`
and load the right module. **`mesh/swarm-mesh.js`**, **`wire/framing.js`**, **`route/routing.js`**, and **`mesh/key-address.js`** are platform-independent aside from OS privileges for TUN and routes.


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

### Topic Mesh (`swarm`)
- **Discovery:** 32-byte **discovery key** (BLAKE2b over domain + topic bytes) is
  what Hyperswarm advertises; passive observers do not see the raw topic string
- **Membership:** after Noise, peers prove possession of the **topic preimage** via
  a keyed capability; wrong preimage drops the connection
- Pairwise streams are still Noise-encrypted for tunnel payloads (no extra allowlist)

### Historical hub / spoke VPN
Authenticated hub (`peers.json`, allowlist) and open-hub behavior were documented
alongside **`server.js`** / **`client.js`** in older revisions. That code path is no
longer in this tree.
