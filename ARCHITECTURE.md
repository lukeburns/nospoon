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

```
 Machine A                          Machine B
+-----------+                     +-----------+
|  App      |                     |  App      |
|  (curl)   |                     |  (nginx)  |
+-----+-----+                     +-----+-----+
      |                                 |
      | normal socket                   | normal socket
      |                                 |
+-----+-----+                     +-----+-----+
|  tun0     |                     |  tun0     |
| 10.0.0.2  |                     | 10.0.0.1  |
+-----+-----+                     +-----+-----+
      |                                 |
      | raw IP packets                  | raw IP packets
      |                                 |
+-----+-----+                     +-----+-----+
|  nospoon  |-------- DHT --------|  nospoon  |
|  client   |   encrypted stream  |  server   |
+-----------+                     +-----------+
```

When Machine A's curl sends a packet to 10.0.0.1, the OS routes it to tun0.
nospoon reads it, wraps it in a length-prefixed frame, sends it over the
encrypted DHT stream. The server receives it, unwraps it, writes it to its
tun0. The OS delivers it to nginx. The reply takes the reverse path.


## File Map

```
bin/
  cli.js              CLI entry point, argument parsing, validation

lib/
  server.js           DHT server, TUN device, packet routing between clients
  client.js           DHT client, auto-reconnect, TUN device
  framing.js          Length-prefix framing for packets over byte streams
  routing.js          IP packet parser + route table (ip -> connection)
  tun.js              Platform dispatcher (loads tun-linux or tun-darwin)
  tun-linux.js        Linux TUN via /dev/net/tun + ioctl
  tun-darwin.js       macOS TUN via utun kernel control socket
  full-tunnel.js      Platform dispatcher (loads full-tunnel-linux or -darwin)
  full-tunnel-linux.js   Linux: iptables NAT, ip route, rp_filter
  full-tunnel-darwin.js  macOS: pfctl NAT, route command, no rp_filter
  validation.js       Standalone validation functions (for testing)

test/
  routing.test.js     Tests for IP parsing and router
  framing.test.js     Tests for encode/decode, overflow, keepalives
  validation.test.js  Tests for input validation functions
  peers-config.test.js  Tests for peer config loading + subnet validation
  server-logic.test.js  Integration tests with mock connections
```


## How a Connection Works (Step by Step)

### 1. Server starts

```
sudo nospoon server --config peers.json
```

1. `cli.js` parses arguments, calls `startServer()` in `server.js`
2. `startServer()` generates a key pair from a random seed (or --seed)
3. Creates a TUN device via `createTunDevice()` — assigns IP, sets MTU
4. Creates a `router` — an in-memory map of `ip -> connection`
5. Loads `peers.json` if provided — validates IPs against the server subnet
6. Creates a HyperDHT server with a `firewall` callback
7. Listens on the DHT — the server is now discoverable by its public key

### 2. Client connects

```
sudo nospoon client <server-public-key> --seed <client-seed>
```

1. `cli.js` parses arguments, calls `startClient()` in `client.js`
2. Creates a TUN device (e.g. 10.0.0.2/24)
3. Calls `dht.connect(serverPublicKey)` — the DHT finds the server,
   punches through NATs, establishes an encrypted Noise stream
4. The server's `firewall` callback fires:
   - Authenticated mode: checks if the client's public key is in `peers.json`
   - Open mode: allows everyone
5. On success, the `connection` event fires on the server

### 3. Packets flow

**Client -> Server:**
1. App on client sends packet to 10.0.0.1
2. OS routes it to tun0 (because 10.0.0.0/24 is routed there)
3. `tun.on('data')` fires in client.js with the raw IP packet
4. Client calls `encode(packet)` — prepends 4-byte length header
5. Client writes the frame to the DHT connection (encrypted stream)
6. Server receives data, `decode()` reassembles the frame
7. Server reads the source IP from the packet header
8. Server validates the source IP (must match assigned IP in auth mode)
9. Server reads the destination IP:
   - If dest is another client: forward directly (client-to-client)
   - Otherwise: write to server's TUN (server or external destination)
10. OS on server delivers the packet to the destination app

**Server -> Client:**
1. Reply packet arrives on server's TUN
2. Server reads destination IP from packet header
3. Looks up the connection in the router (`router.getByIp()`)
4. Encodes and sends the frame over the DHT stream
5. Client decodes it and writes the raw packet to its TUN
6. OS delivers it to the app that sent the original request


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

Returns an object with a simple Map-based route table:
- `add(ip, connection)` — register a client
- `remove(ip)` — unregister a client
- `getByIp(ip)` — look up which connection owns an IP
- `getIpByKey(publicKeyHex)` — reverse lookup: find IP by public key
- `activeCount()` — how many clients are connected


### server.js — The Server

**`ipToInt(ip)`** — Converts "10.0.0.1" to a 32-bit integer for bitwise
subnet math.

**`parseSubnet(cidr)`** — Parses "10.0.0.1/24" into:
```
{
  hostIp:    167772161,  // 10.0.0.1 as integer
  network:   167772160,  // 10.0.0.0 (first address)
  broadcast: 167772415,  // 10.0.0.255 (last address)
  mask:      4294967040, // 255.255.255.0
  prefix:    24
}
```
Used to validate that peer IPs are within the server's subnet.

**`loadPeers(configPath, serverCidr)`** — Reads peers.json, validates:
- Each key is a 64-char hex public key
- Each IP is valid IPv4 or IPv6
- No duplicate IPs
- No 0.0.0.0, no loopback (127.x.x.x)
- IP must be in server's subnet (not network address, not broadcast, not
  server's own IP)

Returns a `Map<publicKeyHex, ipAddress>`.

**`startServer(opts)`** — The main function:

1. **Firewall callback**: Called by HyperDHT during the Noise handshake,
   BEFORE the connection is established. Returns `true` to reject (confusing
   but that's the API). In open mode, allows all. In auth mode, checks if
   the key is in the peers Map.

2. **Connection handler**: When a client connects:
   - Auth mode: immediately adds the client to the router with their
     assigned IP from peers.json
   - Open mode: waits for the first packet to learn the client's IP
     (IP learning)

3. **Packet handler** (inside the decoder callback):
   ```
   Authenticated mode:
     if source IP != assigned IP -> drop (prevents spoofing)

   Open mode:
     if no IP learned yet -> learn from first packet's source IP
       but first check: is this IP already taken? if yes -> drop
     if IP already learned and source != learned IP -> drop
   ```

4. **Routing**: After validation, reads destination IP:
   - Destination is another client? Forward directly (peer-to-peer)
   - Otherwise? Write to TUN (let the OS handle it)

5. **TUN -> clients**: When a packet arrives on the server's TUN, look up
   the destination IP in the router and send it to the right client.


### client.js — The Client

Simpler than the server. Key concepts:

**Auto-reconnect with exponential backoff:**
- Starts at 1 second, doubles each failure, caps at 30 seconds
- Adds random jitter (0-1s) to prevent thundering herd

**Full DHT restart:**
- After 3 consecutive failures, destroys the entire DHT instance and
  creates a new one
- Why? In full-tunnel mode, the split routes direct all traffic through
  tun0. If the tunnel is dead, DHT lookups (which go to random nodes on
  the internet) also go through the dead tunnel and fail. By removing the
  routes and restarting DHT, the client can reach the internet directly
  to find the server at its (possibly new) IP.

**`deriveRemoteIp(clientCidr)`** — Simple helper: if client is 10.0.0.2/24,
the server must be 10.0.0.1. Just replaces the last octet with 1.


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
and load the right module. Everything above them (server.js, client.js,
framing.js, routing.js) is platform-independent.


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
All traffic between peers is encrypted using the Noise protocol (built into
HyperDHT). This is the same protocol used by WireGuard. No plaintext ever
crosses the internet.

### Authentication (Authenticated Mode)
- Server has a `peers.json` mapping public keys to IPs
- `firewall` callback rejects unknown keys BEFORE the Noise handshake
  completes — the connection is never established
- Source IP validation: even after authentication, the server checks that
  each packet's source IP matches the assigned IP. A compromised client
  can't spoof another client's IP.

### Open Mode (Testing Only)
- No authentication — anyone who knows the public key can connect
- Single client only — IP learned from first packet, locked afterward
- IP collision protection — if a second client tries to claim the same IP,
  packets are dropped
- No automatic IP assignment — client must manually choose an unused IP

### Subnet Validation
Peer IPs in `peers.json` are validated against the server's CIDR:
- Must be in the same subnet
- Cannot be the network address (10.0.0.0)
- Cannot be the broadcast address (10.0.0.255)
- Cannot be the server's own IP
- Cannot be 0.0.0.0 or loopback (127.x.x.x)
