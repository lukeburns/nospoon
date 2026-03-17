const fs = require('fs')
const { execFileSync } = require('child_process')
const koffi = require('koffi')

// Load system library
const libc = koffi.load('libSystem.B.dylib')
const socketFn = libc.func('int socket(int domain, int type, int protocol)')
const connectFn = libc.func('int connect(int sockfd, void *addr, unsigned int addrlen)')
const ioctlFn = libc.func('int ioctl(int fd, unsigned long request, void *argp)')
const getsockoptFn = libc.func('int getsockopt(int sockfd, int level, int optname, void *optval, void *optlen)')

// macOS constants for utun
const PF_SYSTEM = 32
const SOCK_DGRAM = 2
const SYSPROTO_CONTROL = 2
const AF_SYS_CONTROL = 2
const CTLIOCGINFO = 0xc0644e03
const UTUN_OPT_IFNAME = 2
const UTUN_CONTROL_NAME = 'com.apple.net.utun_control'

// struct ctl_info: { u_int32_t ctl_id (4 bytes); char ctl_name[96] (96 bytes) } = 100 bytes
const CTL_INFO_SIZE = 100
// struct sockaddr_ctl: 32 bytes total
const SOCKADDR_CTL_SIZE = 32

// macOS utun prepends a 4-byte protocol family header to each packet
const AF_INET = 2
const AF_INET6 = 30

function createUtunSocket () {
  const fd = socketFn(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
  if (fd < 0) {
    throw new Error('Failed to create PF_SYSTEM socket for utun')
  }

  // Get control ID for utun
  const ctlInfo = Buffer.alloc(CTL_INFO_SIZE)
  ctlInfo.write(UTUN_CONTROL_NAME, 4) // ctl_name starts at offset 4
  const ret = ioctlFn(fd, CTLIOCGINFO, ctlInfo)
  if (ret < 0) {
    fs.closeSync(fd)
    throw new Error('Failed to get utun control info (ioctl CTLIOCGINFO)')
  }
  const ctlId = ctlInfo.readUInt32LE(0)

  // Try to connect with auto-assigned unit (sc_unit = 0)
  const addr = Buffer.alloc(SOCKADDR_CTL_SIZE)
  addr[0] = SOCKADDR_CTL_SIZE // sc_len
  addr[1] = PF_SYSTEM         // sc_family
  addr.writeUInt16BE(AF_SYS_CONTROL, 2) // ss_sysaddr
  addr.writeUInt32BE(ctlId, 4)          // sc_id
  addr.writeUInt32BE(0, 8)              // sc_unit = 0 (auto-assign)

  const cret = connectFn(fd, addr, SOCKADDR_CTL_SIZE)
  if (cret < 0) {
    fs.closeSync(fd)
    throw new Error('Failed to create utun device (connect failed)')
  }

  // Get assigned interface name via getsockopt
  const nameBuf = Buffer.alloc(16)
  const lenBuf = Buffer.alloc(4)
  lenBuf.writeUInt32LE(16, 0)
  getsockoptFn(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, nameBuf, lenBuf)

  let end = nameBuf.indexOf(0)
  if (end < 0 || end > 16) end = 16
  const tunName = nameBuf.toString('utf-8', 0, end)

  return { fd, tunName }
}

function createTunDevice ({ name, ipv4, ipv6, mtu = 1400 }) {
  const { fd, tunName } = createUtunSocket()

  // Configure interface with ifconfig
  const ipAddr = ipv4.split('/')[0]
  const prefix = parseInt(ipv4.split('/')[1] || '24', 10)
  const netmask = prefixToNetmask(prefix)

  execFileSync('ifconfig', [tunName, 'inet', ipAddr, ipAddr, 'netmask', netmask])
  if (ipv6) {
    const v6Addr = ipv6.split('/')[0]
    const v6Prefix = ipv6.split('/')[1] || '64'
    execFileSync('ifconfig', [tunName, 'inet6', v6Addr, 'prefixlen', v6Prefix])
  }
  execFileSync('ifconfig', [tunName, 'mtu', String(mtu), 'up'])

  // Add subnet route
  execFileSync('route', ['add', '-net', ipv4, '-interface', tunName])

  // Packet I/O via Node.js streams on the utun fd
  const reader = fs.createReadStream('', { fd, autoClose: false })
  const writer = fs.createWriteStream('', {
    fd,
    autoClose: false,
    fs: {
      write: fs.write,
      open: function (_p, _f, _m, cb) { cb(null, fd) },
      close: function (_fd, cb) { cb(null) }
    }
  })

  // macOS utun prepends a 4-byte AF header to each packet.
  // We strip it on read and prepend it on write, so the rest
  // of the code works with raw IP packets (same as Linux).
  const { EventEmitter } = require('events')
  const tun = new EventEmitter()
  tun.name = tunName

  reader.on('data', function (data) {
    if (data.length <= 4) return
    // Strip 4-byte protocol family header
    tun.emit('data', data.subarray(4))
  })

  reader.on('error', function (err) {
    tun.emit('error', err)
  })

  tun.write = function (packet) {
    if (packet.length < 1) return false
    // Prepend 4-byte AF header based on IP version
    const version = (packet[0] >>> 4) & 0x0f
    const header = Buffer.alloc(4)
    header.writeUInt32BE(version === 6 ? AF_INET6 : AF_INET, 0)
    writer.write(Buffer.concat([header, packet]))
    return true
  }

  tun.release = function () {
    try { reader.destroy() } catch (e) {}
    try { writer.destroy() } catch (e) {}
    try { fs.closeSync(fd) } catch (e) {}
  }

  const addrs = ipv6 ? `${ipv4} + ${ipv6}` : ipv4
  console.log(`TUN device ${tunName} up with ${addrs} (MTU ${mtu})`)

  return tun
}

function prefixToNetmask (prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return [
    (mask >>> 24) & 0xff,
    (mask >>> 16) & 0xff,
    (mask >>> 8) & 0xff,
    mask & 0xff
  ].join('.')
}

module.exports = { createTunDevice }
