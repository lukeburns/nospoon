const fs = require('fs')
const { execFileSync } = require('child_process')
const koffi = require('koffi')

// Load libc and define ioctl
const libc = koffi.load('libc.so.6')
const ioctlFn = libc.func('int ioctl(int fd, unsigned long request, void *argp)')

// Linux TUN constants
const TUNSETIFF = 0x400454ca
const IFF_TUN = 0x0001
const IFF_NO_PI = 0x1000
const IFNAMSIZ = 16
const IFREQ_SIZE = 40

function createTunDevice ({ name, ipv4, ipv6, mtu = 1400 }) {
  // Open TUN clone device
  const fd = fs.openSync('/dev/net/tun', 'r+')

  // Build struct ifreq: name (16 bytes) + flags (2 bytes at offset 16)
  const ifr = Buffer.alloc(IFREQ_SIZE)
  if (name) {
    ifr.write(name, 0, Math.min(name.length, IFNAMSIZ - 1))
  }
  ifr.writeUInt16LE(IFF_TUN | IFF_NO_PI, IFNAMSIZ)

  // Register TUN device via ioctl
  const ret = ioctlFn(fd, TUNSETIFF, ifr)
  if (ret < 0) {
    fs.closeSync(fd)
    throw new Error('Failed to create TUN device (ioctl TUNSETIFF)')
  }

  // Read back assigned interface name (null-terminated)
  let end = ifr.indexOf(0)
  if (end < 0 || end > IFNAMSIZ) end = IFNAMSIZ
  const tunName = ifr.toString('utf-8', 0, end)

  // Configure via ip commands (replaces tuntap2's ioctls)
  execFileSync('ip', ['addr', 'add', ipv4, 'dev', tunName])
  if (ipv6) {
    execFileSync('ip', ['-6', 'addr', 'add', ipv6, 'dev', tunName])
  }
  execFileSync('ip', ['link', 'set', tunName, 'mtu', String(mtu)])
  execFileSync('ip', ['link', 'set', tunName, 'up'])

  // Packet I/O via standard Node.js streams on the TUN fd
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

  // Expose the same interface server.js/client.js expect:
  //   tun.on('data', cb), tun.write(buf), tun.release(), tun.name
  const tun = reader
  tun.name = tunName

  tun.write = function (data) {
    return writer.write(data)
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

module.exports = { createTunDevice }
