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

function createTunDevice ({ name, ipv4, ipv6, mtu = 1400, quiet = false }) {
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

  // Packet read via stream; writes use fs.writeSync so EINVAL from the kernel does not
  // become an unhandled WriteStream 'error' (would terminate the process).
  const reader = fs.createReadStream('', { fd, autoClose: false })
  reader.on('error', function (err) {
    console.error(
      '[nospoon tun]',
      tunName,
      'read:',
      err && err.message ? err.message : String(err)
    )
  })

  // Expose the same interface server.js/client.js expect:
  //   tun.on('data', cb), tun.write(buf), tun.release(), tun.name
  const tun = reader
  tun.name = tunName

  let tunWriteLogCount = 0
  tun.write = function (data) {
    let buf = Buffer.isBuffer(data) ? data : Buffer.from(data)
    let offset = 0
    try {
      while (offset < buf.length) {
        const n = fs.writeSync(fd, buf, offset, buf.length - offset)
        if (n <= 0) break
        offset += n
      }
      return offset === buf.length
    } catch (e) {
      tunWriteLogCount++
      if (tunWriteLogCount <= 5 || tunWriteLogCount % 200 === 0) {
        console.error(
          '[nospoon tun]',
          tunName,
          'write:',
          e && e.message ? e.message : String(e)
        )
      }
      return false
    }
  }

  tun.release = function () {
    try { reader.destroy() } catch (e) {}
    try { fs.closeSync(fd) } catch (e) {}
  }

  const addrs = ipv6 ? `${ipv4} + ${ipv6}` : ipv4
  if (!quiet) {
    console.log(`TUN device ${tunName} up with ${addrs} (MTU ${mtu})`)
  }

  return tun
}

module.exports = { createTunDevice }
