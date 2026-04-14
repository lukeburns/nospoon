// Length-prefix framing for TUN packets over a byte stream.
// Each frame: [4-byte big-endian length][payload]
// This prevents IP packets from merging or splitting over the stream.

function encode (packet) {
  const header = Buffer.allocUnsafe(4)
  header.writeUInt32BE(packet.length, 0)
  return Buffer.concat([header, packet])
}

const MAX_BUFFER_SIZE = 256 * 1024 // 256KB

function createDecoder (onPacket, onOverflow) {
  let buffer = Buffer.alloc(0)

  return function push (chunk) {
    buffer = Buffer.concat([buffer, chunk])

    // Prevent unbounded buffer growth
    if (buffer.length > MAX_BUFFER_SIZE) {
      buffer = Buffer.alloc(0)
      if (onOverflow) onOverflow()
      return
    }

    while (buffer.length >= 4) {
      const len = buffer.readUInt32BE(0)

      if (len > 65535) {
        buffer = Buffer.alloc(0)
        return
      }

      if (buffer.length < 4 + len) break

      const packet = buffer.subarray(4, 4 + len)
      buffer = buffer.subarray(4 + len)
      if (len > 0) onPacket(packet)
    }
  }
}

// Keepalive: a zero-length frame (just the 4-byte header with length=0).
// The decoder silently ignores zero-length packets.
const KEEPALIVE = Buffer.alloc(4, 0)

const KEEPALIVE_INTERVAL_MS = 25000

function startKeepalive (connection) {
  const interval = setInterval(function () {
    if (!connection.destroyed) {
      connection.write(KEEPALIVE)
    } else {
      clearInterval(interval)
    }
  }, KEEPALIVE_INTERVAL_MS)

  interval.unref()

  connection.on('close', function () {
    clearInterval(interval)
  })

  return interval
}

module.exports = { encode, createDecoder, startKeepalive }
