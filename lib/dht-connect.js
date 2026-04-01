'use strict'

/**
 * Same encrypted stream as `dht.connect(serverKey, { keyPair })` for nospoon framing.
 *
 * @param {import('hyperdht')} dht
 * @param {string} remoteKeyHex — 64 lowercase hex (32-byte remote public key)
 * @param {{ publicKey: Buffer, secretKey: Buffer }} keyPair
 * @returns {import('stream').Duplex & { destroy: function(): void, remotePublicKey: Buffer }}
 */
function connectAsClient (dht, remoteKeyHex, keyPair) {
  if (!dht || typeof dht.connect !== 'function') {
    throw new Error('connectAsClient: dht with .connect is required')
  }
  const h = String(remoteKeyHex).trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error('connectAsClient: expected 64 hex character remote key')
  }
  if (!keyPair || !keyPair.publicKey || !keyPair.secretKey) {
    throw new Error('connectAsClient: keyPair with publicKey and secretKey is required')
  }
  return dht.connect(Buffer.from(h, 'hex'), { keyPair })
}

module.exports = { connectAsClient }
