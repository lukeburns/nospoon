'use strict'

const fs = require('fs')
const path = require('path')
const os = require('os')
const crypto = require('crypto')

/**
 * Base directory for persisted nospoon state (identity, default Helia path, etc.).
 * Override with env `NOSPOON_HOME` (absolute path) for tests or alternate profiles.
 */
function getNospoonDir () {
  const h = process.env.NOSPOON_HOME
  if (h != null && String(h).trim() !== '') return path.resolve(String(h).trim())
  return path.join(os.homedir(), '.nospoon')
}

function getIdentityFile () {
  return path.join(getNospoonDir(), 'identity.json')
}

/**
 * Read identity file under {@link getNospoonDir} or create it with a new random seed (dir 0700, file 0600).
 * @returns {string} 64 lowercase hex characters
 */
function loadOrCreatePersistedSeedHex () {
  const nospoonDir = getNospoonDir()
  const identityFile = path.join(nospoonDir, 'identity.json')

  if (fs.existsSync(identityFile)) {
    let raw
    try {
      raw = fs.readFileSync(identityFile, 'utf8')
    } catch (e) {
      const msg = e && e.message ? e.message : String(e)
      throw new Error(`cannot read nospoon identity (${identityFile}): ${msg}`)
    }
    let j
    try {
      j = JSON.parse(raw)
    } catch {
      throw new Error(`nospoon identity file is not valid JSON: ${identityFile}`)
    }
    const h = String(j.seedHex || j.seed || '').trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(h)) {
      throw new Error(
        `nospoon identity has invalid seedHex (expected 64 hex chars): ${identityFile}`
      )
    }
    return h
  }

  const seedHex = crypto.randomBytes(32).toString('hex')
  const payload = { v: 1, seedHex }
  fs.mkdirSync(nospoonDir, { recursive: true, mode: 0o700 })
  const tmp = path.join(
    nospoonDir,
    `.identity.${process.pid}.${Date.now()}.tmp`
  )
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 })
  fs.renameSync(tmp, identityFile)
  try {
    fs.chmodSync(identityFile, 0o600)
  } catch (_) {}

  return seedHex
}

module.exports = {
  getNospoonDir,
  getIdentityFile,
  loadOrCreatePersistedSeedHex
}
