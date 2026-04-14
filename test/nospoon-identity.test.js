'use strict'

const { describe, it, before, after } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const os = require('os')

const identityPath = '../lib/identity/identity'

describe('identity', function () {
  let prevHome
  let tmpRoot

  before(function () {
    prevHome = process.env.NOSPOON_HOME
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nospoon-id-'))
  })

  after(function () {
    if (prevHome === undefined) delete process.env.NOSPOON_HOME
    else process.env.NOSPOON_HOME = prevHome
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true })
    } catch (_) {}
    delete require.cache[require.resolve(identityPath)]
  })

  it('loadOrCreatePersistedSeedHex creates then reuses identity.json', function () {
    process.env.NOSPOON_HOME = path.join(tmpRoot, 'persist')
    delete require.cache[require.resolve(identityPath)]
    const {
      loadOrCreatePersistedSeedHex,
      getIdentityFile
    } = require(identityPath)
    const idPath = getIdentityFile()
    assert.equal(fs.existsSync(idPath), false)
    const a = loadOrCreatePersistedSeedHex()
    assert.match(a, /^[0-9a-f]{64}$/)
    assert.ok(fs.existsSync(idPath))
    const b = loadOrCreatePersistedSeedHex()
    assert.equal(a, b)
  })

  it('rejects invalid seedHex in existing file', function () {
    process.env.NOSPOON_HOME = path.join(tmpRoot, 'invalid')
    delete require.cache[require.resolve(identityPath)]
    const { loadOrCreatePersistedSeedHex, getIdentityFile } = require(identityPath)
    const idPath = getIdentityFile()
    fs.mkdirSync(path.dirname(idPath), { recursive: true })
    fs.writeFileSync(idPath, JSON.stringify({ v: 1, seedHex: 'deadbeef' }), 'utf8')
    assert.throws(
      () => loadOrCreatePersistedSeedHex(),
      /invalid seedHex/
    )
  })
})
