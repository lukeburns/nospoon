'use strict'

/**
 * v86 (fetch backend) + browser-net: inbound mesh TCP sessions bridge to a guest TCP port.
 * Bundled shim via {@code browser-net-shim}; WebSocket proxy comes from {@link ./env.js}
 * ({@code applyBrowserNetProxyFromLocation}), not from the control HTTP host.
 */

const { BrowserNetServer, defaultBrowserNetWsUrl } = require('browser-net-shim')

/** Bump if snapshot format or guest config changes and old blobs must be ignored. */
const SNAPSHOT_SCHEMA = 3
/** Must match: 256M RAM, 8M VGA, ACPI, ne2k+fetch, v86 0.5.319, FreeBSD disk (copy.sh layout). */
const SNAPSHOT_TAG = 'hello-256m-8vga-05319-freebsd-ne2k-acpi'

const IDB_NAME = 'nospoon-v86-example'
const IDB_VER = 1
const IDB_STORE = 'kv'

const GUEST_PORT = 22
const MESH_PORT = 22

/** How often to retry the bridge probe while waiting for the guest. */
const POLL_INTERVAL_MS = 5000

function idbOpen () {
  return new Promise(function (resolve, reject) {
    const r = indexedDB.open(IDB_NAME, IDB_VER)
    r.onerror = function () {
      reject(r.error)
    }
    r.onsuccess = function () {
      resolve(r.result)
    }
    r.onupgradeneeded = function (e) {
      const db = e.target.result
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: 'id' })
      }
    }
  })
}

function idbTx (db, mode, fn) {
  return new Promise(function (resolve, reject) {
    const tx = db.transaction(IDB_STORE, mode)
    const store = tx.objectStore(IDB_STORE)
    let out
    try {
      out = fn(store)
    } catch (e) {
      reject(e)
      return
    }
    tx.oncomplete = function () {
      resolve(out)
    }
    tx.onerror = function () {
      reject(tx.error)
    }
  })
}

async function idbPutSnapshot (stateBuf) {
  const db = await idbOpen()
  const meta = {
    id: 'meta',
    schema: SNAPSHOT_SCHEMA,
    tag: SNAPSHOT_TAG,
    savedAt: Date.now(),
    byteLength: stateBuf.byteLength
  }
  const body = { id: 'state', buffer: stateBuf }
  await idbTx(db, 'readwrite', function (store) {
    store.put(meta)
    store.put(body)
  })
  db.close()
}

async function idbGetSnapshotBuffer () {
  const db = await idbOpen()
  const meta = await new Promise(function (resolve, reject) {
    const r = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get('meta')
    r.onsuccess = function () {
      resolve(r.result || null)
    }
    r.onerror = function () {
      reject(r.error)
    }
  })
  if (
    !meta ||
    meta.schema !== SNAPSHOT_SCHEMA ||
    meta.tag !== SNAPSHOT_TAG
  ) {
    db.close()
    return null
  }
  const row = await new Promise(function (resolve, reject) {
    const r = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get('state')
    r.onsuccess = function () {
      resolve(r.result || null)
    }
    r.onerror = function () {
      reject(r.error)
    }
  })
  db.close()
  if (!row || !row.buffer) return null
  return row.buffer
}

async function idbClearSnapshot () {
  const db = await idbOpen()
  await idbTx(db, 'readwrite', function (store) {
    store.delete('meta')
    store.delete('state')
  })
  db.close()
}

async function idbSnapshotMetaOnly () {
  const db = await idbOpen()
  const meta = await new Promise(function (resolve, reject) {
    const r = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get('meta')
    r.onsuccess = function () {
      resolve(r.result || null)
    }
    r.onerror = function () {
      reject(r.error)
    }
  })
  db.close()
  if (
    !meta ||
    meta.schema !== SNAPSHOT_SCHEMA ||
    meta.tag !== SNAPSHOT_TAG
  ) {
    return null
  }
  return { savedAt: meta.savedAt, byteLength: meta.byteLength }
}

/**
 * @param {{ controlPanelOrigin: string }} opts
 */
async function initV86HelloDemo (opts) {
  const controlPanelOrigin = String(opts.controlPanelOrigin || '').trim()
  const screenEl = document.getElementById('v86-screen-container')
  const logEl = document.getElementById('v86-log')
  const saveSnapBtn = document.getElementById('v86-save-snapshot')
  const clearSnapBtn = document.getElementById('v86-clear-snapshot')
  const snapStatusEl = document.getElementById('v86-snapshot-status')
  const stopSshBtn = document.getElementById('v86-stop-ssh')
  const bridgeStatusEl = document.getElementById('v86-bridge-status')
  const bindHostEl = document.getElementById('bindhost')

  function log (line) {
    if (logEl) {
      logEl.textContent += line + '\n'
      logEl.scrollTop = logEl.scrollHeight
    } else {
      console.error(line)
    }
  }

  function setBridgeState (state) {
    if (bridgeStatusEl) {
      bridgeStatusEl.className = 'bridge-status bridge-status--' + state
      bridgeStatusEl.title =
        state === 'connected' ? 'Bridge connected'
          : state === 'connecting' ? 'Connecting to guest…'
          : 'Bridge off'
    }
    if (stopSshBtn) {
      stopSshBtn.hidden = state !== 'connected'
    }
  }

  const originBase =
    controlPanelOrigin.indexOf('://') !== -1
      ? controlPanelOrigin
      : 'http://' + controlPanelOrigin

  const v86Base = new URL('/v86/', originBase.endsWith('/') ? originBase : originBase + '/')
  let V86
  let wasmUrl
  try {
    wasmUrl = new URL('v86.wasm', v86Base).href
    ;({ V86 } = await import(new URL('libv86.mjs', v86Base).href))
  } catch (e) {
    log(
      'v86 init failed (need same-origin /v86/* after build — run npm run vendor && npm run build): ' +
        (e && e.message ? e.message : e)
    )
    return
  }

  const guestBase = new URL('guest/', v86Base)
  const V86_GUEST = {
    bios: { url: new URL('seabios.bin', guestBase).href },
    vga_bios: { url: new URL('vgabios.bin', guestBase).href }
  }
  const FREEBSD_DISK_URL = new URL('freebsd/.img', guestBase).href
  const FREEBSD_DISK_BYTES = 2147483648

  let freebsdMeta = null
  try {
    const metaUrl = new URL('guest/freebsd-meta.json', v86Base).href
    const mr = await fetch(metaUrl)
    if (mr.ok) freebsdMeta = await mr.json()
  } catch (_) {}

  let emulator = null
  let sshServer = null
  let pollTimer = null
  let macFixed = false

  function tcpProbeWithTimeout (na, port, ms) {
    let timer
    return Promise.race([
      na.tcp_probe(port),
      new Promise(function (_resolve, reject) {
        timer = setTimeout(function () {
          reject(new Error('probe-timeout'))
        }, ms)
      })
    ])
      .then(function (ok) {
        clearTimeout(timer)
        return ok
      })
      .catch(function (e) {
        clearTimeout(timer)
        if (e && e.message === 'probe-timeout') return false
        throw e
      })
  }

  function withTimeout (p, ms, label) {
    let timer
    return Promise.race([
      p,
      new Promise(function (_resolve, reject) {
        timer = setTimeout(function () {
          reject(new Error(label + '-timeout'))
        }, ms)
      })
    ]).finally(function () {
      clearTimeout(timer)
    })
  }

  const wsUrl = defaultBrowserNetWsUrl(
    typeof window !== 'undefined' && window.location
      ? window.location.href
      : 'http://127.0.0.1/'
  )

  function v86BaseConfig (initialStateBuf) {
    const c = {
      wasm_path: wasmUrl,
      memory_size: 256 * 1024 * 1024,
      vga_memory_size: 8 * 1024 * 1024,
      acpi: true,
      screen_container: screenEl,
      bios: V86_GUEST.bios,
      vga_bios: V86_GUEST.vga_bios,
      hda: {
        url: FREEBSD_DISK_URL,
        size: FREEBSD_DISK_BYTES,
        async: true,
        use_parts: true,
        fixed_chunk_size: 1048576
      },
      net_device: { relay_url: 'fetch', type: 'ne2k' },
      autostart: true
    }
    if (initialStateBuf) {
      c.initial_state = { buffer: initialStateBuf.slice(0) }
    }
    return c
  }

  /** First 1 MiB chunk URL (must match copy.sh / vendor-v86 layout). */
  const FREEBSD_PROBE_CHUNK_URL = new URL(
    'guest/freebsd/0-1048576.img',
    v86Base
  ).href

  async function probeFreebsdDiskChunkPresent () {
    try {
      let r = await fetch(FREEBSD_PROBE_CHUNK_URL, { method: 'HEAD' })
      if (r.ok) return true
      r = await fetch(FREEBSD_PROBE_CHUNK_URL, { headers: { Range: 'bytes=0-0' } })
      return r.ok || r.status === 206
    } catch (_) {
      return false
    }
  }

  async function freebsdGuestReady () {
    if (freebsdMeta && freebsdMeta.diskChunksPresent === true) return true
    const probed = await probeFreebsdDiskChunkPresent()
    if (probed) {
      if (freebsdMeta && freebsdMeta.diskChunksPresent !== true) {
        log(
          'guest/freebsd-meta.json says disk chunks missing, but guest/freebsd/0-1048576.img is reachable — cold boot will proceed. Regenerate meta: in this directory run `npm run vendor` (omit --freebsd-disk to rescan disk chunks only).'
        )
      }
      return true
    }
    if (!freebsdMeta) {
      log(
        'Missing guest/freebsd-meta.json and first disk chunk. From this example directory run `npm run vendor`.'
      )
      return false
    }
    log(
      'FreeBSD disk chunks look missing (no response for guest/freebsd/0-1048576.img). From this example directory run `npm run fetch-freebsd-disk` (~2 GiB).'
    )
    return false
  }

  async function refreshSnapshotStatus () {
    if (!snapStatusEl) return
    try {
      const m = await idbSnapshotMetaOnly()
      snapStatusEl.textContent = m
        ? 'IndexedDB snapshot: ' +
          new Date(m.savedAt).toLocaleString() +
          ' (~' +
          Math.round(m.byteLength / (1024 * 1024)) +
          ' MiB). Same origin only; clearing site data removes it.'
        : 'No IndexedDB snapshot for this demo in this browser.'
    } catch (_) {
      snapStatusEl.textContent = 'Could not read IndexedDB snapshot status.'
    }
  }

  refreshSnapshotStatus()

  /**
   * v86 NE2000 bug workaround — see earlier comments for full explanation.
   * Temporarily enables promiscuous mode, sends a broadcast ARP to learn the
   * guest's real MAC, patches ne2k.mac and na.vm_mac, restores filtering.
   */
  async function fixNe2kMacAfterRestore (na) {
    if (macFixed) return
    var ne2k
    try {
      ne2k = emulator.v86.cpu.devices.net
    } catch (_) {
      return
    }
    if (!ne2k || !na) return

    ne2k.rxcr = ne2k.rxcr | 0x10

    var realMac = null
    var origSend = na.send
    na.send = function (data) {
      if (!realMac && data && data.length >= 14) {
        var src = new Uint8Array(data.buffer || data, (data.byteOffset || 0) + 6, 6)
        if (src[0] === 0x00 && src[1] === 0x22 && src[2] === 0x15) {
          realMac = new Uint8Array(src)
        }
      }
      return origSend.call(na, data)
    }

    var arp = new Uint8Array(42)
    arp.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    arp.set([0x52, 0x54, 0x00, 0x01, 0x02, 0x03], 6)
    arp[12] = 0x08; arp[13] = 0x06
    arp[14] = 0x00; arp[15] = 0x01
    arp[16] = 0x08; arp[17] = 0x00
    arp[18] = 6; arp[19] = 4
    arp[20] = 0x00; arp[21] = 0x01
    arp.set([0x52, 0x54, 0x00, 0x01, 0x02, 0x03], 22)
    arp.set(na.router_ip, 28)
    arp.set([0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 32)
    arp.set(na.vm_ip, 38)
    na.receive(arp)

    await new Promise(function (r) { setTimeout(r, 500) })
    na.send = origSend

    if (realMac) {
      var fmtMac = function (m) { return Array.from(m).map(function (b) { return b.toString(16).padStart(2, '0') }).join(':') }
      log('Learned guest MAC: ' + fmtMac(realMac))
      ne2k.mac = new Uint8Array(realMac)
      na.vm_mac = new Uint8Array(realMac)
      ne2k.rxcr = ne2k.rxcr & ~0x10
      macFixed = true
    }
  }

  /** Try to bring up the bridge. Returns true on success. */
  async function tryStartBridge () {
    if (!emulator || !emulator.network_adapter) return false
    if (sshServer) return true
    const na = emulator.network_adapter

    await fixNe2kMacAfterRestore(na)

    let open
    try {
      open = await tcpProbeWithTimeout(na, GUEST_PORT, 10000)
    } catch (_) {
      return false
    }
    if (!open) return false

    const host =
      bindHostEl && bindHostEl.value.trim() ? bindHostEl.value.trim() : ''
    const server = new BrowserNetServer({ url: wsUrl })
    server.addEventListener('connection', function (ev) {
      const sock = ev.detail
      let tcp = null
      try {
        tcp = na.connect(GUEST_PORT)
      } catch (e) {
        try { sock.end() } catch (_) {}
        return
      }
      tcp.on('data', function (u8) {
        try { sock.write(u8) } catch (_) {}
      })
      tcp.on('close', function () {
        try { sock.end() } catch (_) {}
      })
      tcp.on('shutdown', function () {
        try { sock.end() } catch (_) {}
      })
      sock.addEventListener('data', function (e) {
        if (tcp) tcp.write(new Uint8Array(e.data))
      })
      sock.addEventListener('close', function () {
        try { if (tcp) tcp.close() } catch (_) {}
        tcp = null
      })
    })
    try {
      if (host) {
        await withTimeout(server.listen({ port: MESH_PORT, host }), 30000, 'listen')
      } else {
        await withTimeout(server.listen(MESH_PORT), 30000, 'listen')
      }
      sshServer = server
      log('Bridge connected — mesh :' + MESH_PORT + ' → guest :' + GUEST_PORT)
      return true
    } catch (e) {
      try { server.close() } catch (_) {}
      const msg = e && e.message ? e.message : e
      log('Bridge listen error: ' + msg)
      return false
    }
  }

  function stopBridge () {
    if (sshServer) {
      try { sshServer.close() } catch (_) {}
      sshServer = null
      log('Bridge disconnected.')
    }
  }

  function stopPolling () {
    if (pollTimer) {
      clearTimeout(pollTimer)
      pollTimer = null
    }
  }

  /** Poll until bridge connects, then stop. */
  function startPolling () {
    stopPolling()
    setBridgeState('connecting')

    async function tick () {
      pollTimer = null
      if (sshServer) {
        setBridgeState('connected')
        return
      }
      const ok = await tryStartBridge()
      if (ok) {
        setBridgeState('connected')
      } else {
        pollTimer = setTimeout(tick, POLL_INTERVAL_MS)
      }
    }

    tick()
  }

  // --- Auto-start VM on page load ---
  async function startVm () {
    if (emulator) return
    try {
      let snap = await idbGetSnapshotBuffer()
      if (!snap) {
        if (!(await freebsdGuestReady())) return
        log('No snapshot — cold-booting FreeBSD from disk (slow). After login, run dhclient on the ethernet interface; sshd on 22 when ready.')
      } else {
        if (!(await freebsdGuestReady())) return
      }
      emulator = new V86(v86BaseConfig(snap))
      if (snap) {
        log('Restored VM from snapshot.')
      }
    } catch (e) {
      log('VM error: ' + (e && e.message ? e.message : e))
      emulator = null
    }
  }

  await startVm()

  // --- Clipboard: intercept before v86's global keyboard handler ---
  if (emulator) {
    // v86 registers keyboard handlers globally.  We intercept in the
    // capture phase on window so we see events first.  For modifier
    // combos (Cmd/Ctrl + C/V/A/X) we stop propagation so v86 never
    // receives them, letting the browser handle copy/paste natively.
    function guardModifier (e) {
      // Only intercept Cmd (Meta) combos for clipboard — let Ctrl through
      // so Ctrl+C (SIGINT) etc. reach the guest.
      if (e.metaKey && /^[acvx]$/i.test(e.key)) {
        e.stopImmediatePropagation()
      }
    }
    window.addEventListener('keydown', guardModifier, true)
    window.addEventListener('keyup', guardModifier, true)
    window.addEventListener('keypress', guardModifier, true)

    // Paste: send clipboard text into the guest as keystrokes.
    document.addEventListener('paste', function (e) {
      if (!emulator) return
      // Only paste into the guest when the screen container has or is
      // near focus (not when typing in an input elsewhere on the page).
      var active = document.activeElement
      if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) return
      var text = e.clipboardData && e.clipboardData.getData('text')
      if (text) {
        e.preventDefault()
        emulator.keyboard_send_text(text)
      }
    })
  }

  // Begin polling for bridge connectivity
  if (emulator) {
    startPolling()
  }

  if (saveSnapBtn) {
    saveSnapBtn.onclick = async function () {
      if (!emulator) {
        log('VM not running.')
        return
      }
      stopPolling()
      if (sshServer) {
        stopBridge()
      }
      setBridgeState('off')
      try {
        await emulator.stop()
        const raw = await emulator.save_state()
        const copy = raw.slice(0)
        await idbPutSnapshot(copy)
        await emulator.run()
        log(
          'Saved snapshot to IndexedDB (~' +
            Math.round(copy.byteLength / (1024 * 1024)) +
            ' MiB).'
        )
        await refreshSnapshotStatus()
      } catch (e) {
        const msg = e && e.name === 'QuotaExceededError' ? 'storage quota exceeded' : e && e.message ? e.message : e
        log('Save snapshot failed: ' + msg)
        try {
          await emulator.run()
        } catch (_) {}
      }
      // Resume polling after save
      startPolling()
    }
  }

  if (clearSnapBtn) {
    clearSnapBtn.onclick = async function () {
      try {
        await idbClearSnapshot()
        log('Cleared IndexedDB snapshot.')
        await refreshSnapshotStatus()
      } catch (e) {
        log('Clear snapshot failed: ' + (e && e.message ? e.message : e))
      }
    }
  }

  if (stopSshBtn) {
    stopSshBtn.onclick = function () {
      stopPolling()
      stopBridge()
      setBridgeState('off')
    }
  }
}

module.exports = {
  initV86HelloDemo
}
