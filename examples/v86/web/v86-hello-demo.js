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
  const startVmBtn = document.getElementById('v86-start-vm')
  const stopVmBtn = document.getElementById('v86-stop-vm')
  const saveSnapBtn = document.getElementById('v86-save-snapshot')
  const clearSnapBtn = document.getElementById('v86-clear-snapshot')
  const resumeIdbEl = document.getElementById('v86-resume-idb')
  const snapStatusEl = document.getElementById('v86-snapshot-status')
  const startSshBtn = document.getElementById('v86-start-ssh')
  const stopSshBtn = document.getElementById('v86-stop-ssh')
  const sshPortEl = document.getElementById('v86-ssh-port')
  const guestPortEl = document.getElementById('v86-guest-port')
  const bindHostEl = document.getElementById('bindhost')

  function log (line) {
    if (logEl) {
      logEl.textContent += line + '\n'
      logEl.scrollTop = logEl.scrollHeight
    } else {
      console.error(line)
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

  function freebsdGuestReady () {
    if (!freebsdMeta) {
      log(
        'Missing guest/freebsd-meta.json. From the nospoon package root run: node scripts/copy-v86-assets.js (or npm run build).'
      )
      return false
    }
    if (!freebsdMeta.diskChunksPresent) {
      log(
        'FreeBSD disk chunks are not installed (~2 GiB). From the package root run: npm run fetch-freebsd-disk'
      )
      return false
    }
    return true
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

  if (!startVmBtn || !stopVmBtn) {
    log('Missing v86 control elements in the page.')
    return
  }

  startVmBtn.onclick = async function () {
    if (emulator) {
      log('VM already running.')
      return
    }
    try {
      if (sshServer) {
        try {
          sshServer.close()
        } catch (_) {}
        sshServer = null
      }
      let snap = null
      if (resumeIdbEl && resumeIdbEl.checked) {
        snap = await idbGetSnapshotBuffer()
        if (!snap) {
          log('Resume checked but no valid snapshot — cold boot from disk (long; click the v86 canvas first so the window has focus for keyboard).')
        }
      }
      if (!freebsdGuestReady()) {
        return
      }
      emulator = new V86(v86BaseConfig(snap))
      if (snap) {
        log(
          'Restored VM from IndexedDB snapshot. Start bridge again when ready; if probe fails, fix guest networking (e.g. dhclient) and ensure sshd listens on the guest port.'
        )
      } else {
        log(
          'Cold-booting FreeBSD from disk (ne2k+ACPI, same RAM/disk as copy.sh) — first boot is slow. After login, run dhclient on the ethernet interface for the mesh bridge; sshd on 22 when ready.'
        )
      }
    } catch (e) {
      log('VM error: ' + (e && e.message ? e.message : e))
      emulator = null
    }
  }

  stopVmBtn.onclick = async function () {
    if (sshServer) {
      try {
        sshServer.close()
      } catch (_) {}
      sshServer = null
    }
    if (emulator) {
      try {
        if (typeof emulator.destroy === 'function') await emulator.destroy()
        else if (typeof emulator.stop === 'function') await emulator.stop()
      } catch (_) {}
      emulator = null
      if (screenEl) screenEl.innerHTML = ''
    }
    log('VM stopped.')
  }

  if (saveSnapBtn) {
    saveSnapBtn.onclick = async function () {
      if (!emulator) {
        log('Start the VM before saving a snapshot.')
        return
      }
      if (sshServer) {
        try {
          sshServer.close()
        } catch (_) {}
        sshServer = null
        log('Bridge stopped (required for a clean snapshot).')
      }
      try {
        await emulator.stop()
        const raw = await emulator.save_state()
        const copy = raw.slice(0)
        await idbPutSnapshot(copy)
        await emulator.run()
        log(
          'Saved snapshot to IndexedDB (~' +
            Math.round(copy.byteLength / (1024 * 1024)) +
            ' MiB). Check Resume before Start VM next time.'
        )
        await refreshSnapshotStatus()
      } catch (e) {
        const msg = e && e.name === 'QuotaExceededError' ? 'storage quota exceeded' : e && e.message ? e.message : e
        log('Save snapshot failed: ' + msg)
        try {
          await emulator.run()
        } catch (_) {}
      }
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

  if (startSshBtn) {
    startSshBtn.onclick = async function () {
      if (!emulator || !emulator.network_adapter) {
        log('Start the VM first; wait until the guest TCP port you need is listening.')
        return
      }
      if (sshServer) {
        log('Bridge already running (Stop bridge first).')
        return
      }
      const na = emulator.network_adapter
      const guestPort = guestPortEl ? Number(guestPortEl.value) || 22 : 22
      log('Probing guest TCP port ' + guestPort + ' (15s max)…')
      let open
      try {
        open = await tcpProbeWithTimeout(na, guestPort, 15000)
      } catch (e) {
        log('Probe error: ' + (e && e.message ? e.message : e))
        return
      }
      if (!open) {
        log(
          'Port ' +
            guestPort +
            ' not reachable (probe failed or timed out). In FreeBSD try `service sshd onestart` or `dhclient` if the guest lost its IP after resume; ensure sshd listens on that port.'
        )
        return
      }
      const port = sshPortEl ? Number(sshPortEl.value) || 2222 : 2222
      const host =
        bindHostEl && bindHostEl.value.trim() ? bindHostEl.value.trim() : ''
      const server = new BrowserNetServer({ url: wsUrl })
      server.addEventListener('connection', function (ev) {
        const sock = ev.detail
        let tcp = null
        try {
          tcp = na.connect(guestPort)
        } catch (e) {
          try {
            sock.end()
          } catch (_) {}
          return
        }
        tcp.on('data', function (u8) {
          try {
            sock.write(u8)
          } catch (_) {}
        })
        tcp.on('close', function () {
          try {
            sock.end()
          } catch (_) {}
        })
        tcp.on('shutdown', function () {
          try {
            sock.end()
          } catch (_) {}
        })
        sock.addEventListener('data', function (e) {
          if (tcp) tcp.write(new Uint8Array(e.data))
        })
        sock.addEventListener('close', function () {
          try {
            if (tcp) tcp.close()
          } catch (_) {}
          tcp = null
        })
      })
      try {
        log('Opening browser-net WebSocket and binding mesh port ' + port + ' (30s max)…')
        if (host) {
          await withTimeout(server.listen({ port, host }), 30000, 'listen')
        } else {
          await withTimeout(server.listen(port), 30000, 'listen')
        }
        sshServer = server
        log(
          'Bridge: mesh TCP ' +
            (host || 'primary') +
            ':' +
            port +
            ' → guest :' +
            guestPort +
            '. Peers: `ssh -p ' +
            port +
            ' <mesh-host>` when the guest speaks SSH on that port (FreeBSD sshd on 22); use `nc` for raw TCP to other services.'
        )
      } catch (e) {
        try {
          server.close()
        } catch (_) {}
        sshServer = null
        const msg = e && e.message ? e.message : e
        log(
          'listen error: ' +
            msg +
            (String(msg).indexOf('timeout') !== -1
              ? ' — try Stop bridge, refresh the page, then Start VM and bridge again.'
              : '')
        )
      }
    }
  }

  if (stopSshBtn) {
    stopSshBtn.onclick = function () {
      if (sshServer) {
        try {
          sshServer.close()
        } catch (_) {}
        sshServer = null
        log('Bridge stopped.')
      } else {
        log('No bridge is running.')
      }
    }
  }
}

module.exports = {
  initV86HelloDemo
}
