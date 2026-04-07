'use strict'

/**
 * v86 + browser-net interface mode: guest NE2000 ↔ Ethernet ↔ raw IPv4 ↔ mesh tunnel.
 * The guest OS handles TCP/IP directly; we just bridge Ethernet frames to raw IP packets.
 * Bundled shim via {@code browser-net-shim}; WebSocket proxy comes from {@link ./env.js}.
 */

const { BrowserNetInterface, defaultBrowserNetWsUrl } = require('browser-net-shim')
const { whoisUrlSelf } = require('./env.js')

/** Bump if snapshot format or guest config changes and old blobs must be ignored. */
const SNAPSHOT_SCHEMA = 3
/** Must match: 256M RAM, 8M VGA, ACPI, ne2k+fetch, v86 0.5.319, FreeBSD disk (copy.sh layout). */
const SNAPSHOT_TAG = 'hello-256m-8vga-05319-freebsd-ne2k-acpi'

const IDB_NAME = 'nospoon-v86-example'
const IDB_VER = 1
const IDB_STORE = 'kv'

/** How often to retry bind_interface while waiting for the mesh. */
const POLL_INTERVAL_MS = 5000

/** Hard-coded topic for this demo. */
const BIND_TOPIC = 'v86'

/** Fixed MAC for our virtual gateway (Ethernet framing). */
const GATEWAY_MAC = new Uint8Array([0x52, 0x54, 0x00, 0x01, 0x02, 0x03])
const BROADCAST_MAC = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

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
  let activeIface = null
  let pollTimer = null

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
      // relay_url needed so v86 creates the NE2000 device; wireEthernetBridge
      // replaces the fetch adapter's bus handler with our raw IP tunnel.
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

  /** @type {((ethFrame: unknown) => void) | null} */
  let bridgeNet0SendHandler = null

  /**
   * v86's {@code relay_url: "fetch"} adapter registers {@code net0-send} and runs {@code Hb()} on
   * every guest frame. For TCP flows it did not originate (e.g. inbound SYN to {@code nc -l}),
   * {@code Hb} injects RST into the guest — so you see RX logs but never TX / no SYN-ACK on the mesh.
   * Raw mesh traffic must not go through that path; drop only the adapter's listener.
   * @param {{ network_adapter?: object, bus?: { listeners?: Record<string, Array<{ this_value?: object }>> }, _nospoonStrippedV86FetchNet0Send?: boolean }} em
   */
  function stripBuiltinFetchNet0Send (em) {
    if (!em || em._nospoonStrippedV86FetchNet0Send) return
    const na = em.network_adapter
    const listeners = em.bus && em.bus.listeners
    if (!na || !listeners) return
    const key = 'net0-send'
    const arr = listeners[key]
    if (!Array.isArray(arr)) return
    const kept = arr.filter(function (ent) {
      return ent.this_value !== na
    })
    if (kept.length === arr.length) return
    listeners[key] = kept
    em._nospoonStrippedV86FetchNet0Send = true
    log(
      'Detached v86 built-in net0-send (fetch NAT) so raw mesh TCP is not RST’d — guest handles real IP/TCP.'
    )
  }

  /**
   * Hook v86's NE2000 bus to forward raw IPv4 packets through a BrowserNetInterface.
   * Handles ARP at the Ethernet level so the guest can resolve any IP to our
   * gateway MAC — all traffic routes through the interface tunnel.
   */
  function wireEthernetBridge (iface) {
    const bus = emulator.bus
    stripBuiltinFetchNet0Send(emulator)

    if (bridgeNet0SendHandler) {
      try {
        bus.unregister('net0-send', bridgeNet0SendHandler)
      } catch (_) {}
      bridgeNet0SendHandler = null
    }

    // Never trust NE2000's MAC register after snapshot restore — the set_state
    // bug gives a random constructor value that may differ from what the guest
    // driver actually uses.  Start null and learn from the first outgoing frame.
    let guestMac = null
    const fmtIp = function (u8, off) { return u8[off] + '.' + u8[off + 1] + '.' + u8[off + 2] + '.' + u8[off + 3] }
    const fmtMac = function (u8, off) { return Array.from(u8.subarray(off, off + 6)).map(function (b) { return b.toString(16).padStart(2, '0') }).join(':') }
    const fmtPkt = function (ip) {
      var s = fmtIp(ip, 12) + ' → ' + fmtIp(ip, 16) + ' proto=' + ip[9] + ' len=' + ip.length
      if (ip[9] === 6 && ip.length >= 40) {
        var ihl = (ip[0] & 0x0f) * 4
        var f = ip[ihl + 13], fl = []
        if (f & 0x02) fl.push('SYN')
        if (f & 0x10) fl.push('ACK')
        if (f & 0x01) fl.push('FIN')
        if (f & 0x04) fl.push('RST')
        if (f & 0x08) fl.push('PSH')
        s += ' [' + fl.join(',') + '] :' + ((ip[ihl] << 8) | ip[ihl + 1]) + '→:' + ((ip[ihl + 2] << 8) | ip[ihl + 3])
      }
      return s
    }

    bridgeNet0SendHandler = function (ethFrame) {
      const u8 = new Uint8Array(ethFrame)
      if (u8.length < 14) return
      var _et = (u8[12] << 8) | u8[13]
      log('NET0-SEND len=' + u8.length + ' etherType=0x' + _et.toString(16) + ' srcMAC=' + fmtMac(u8, 6) + ' dstMAC=' + fmtMac(u8, 0))

      // Learn guest MAC from source field of outgoing frames
      if (!guestMac) {
        guestMac = u8.slice(6, 12)
        log('Learned guest MAC: ' + fmtMac(guestMac, 0))
      }

      const etherType = (u8[12] << 8) | u8[13]

      if (etherType === 0x0806 && u8.length >= 42) {
        // ARP — reply to requests with our gateway MAC, but skip requests
        // for the guest's own IP (gratuitous ARP / DAD) to avoid FreeBSD
        // detecting a false IP conflict and killing connections.
        const opcode = (u8[20] << 8) | u8[21]
        if (opcode !== 1) return
        var targetIp = fmtIp(u8, 38)
        var senderIp = fmtIp(u8, 28)
        if (targetIp === senderIp) {
          log('ARP probe (DAD) for ' + targetIp + ' — ignoring')
          return
        }
        log('ARP request: who has ' + targetIp + '? → replying with gateway MAC')
        const reply = new Uint8Array(42)
        reply.set(u8.subarray(6, 12), 0)   // dst = sender's MAC
        reply.set(GATEWAY_MAC, 6)            // src = gateway
        reply[12] = 0x08; reply[13] = 0x06
        reply[14] = 0x00; reply[15] = 0x01   // hw type: Ethernet
        reply[16] = 0x08; reply[17] = 0x00   // proto type: IPv4
        reply[18] = 6; reply[19] = 4
        reply[20] = 0x00; reply[21] = 0x02   // opcode: reply
        reply.set(GATEWAY_MAC, 22)            // sender MAC
        reply.set(u8.subarray(38, 42), 28)    // sender IP = requested target IP
        reply.set(u8.subarray(22, 28), 32)    // target = original sender
        bus.send('net0-receive', reply)
        return
      }

      if (etherType === 0x0800) {
        // IPv4 — strip Ethernet header and any Ethernet padding (NE2000
        // pads frames to 60 bytes; the extra bytes corrupt the TCP stream
        // if forwarded). Trim to the IP total length field.
        var ip = u8.subarray(14)
        var ipTotalLen = (ip[2] << 8) | ip[3]
        if (ipTotalLen < 20 || ipTotalLen > ip.length) return
        ip = ip.subarray(0, ipTotalLen)
        log('TX ' + fmtPkt(ip))
        iface.send(ip)
      }
    }
    bus.register('net0-send', bridgeNet0SendHandler)

    iface.on('packet', function (ev) {
      const ipPkt = ev.data
      if (!ipPkt || ipPkt.length < 20) return
      log('RX ' + fmtPkt(ipPkt))
      // Wrap in Ethernet: dst=guest (broadcast until learned), src=gateway, type=IPv4
      const frame = new Uint8Array(14 + ipPkt.length)
      frame.set(guestMac || BROADCAST_MAC, 0)
      frame.set(GATEWAY_MAC, 6)
      frame[12] = 0x08; frame[13] = 0x00
      frame.set(ipPkt, 14)
      log('NET0-INJECT len=' + frame.length + ' dstMAC=' + fmtMac(frame, 0) + ' srcMAC=' + fmtMac(frame, 6))
      bus.send('net0-receive', frame)
    })
  }

  /** Try to bind the interface. Returns true on success. */
  async function tryStartBridge () {
    if (!emulator) return false
    if (activeIface) return true

    let host = bindHostEl && bindHostEl.value.trim() ? bindHostEl.value.trim() : ''
    if (!host) {
      // Fetch our z32 public key and bind to <z32>.v86
      try {
        const r = await fetch(whoisUrlSelf())
        if (r.ok) {
          const z32 = (await r.text()).trim().split(/\r?\n/)[0].trim()
          if (z32) host = z32 + '.' + BIND_TOPIC
        }
      } catch (_) {}
    }
    if (!host) {
      log('Bridge bind error: could not resolve local key for topic ' + BIND_TOPIC)
      return false
    }
    const iface = new BrowserNetInterface({ url: wsUrl })
    try {
      const boundIp = await iface.bind(host)
      wireEthernetBridge(iface)
      activeIface = iface
      log('Bridge connected — bound to ' + boundIp)
      // Configure the guest's NIC with the mesh IP (delay for guest shell readiness)
      setTimeout(function () {
        emulator.keyboard_send_text('ifconfig ed0 inet ' + boundIp + '/24\n')
      }, 1000)
      // setTimeout(function () {
      //   emulator.keyboard_send_scancodes([                                                                        
      //     0x1D,       // Ctrl down                                                                                
      //     0x26,       // L down                                                                                   
      //     0xA6,       // L up                                                                                     
      //     0x9D        // Ctrl up                                                                                  
      //   ])
      // }, 1000)
      return true
    } catch (e) {
      try { iface.close() } catch (_) {}
      const msg = e && e.message ? e.message : e
      log('Bridge bind error: ' + msg)
      return false
    }
  }

  function stopBridge () {
    if (emulator && bridgeNet0SendHandler) {
      try {
        emulator.bus.unregister('net0-send', bridgeNet0SendHandler)
      } catch (_) {}
      bridgeNet0SendHandler = null
    }
    if (activeIface) {
      try { activeIface.close() } catch (_) {}
      activeIface = null
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
      if (activeIface) {
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
      if (activeIface) {
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
