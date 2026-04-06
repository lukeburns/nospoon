import { useEffect, useRef } from 'react'

export function V86Panel ({ controlPanelOrigin }) {
  const logRef = useRef(null)
  const ranRef = useRef(false)

  useEffect(() => {
    if (ranRef.current) return
    ranRef.current = true
    const o =
      controlPanelOrigin.indexOf('://') !== -1
        ? controlPanelOrigin
        : `http://${controlPanelOrigin}`
    ;(async function () {
      try {
        const demoUrl = new URL(
          '/v86/hello-demo.mjs',
          o.endsWith('/') ? o : `${o}/`
        ).href
        const mod = await import(/* @vite-ignore */ demoUrl)
        await mod.initV86HelloDemo({ controlPanelOrigin: o })
      } catch (e) {
        const msg = e && e.message ? e.message : String(e)
        const el = logRef.current
        if (el) el.textContent = (el.textContent || '') + `v86 loader error: ${msg}\n`
        else console.error(e)
      }
    })()
  }, [controlPanelOrigin])

  return (
    <section>
      <h2>v86 (x86 in the browser)</h2>
      <p>
        Loads <strong>v86</strong> + WASM from the control panel (<code>/v86/</code>), with the{' '}
        <strong>fetch</strong> network (NE2000, matching copy.sh’s defaults). The guest is <strong>FreeBSD</strong> — prefetch
        disk chunks from the nospoon repo with <code>npm run fetch-freebsd-disk</code> (~2 GiB under <code>lib/v86/guest/freebsd/</code>). Cold boot
        is from disk; use <strong>IndexedDB</strong> save/resume for fast restarts. Click the emulated
        screen so it has focus for keyboard input. Bring up networking with <code>dhclient</code> on the guest interface, then
        bridge port <strong>22</strong> below. Test with <code>ssh</code> or <code>nc</code> to your mesh bind host and listen port.
      </p>
      <div id="v86-screen-container" />
      <p>
        <button type="button" id="v86-start-vm">Start VM</button>
        <button type="button" id="v86-stop-vm">Stop VM</button>
        <button type="button" id="v86-save-snapshot">Save snapshot to browser</button>
        <button type="button" id="v86-clear-snapshot">Clear saved snapshot</button>
      </p>
      <p>
        <label>
          <input type="checkbox" id="v86-resume-idb" /> Resume from saved snapshot (IndexedDB; tens of MiB; same browser only)
        </label>
      </p>
      <p id="v86-snapshot-status" className="v86-snapshot-status" />
      <p className="field-row">
        <label>
          Guest TCP port <input id="v86-guest-port" type="number" defaultValue={22} min={1} max={65535} />
        </label>
        <label>
          Mesh listen port <input id="v86-ssh-port" type="number" defaultValue={2222} min={1} max={65535} />
        </label>
        <span className="field-hint-inline">(uses bind host above)</span>
      </p>
      <p>
        <button type="button" id="v86-start-ssh">Start bridge</button>
        <button type="button" id="v86-stop-ssh">Stop bridge</button>
      </p>
      <p><strong>v86 log</strong></p>
      <pre id="v86-log" className="v86-log" ref={logRef} />
    </section>
  )
}
