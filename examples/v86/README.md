# v86 + mesh bridge (self-contained example)

Like **`examples/simple`**: esbuild bundle + **`web/env.js`** for browser-net / whois. **v86** firmware, wasm, and guest files live under **`assets/v86/`** (filled by **`npm run vendor`**) and are copied to **`dist/v86/`** on build so **`npm run preview`** serves a same-origin **`/v86/`** tree (no nospoon control HTTP required).

## Layout

| Path | Role |
|------|------|
| `assets/v86/` | Vendored output: `libv86.mjs`, `v86.wasm`, `guest/*` (created by `npm run vendor`) |
| `web/env.js` | Proxy + whois + **`resolveControlPanelOrigin()`** (defaults to `location.origin`) |
| `web/v86-hello-demo.js` | VM + IndexedDB + TCP bridge |

## Commands

```bash
cd examples/v86
npm install
npm run vendor              # copy wasm/mjs from npm + fetch BIOS; writes freebsd-meta.json
npm run fetch-freebsd-disk  # optional ~2 GiB chunks into assets/v86/guest/freebsd/
npm run build
npm run preview             # http://127.0.0.1:4173 — v86 at /v86/
```

**Inline single-file HTML** (`npm run build:inline`) still copies **`assets/v86` → `dist/v86`**, so upload **`dist/`** (or the whole `dist` folder next to the inline HTML) for IPFS/static hosts that need `/v86/` beside the page.

## Overrides

- **`?controlOrigin=http://…`** — load `/v86/*` from another origin (static preview, second dev server, etc.).
- Same **`proxyHost`**, **`wsHost`**, **`whoisOrigin`**, … as **`examples/simple`**.

## Nospoon package

The **`nospoon`** package no longer vendors or serves v86 assets; use this **`examples/v86`** tree (or copy its **`dist/v86`** layout) when you need the VM demo.
