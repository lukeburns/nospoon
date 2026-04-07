# Browser TCP service example

This directory shows a **small but real split** between:

1. **Environment** (`web/env.js`) — how the page reaches the mesh control plane (`setBrowserNetProxy`) and optional whois URLs. This is deployment wiring, not your service.
2. **Service** (`web/server/tcp-broadcast-server.js`) — Node-style `net.createServer`, listen loop, and broadcast. No DOM; it reports events through an injected `ui` object and `resolvePeerLabel`.
3. **Shell + client** (`web/index.html`, `web/styles.css`, `web/main.js`) — static document and UI that starts the service and maps callbacks to the DOM.

The static site is **both** the host for the page and the place where the virtual TCP server runs: same origin for assets, same JS context for `net`.

## Layout

| Path | Role |
|------|------|
| `web/index.html` | Document shell; references `styles.css` and `bundle.js` after build |
| `web/styles.css` | Presentation only |
| `web/main.js` | Entry: wires UI + calls `createTcpBroadcastServer` |
| `web/env.js` | Proxy + whois helpers |
| `web/server/tcp-broadcast-server.js` | Portable “server” logic |

## Commands

```bash
npm install
npm run build          # dist/index.html + dist/bundle.js + dist/styles.css
npm run build:inline   # single dist/index.html (inline script)
npm run preview        # http://127.0.0.1:4173 — run after build
```

Query parameters for the proxy (`proxyHost`, `wsHost`, …) behave as before; see `web/env.js`.

## Copying the pattern

To add your own service, keep **`env.js`-level concerns** separate, implement **`net` listeners** in a module that does not import `document`, and use **`main.js`** only to translate callbacks into UI or other browser APIs.
