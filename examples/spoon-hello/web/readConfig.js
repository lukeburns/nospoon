/**
 * Injected by {@link ../server.js} as JSON in `#spoon-hello-config` when served from the mesh hello HTTP server.
 * Under `npm run dev`, dev.mjs defines defaults via the HTML template.
 */
export function readSpoonHelloConfig () {
  const el = document.getElementById('spoon-hello-config')
  if (!el) {
    return {
      signedPlainText: '',
      controlPanelOrigin: 'http://127.0.0.1:80',
      primaryMeshZ32: ''
    }
  }
  try {
    const o = JSON.parse(el.textContent || '{}')
    return {
      signedPlainText:
        typeof o.signedPlainText === 'string'
          ? o.signedPlainText
          : '(dev) Open this page from the mesh hello server for a signed greeting, or point controlPanelOrigin at your nospoon control panel.',
      controlPanelOrigin:
        typeof o.controlPanelOrigin === 'string' && o.controlPanelOrigin.trim()
          ? o.controlPanelOrigin.trim()
          : 'http://127.0.0.1:80',
      primaryMeshZ32:
        typeof o.primaryMeshZ32 === 'string' ? o.primaryMeshZ32 : ''
    }
  } catch {
    return {
      signedPlainText: '',
      controlPanelOrigin: 'http://127.0.0.1:80',
      primaryMeshZ32: ''
    }
  }
}
