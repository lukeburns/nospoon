/**
 * Injected by {@link ../server.js} as JSON in `#spoon-hello-config` when served from the mesh hello HTTP server.
 * Under `npm run dev`, dev defaults come from the HTML template.
 */
export function readSpoonHelloConfig () {
  const el = document.getElementById('spoon-hello-config')
  if (!el) {
    return {
      signedPlainText: ''
    }
  }
  try {
    const o = JSON.parse(el.textContent || '{}')
    return {
      signedPlainText:
        typeof o.signedPlainText === 'string'
          ? o.signedPlainText
          : '(dev) Open this page from the mesh hello server for a signed greeting.'
    }
  } catch {
    return { signedPlainText: '' }
  }
}
