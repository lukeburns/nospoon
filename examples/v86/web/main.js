'use strict'

/**
 * Entry: same host assumptions as {@link ../../simple/web/main.js} ({@link ./env.js}), then boot v86.
 */

const {
  applyBrowserNetProxyFromLocation,
  resolveControlPanelOrigin,
  resolveVirtualListenHost
} = require('./env.js')
const { initV86HelloDemo } = require('./v86-hello-demo.js')

applyBrowserNetProxyFromLocation()

async function prefillBindHost () {
  const el = document.getElementById('bindhost')
  if (!el || el.value.trim()) return
  const vh = await resolveVirtualListenHost()
  if (vh) el.value = vh
}

async function boot () {
  await prefillBindHost()
  const origin = resolveControlPanelOrigin()
  await initV86HelloDemo({ controlPanelOrigin: origin })
}

if (typeof document !== 'undefined' && document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function () {
    void boot()
  })
} else {
  void boot()
}
