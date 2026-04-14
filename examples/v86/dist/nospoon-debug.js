/**
 * nospoon-debug.js — reusable browser debug harness for nospoon examples.
 *
 * Load via <script src="nospoon-debug.js"></script> BEFORE the app bundle.
 * Console interception and error capture start immediately.
 *
 * Public API (window.__nospoonDebug):
 *   .on(type, handler)            — register a command handler
 *   .observe(selectorOrElement)   — MutationObserver forwarding for a DOM log element
 *   .push(msg)                    — manually send a log line
 */
;(function () {
  var CP = 'http://10.254.0.1'
  var handlers = {}
  var queue = []
  var timer = null

  function flush () {
    if (!queue.length) return
    var batch = queue.splice(0, 50)
    try {
      var x = new XMLHttpRequest()
      x.open('POST', CP + '/api/browser-log', true)
      x.setRequestHeader('Content-Type', 'application/json')
      x.send(JSON.stringify(batch))
    } catch (_) {}
  }

  function push (s) {
    queue.push(s)
    if (!timer) timer = setTimeout(function () { timer = null; flush() }, 100)
  }

  var origLog = console.log.bind(console)
  var origErr = console.error.bind(console)

  console.log = function () {
    var a = [].slice.call(arguments).map(String).join(' ')
    push('[console.log] ' + a)
    origLog.apply(console, arguments)
  }

  console.error = function () {
    var a = [].slice.call(arguments).map(String).join(' ')
    push('[console.err] ' + a)
    origErr.apply(console, arguments)
  }

  window.addEventListener('error', function (e) { push('[uncaught] ' + e.message) })

  function observe (selectorOrElement) {
    var el = typeof selectorOrElement === 'string'
      ? document.querySelector(selectorOrElement)
      : selectorOrElement
    if (!el) { push('[nospoon-debug] observe: element not found'); return }
    var lastLen = 0
    var obs = new MutationObserver(function () {
      var txt = el.textContent || ''
      if (txt.length > lastLen) {
        var lines = txt.substring(lastLen).split('\n').filter(Boolean)
        lines.forEach(function (l) { push(l) })
        lastLen = txt.length
      }
    })
    obs.observe(el, { childList: true, characterData: true, subtree: true })
  }

  function on (type, handler) {
    handlers[type] = handler
  }

  setInterval(function () {
    try {
      var x = new XMLHttpRequest()
      x.open('GET', CP + '/api/browser-cmd', false)
      x.send()
      if (x.status === 200) {
        var cmds = JSON.parse(x.responseText)
        cmds.forEach(function (cmd) {
          var h = handlers[cmd.type]
          if (h) { h(cmd); push('[cmd:' + cmd.type + '] ok') }
          else { push('[cmd] unhandled type: ' + cmd.type) }
        })
      }
    } catch (_) {}
  }, 1000)

  window.__nospoonDebug = { on: on, observe: observe, push: push }
  push('nospoon-debug attached')
})()
