import { useMemo, useState } from 'react'
import { readSpoonHelloConfig } from './readConfig.js'
import { BrowserNetPanel } from './BrowserNetPanel.jsx'
import { V86Panel } from './V86Panel.jsx'

export function App () {
  const cfg = useMemo(() => readSpoonHelloConfig(), [])
  const [shimNote, setShimNote] = useState(null)

  const { signedPlainText, controlPanelOrigin, primaryMeshZ32 } = cfg

  return (
    <main className="app">
      <pre id="signature" className="signature">{signedPlainText}</pre>
      {shimNote ? (
        <p className="app-alert" role="alert">
          {shimNote}
        </p>
      ) : null}
      <BrowserNetPanel
        controlPanelOrigin={controlPanelOrigin}
        primaryMeshZ32={primaryMeshZ32}
        onShimError={(e) =>
          setShimNote(
            e && e.message
              ? `browser-net shim: ${e.message}`
              : String(e)
          )
        }
      />
      <V86Panel controlPanelOrigin={controlPanelOrigin} />
    </main>
  )
}
