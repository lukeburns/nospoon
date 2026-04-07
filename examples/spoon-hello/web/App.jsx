import { useMemo } from 'react'
import { readSpoonHelloConfig } from './readConfig.js'

export function App () {
  const { signedPlainText } = useMemo(() => readSpoonHelloConfig(), [])

  return (
    <main className="app">
      <pre id="signature" className="signature">{signedPlainText}</pre>
    </main>
  )
}
