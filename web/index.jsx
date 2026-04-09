import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import HowNospoonExplainerPage from './how-nospoon-explainer.jsx'
import './app.css'

const el = document.getElementById('root')
if (el) {
  const raw = window.location.pathname || '/'
  const path = raw.replace(/\/$/, '') || '/'
  if (path === '/how-nospoon') {
    createRoot(el).render(<HowNospoonExplainerPage />)
  } else {
    createRoot(el).render(<App />)
  }
}
