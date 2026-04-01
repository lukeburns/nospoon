import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import './app.css'

const el = document.getElementById('root')
if (el) createRoot(el).render(<App />)
