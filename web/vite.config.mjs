import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const webRoot = dirname(fileURLToPath(import.meta.url))

/** Control server from `nospoon web` (override with NOSPOON_WEB_PROXY_TARGET). */
const proxyTarget = process.env.NOSPOON_WEB_PROXY_TARGET || 'http://127.0.0.1:8790'

const vitePortRaw = process.env.NOSPOON_WEB_VITE_PORT
const vitePort = vitePortRaw ? parseInt(vitePortRaw, 10) : 5173
const useOrchestratorPort = Number.isFinite(vitePort) && vitePort > 0 && vitePort <= 65535

export default defineConfig({
  root: webRoot,
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: useOrchestratorPort ? vitePort : 5173,
    strictPort: !!vitePortRaw,
    proxy: {
      '/api': {
        target: proxyTarget,
        changeOrigin: true
      }
    }
  }
})
