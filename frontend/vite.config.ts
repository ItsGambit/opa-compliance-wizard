/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    // the shared CSV test cases live in ../tests/fixtures (read by the server's tests too)
    fs: { allow: ['..'] },
    proxy: {
      // changeOrigin: the backend refuses a Host other than its own
      // loopback name and port (5.53.0 local-mode Host check).
      '/api': { target: 'http://localhost:8766', changeOrigin: true },
    },
  },
  // Vitest reads this same config -- no separate vitest.config.ts needed.
  // jsdom (not happy-dom) since useAccessBootstrapJob's tests rely on
  // window.setInterval/clearInterval timer semantics jsdom implements
  // more completely.
  test: {
    environment: 'jsdom',
    globals: true,
  },
})
