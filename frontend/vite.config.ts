/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8766',
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
