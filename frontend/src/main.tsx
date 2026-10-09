import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import './index.css'
import App from './App.tsx'
import { ToastProvider } from './components/ToastProvider.tsx'
import { SessionExpiredDialog } from './components/SessionExpiredDialog.tsx'
import { createQueryClient } from './api/queryClient.ts'

const queryClient = createQueryClient()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
      <ToastProvider />
      <SessionExpiredDialog />
    </QueryClientProvider>
  </StrictMode>,
)
