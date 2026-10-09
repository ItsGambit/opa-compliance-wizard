import { useState, useEffect, useCallback } from 'react'

export interface ToastMessage {
  id: string
  title: string
  description?: string
  variant?: 'default' | 'success' | 'error'
  /** Override how long it stays (ms) -- e.g. a warning that asks for a manual step. */
  duration?: number
}

type Listener = (msg: ToastMessage) => void
const listeners: Set<Listener> = new Set()

// UI-15 (external review, 2026-10-05): ids were Date.now(), so two toasts
// in the same millisecond (e.g. "group created" + "service account not
// added") shared one id -- duplicate React keys, and dismissing one removed
// both. A module counter is unique for the page's lifetime.
let nextToastId = 0

export function toast(msg: Omit<ToastMessage, 'id'>) {
  nextToastId += 1
  const message: ToastMessage = { ...msg, id: `toast-${nextToastId}` }
  listeners.forEach(l => l(message))
}

export function useToastMessages() {
  const [messages, setMessages] = useState<ToastMessage[]>([])

  useEffect(() => {
    const listener: Listener = (msg) => setMessages(prev => [...prev, msg])
    listeners.add(listener)
    return () => { listeners.delete(listener) }
  }, [])

  const dismiss = useCallback((id: string) => {
    setMessages(prev => prev.filter(m => m.id !== id))
  }, [])

  return { messages, dismiss }
}
