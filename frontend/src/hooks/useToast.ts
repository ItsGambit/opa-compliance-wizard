import { useState, useEffect, useCallback } from 'react'

export interface ToastMessage {
  id: string
  title: string
  description?: string
  variant?: 'default' | 'success' | 'error'
}

type Listener = (msg: ToastMessage) => void
const listeners: Set<Listener> = new Set()

export function toast(msg: Omit<ToastMessage, 'id'>) {
  const message: ToastMessage = { ...msg, id: String(Date.now()) }
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
