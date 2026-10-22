import * as Toast from '@radix-ui/react-toast'
import { X } from 'lucide-react'
import { useToastMessages, type ToastMessage } from '../hooks/useToast'

/** Success/info toasts stay 3.5 s; errors and warnings carry text the user
 * may need to read (or act on), so they stay 8 s (UI-15). Hovering or
 * focusing a toast pauses its timer (Radix Toast). */
export const TOAST_DURATION_MS = 3500
export const ERROR_TOAST_DURATION_MS = 8000

export function ToastProvider() {
  const { messages, dismiss } = useToastMessages()

  return (
    <Toast.Provider swipeDirection="right" duration={TOAST_DURATION_MS}>
      {messages.map(m => (
        <ToastItem key={m.id} message={m} onDismiss={() => dismiss(m.id)} />
      ))}
      <Toast.Viewport className="fixed bottom-4 right-4 flex flex-col gap-2 z-[9999] w-80 max-w-[calc(100vw-2rem)]" />
    </Toast.Provider>
  )
}

function ToastItem({ message: m, onDismiss }: { message: ToastMessage; onDismiss: () => void }) {
  // A neutral card with a coloured left edge (the approved mockup's toast); the state is also in the words of the title.
  const edge = m.variant === 'error' ? 'border-l-loss' : m.variant === 'success' ? 'border-l-win' : m.variant === 'warning' ? 'border-l-warn' : 'border-l-border'
  const titleColor = 'text-text'

  return (
    <Toast.Root
      open
      duration={m.duration ?? (m.variant === 'error' || m.variant === 'warning' ? ERROR_TOAST_DURATION_MS : undefined)}
      onOpenChange={open => { if (!open) onDismiss() }}
      className={`bg-bg-elevated border border-border border-l-[3px] ${edge} rounded-lg shadow-xl px-4 py-3 flex items-start gap-3
        data-[state=open]:animate-[slide-in-from-right_0.2s_ease-out]
        data-[state=closed]:animate-[slide-out-to-right_0.15s_ease-in]`}
    >
      <div className="flex-1 min-w-0">
        <Toast.Title className={`text-sm font-semibold ${titleColor}`}>{m.title}</Toast.Title>
        {m.description && (
          <Toast.Description className="text-xs text-text-faint mt-0.5">{m.description}</Toast.Description>
        )}
        {m.action && (
          <a href={m.action.href} className="text-xs text-accent-text underline underline-offset-2 mt-1 inline-block">{m.action.label}</a>
        )}
      </div>
      <Toast.Close asChild>
        <button type="button" aria-label="Dismiss notification" className="text-text-faint hover:text-text-dim transition-colors shrink-0 mt-0.5">
          <X size={13} aria-hidden="true" />
        </button>
      </Toast.Close>
    </Toast.Root>
  )
}
