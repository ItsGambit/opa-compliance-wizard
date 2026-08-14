import * as Toast from '@radix-ui/react-toast'
import { X } from 'lucide-react'
import { useToastMessages, type ToastMessage } from '../hooks/useToast'

export function ToastProvider() {
  const { messages, dismiss } = useToastMessages()

  return (
    <Toast.Provider swipeDirection="right" duration={3500}>
      {messages.map(m => (
        <ToastItem key={m.id} message={m} onDismiss={() => dismiss(m.id)} />
      ))}
      <Toast.Viewport className="fixed bottom-4 right-4 flex flex-col gap-2 z-[9999] w-80 max-w-[calc(100vw-2rem)]" />
    </Toast.Provider>
  )
}

function ToastItem({ message: m, onDismiss }: { message: ToastMessage; onDismiss: () => void }) {
  const borderColor = m.variant === 'error' ? 'border-loss/40' : m.variant === 'success' ? 'border-win/40' : 'border-border'
  const titleColor  = m.variant === 'error' ? 'text-loss' : m.variant === 'success' ? 'text-win' : 'text-text'

  return (
    <Toast.Root
      open
      onOpenChange={open => { if (!open) onDismiss() }}
      className={`bg-bg-elevated border ${borderColor} rounded-lg shadow-xl px-4 py-3 flex items-start gap-3
        data-[state=open]:animate-[slide-in-from-right_0.2s_ease-out]
        data-[state=closed]:animate-[slide-out-to-right_0.15s_ease-in]`}
    >
      <div className="flex-1 min-w-0">
        <Toast.Title className={`text-sm font-medium ${titleColor}`}>{m.title}</Toast.Title>
        {m.description && (
          <Toast.Description className="text-xs text-text-faint mt-0.5">{m.description}</Toast.Description>
        )}
      </div>
      <Toast.Close asChild>
        <button className="text-text-faint hover:text-text-dim transition-colors shrink-0 mt-0.5">
          <X size={13} />
        </button>
      </Toast.Close>
    </Toast.Root>
  )
}
