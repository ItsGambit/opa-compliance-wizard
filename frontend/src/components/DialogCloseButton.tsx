import * as Dialog from '@radix-ui/react-dialog'
import { X } from 'lucide-react'

/** The icon-only "X" every dialog had, now with an accessible name
 * (UI-19: screen readers announced each one as just "button"). */
export function DialogCloseButton({ label = 'Close', size = 16 }: { label?: string; size?: number }) {
  return (
    <Dialog.Close asChild>
      <button type="button" aria-label={label} title={label} className="text-text-faint hover:text-text-dim">
        <X size={size} aria-hidden="true" />
      </button>
    </Dialog.Close>
  )
}
