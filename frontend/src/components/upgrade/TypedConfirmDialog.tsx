import { useState, type ReactNode } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { DialogCloseButton } from '../DialogCloseButton'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  /** The word the admin must type exactly (ROLLBACK, PRUNE); omitted = a plain confirmation (still followed by the MFA approval). */
  word?: string
  confirmLabel: string
  busy?: boolean
  danger?: boolean
  onConfirm: () => void
}

/** A destructive or state-changing request: say what it does, make the admin type the word, then (hosted mode) the MFA approval follows. */
export function TypedConfirmDialog({ open, onOpenChange, title, children, word, confirmLabel, busy, danger, onConfirm }: Props) {
  const [typed, setTyped] = useState('')
  return (
    <Dialog.Root open={open} onOpenChange={o => { if (!o) setTyped(''); onOpenChange(o) }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content aria-describedby="typed-desc" className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[32rem] max-h-[90vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-2">
            <Dialog.Title className="m-0 text-sm font-semibold text-text">{title}</Dialog.Title>
            <DialogCloseButton />
          </div>
          <div id="typed-desc" className="text-xs text-text-dim flex flex-col gap-2">{children}</div>
          {word && (
            <div className="flex items-center gap-2 flex-wrap mt-3">
              <label htmlFor="typed-word" className="section-label">Type <code className="font-mono normal-case">{word}</code> to confirm</label>
              <input id="typed-word" className="text-input w-40" autoComplete="off" spellCheck={false} value={typed} onChange={e => setTyped(e.target.value)} />
            </div>
          )}
          <p className="text-xs text-muted mt-2 mb-0">Then a step-up MFA approval. Nothing changes until you return from it.</p>
          <div className="flex justify-end gap-2 mt-4">
            <button type="button" className="btn-secondary !text-text-dim" onClick={() => onOpenChange(false)}>Cancel</button>
            <button type="button" className={danger ? 'btn-primary !bg-loss' : 'btn-primary'} disabled={(!!word && typed !== word) || busy}
              onClick={() => { setTyped(''); onConfirm() }}>{confirmLabel}</button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
