import { useEffect, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Megaphone, X } from 'lucide-react'
import { saveBanner } from '../api/client'
import { useBanner } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { BannerVariant } from '../types'

const VARIANTS: { value: BannerVariant; label: string }[] = [
  { value: 'info', label: 'Info (blue)' },
  { value: 'warning', label: 'Warning (amber)' },
  { value: 'danger', label: 'Danger (red)' },
]

interface Props {
  // Both optional -- omit for the self-contained trigger button (falls back
  // to internal state, unchanged behavior). Pass both when opened remotely
  // (e.g. SideNav's utility row).
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function BannerSettingsDialog({ open: openProp, onOpenChange }: Props = {}) {
  const [openState, setOpenState] = useState(false)
  const open = openProp ?? openState
  const setOpen = onOpenChange ?? setOpenState
  const { data: banner } = useBanner()
  const queryClient = useQueryClient()

  const [enabled, setEnabled] = useState(false)
  const [message, setMessage] = useState('')
  const [variant, setVariant] = useState<BannerVariant>('warning')
  const [dismissible, setDismissible] = useState(true)

  // Re-seed the form from the server every time the dialog opens, so a
  // second admin's more recent edit isn't silently clobbered by whatever
  // this browser happened to have open before.
  useEffect(() => {
    if (open && banner) {
      setEnabled(banner.enabled)
      setMessage(banner.message)
      setVariant(banner.variant)
      setDismissible(banner.dismissible)
    }
  }, [open, banner])

  const saveMutation = useMutation({
    mutationFn: () => saveBanner({ enabled, message, variant, dismissible }),
    onSuccess: () => {
      toast({ title: enabled ? 'Banner published' : 'Banner disabled', variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['banner'] })
      setOpen(false)
    },
    onError: (err: Error) => toast({ title: 'Could not save banner', description: err.message, variant: 'error' }),
  })

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      {openProp === undefined && (
        <Dialog.Trigger asChild>
          <button type="button" className="btn-secondary !px-2" title="Announcement banner">
            <Megaphone size={14} />
          </button>
        </Dialog.Trigger>
      )}
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[28rem] p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Announcement banner</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="text-text-faint hover:text-text-dim">
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>

          <p className="text-xs text-text-faint mb-4">
            Shown at the top of every page for everyone using this dashboard — for
            planned maintenance, a known incident, or any org-wide notice.
          </p>

          <div className="flex flex-col gap-3">
            <label className="flex items-center gap-2 text-sm text-text cursor-pointer">
              <input
                type="checkbox"
                checked={enabled}
                onChange={e => setEnabled(e.target.checked)}
                className="accent-accent"
              />
              Show banner
            </label>

            <div className="field">
              <label className="section-label block mb-1">Message</label>
              <textarea
                className="text-input w-full min-h-20 resize-y"
                value={message}
                onChange={e => setMessage(e.target.value)}
                placeholder="e.g. Scheduled OPA maintenance Sat 10pm–12am PT — creates/updates will be paused."
              />
            </div>

            <div className="field">
              <label className="section-label block mb-1">Style</label>
              <select
                className="text-input w-full"
                value={variant}
                onChange={e => setVariant(e.target.value as BannerVariant)}
              >
                {VARIANTS.map(v => (
                  <option key={v.value} value={v.value}>{v.label}</option>
                ))}
              </select>
            </div>

            <label className="flex items-center gap-2 text-sm text-text cursor-pointer">
              <input
                type="checkbox"
                checked={dismissible}
                onChange={e => setDismissible(e.target.checked)}
                className="accent-accent"
              />
              Let viewers dismiss it
            </label>
          </div>

          <div className="flex justify-end gap-2 mt-5">
            <Dialog.Close asChild>
              <button type="button" className="btn-secondary">Cancel</button>
            </Dialog.Close>
            <button
              type="button"
              className="btn-primary"
              disabled={saveMutation.isPending || (enabled && !message.trim())}
              onClick={() => saveMutation.mutate()}
            >
              Save
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
