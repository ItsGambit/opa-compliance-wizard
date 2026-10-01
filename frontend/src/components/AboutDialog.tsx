import { useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { Info, X } from 'lucide-react'

interface Props {
  // Both optional -- omit for the self-contained trigger button (falls back
  // to internal state, unchanged behavior). Pass both when opened remotely
  // (e.g. SideNav's utility row).
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function AboutDialog({ open: openProp, onOpenChange }: Props = {}) {
  const [openState, setOpenState] = useState(false)
  const open = openProp ?? openState
  const setOpen = onOpenChange ?? setOpenState

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      {openProp === undefined && (
        <Dialog.Trigger asChild>
          <button type="button" className="btn-secondary !px-2" title="About / disclaimer">
            <Info size={14} />
          </button>
        </Dialog.Trigger>
      )}
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[26rem] p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">About OPA Compliance Wizard</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="text-text-faint hover:text-text-dim">
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>

          <div className="flex flex-col gap-3 text-xs text-text-dim leading-relaxed">
            <p>
              An unofficial, community tool that helps PAM admins pull the audit
              evidence their auditors ask for (SOC 2, SOX, ISO 27001, and similar
              frameworks) out of Okta Privileged Access (OPA) and core Okta audit
              history — plus building and managing OPA secret folders, resource
              groups, projects, groups, and security policies.
            </p>
            <div className="card p-3 bg-bg-hover border-warn text-text-dim">
              <p className="font-medium text-text mb-1">No warranty</p>
              <p>
                This tool is provided <strong>as-is, with no warranty of any kind</strong>,
                express or implied — including no warranty of merchantability, fitness
                for a particular purpose, or non-infringement. It makes real API calls
                that create, modify, and delete real objects in your OPA and Okta
                tenants. <strong>You are solely responsible for reviewing what it does
                before running it, especially against a production environment, and you
                assume all risk of using it.</strong> It is not an official Okta product
                and comes with no support commitment.
              </p>
            </div>
            <p className="text-text-faint">
              Licensed under MIT. Feedback and issues are welcome via the project's
              GitHub repository.
            </p>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
