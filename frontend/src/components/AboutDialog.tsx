import * as Dialog from '@radix-ui/react-dialog'
import { AFFILIATION, BRAND_BLURB, BRAND_TAGLINE } from '../utils/brand'
import { Brand } from './Brand'
import { DialogCloseButton } from './DialogCloseButton'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AboutDialog({ open, onOpenChange: setOpen }: Props) {

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content aria-describedby={undefined} className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[26rem] p-5">
          <div className="flex items-start justify-between mb-3">
            <Dialog.Title asChild>
              <h2 className="m-0"><Brand variant="lockup" tagline={BRAND_TAGLINE} /></h2>
            </Dialog.Title>
            <DialogCloseButton />
          </div>

          <div className="flex flex-col gap-3 text-xs text-text-dim leading-relaxed">
            <p>
              {BRAND_BLURB} It also includes Folder Builder, for creating OPA vault folders, resource groups,
              projects, groups and security policies.
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
            <p className="text-muted">{AFFILIATION}</p>
            <p className="text-muted">
              Licensed under MIT. Feedback and issues are welcome via the project's
              GitHub repository.
            </p>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
