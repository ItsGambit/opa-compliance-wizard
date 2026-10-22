import { ChevronDown } from 'lucide-react'

/** The mockup's "Environment  prod-example ▾" control (the Overview's controls row and the Access Explorer's header): it names the active
 * environment and opens the Environments dialog, where it is changed. */
export function EnvironmentButton({ environment, onOpen }: { environment: string; onOpen?: () => void }) {
  return (
    <button type="button" className="text-input inline-flex items-center gap-1.5 !py-1.5 !px-2.5 min-h-[2.125rem]" onClick={onOpen} disabled={!onOpen}
      aria-label={`Environment: ${environment}. Open Environments`}>
      <span className="text-muted text-xs">Environment</span> {environment}<ChevronDown size={13} aria-hidden="true" className="text-muted" />
    </button>
  )
}
