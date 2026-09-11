import { LogOut } from 'lucide-react'
import { useWhoami } from '../api/hooks'

// Shown only when this dashboard is running behind the Okta login gate
// (nginx auth_request -> server/auth_gate.py) -- a direct/local run has no
// login to display or log out of, and /api/whoami reports that via
// is_local rather than the frontend guessing from the URL/environment.
export function UserMenu() {
  const { data: whoami } = useWhoami()

  if (!whoami || whoami.is_local) {
    return null
  }

  return (
    <div className="flex items-center gap-2 text-xs text-text-faint">
      <span className="text-text-dim font-medium" title="Signed in via Okta">
        {whoami.email}
      </span>
      <a
        href="/logout"
        className="btn-secondary !px-2 inline-flex items-center"
        title="Log out"
      >
        <LogOut size={14} />
      </a>
    </div>
  )
}
