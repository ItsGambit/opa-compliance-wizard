import { useCrossChecks, useEnvironments } from '../api/hooks'
import type { AccessModel } from '../types'
import { UsersTab } from './UsersTab'

interface Props {
  model: AccessModel
  onUserGroupRemoved: (userId: string, groupId: string) => void
}

/** The Access Explorer Users view plus (5.50.0) the Okta lifecycle flags of cross-check C1: people whose Okta user
 * is deprovisioned, suspended or missing but who are still OPA principals. Read from the newest stored lookup; nothing
 * is shown until one has been run (Reports > Cross-checks). */
export function UsersView({ model, onUserGroupRemoved }: Props) {
  const { data: environments } = useEnvironments()
  const { data } = useCrossChecks(environments?.active ?? undefined)
  const okta = data?.user_flags.snapshot ? { capturedAt: data.user_flags.snapshot.captured_at, users: data.user_flags.users } : undefined
  return <UsersTab model={model} okta={okta} onUserGroupRemoved={onUserGroupRemoved} />
}
