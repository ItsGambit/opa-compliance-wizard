import { Check, UserPlus } from 'lucide-react'
import { useServiceAccount } from '../api/hooks'
import { useAddServiceAccountToGroup } from '../hooks/useAddServiceAccountToGroup'

interface Props {
  groupId: string
}

/** Renders next to any group shown as (or picked to become) a security-
 * policy or resource-group principal: "already a member" if this
 * dashboard's own service account is in the group, or a one-click "Add"
 * if not — the opt-in, "if it's not already there" counterpart to the
 * automatic add that happens for groups this dashboard creates itself
 * (see useCreateGroup). Renders nothing while the service account's own
 * membership hasn't loaded yet, rather than a loading flicker next to
 * every group in a list. */
export function ServiceAccountGroupStatus({ groupId }: Props) {
  const { data: serviceAccount } = useServiceAccount()
  const addMutation = useAddServiceAccountToGroup()

  if (!serviceAccount) return null

  if (serviceAccount.group_ids.includes(groupId)) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs text-win shrink-0"
        title={`'${serviceAccount.name}' (this dashboard's service account) is already a member`}
      >
        <Check size={12} /> service account
      </span>
    )
  }

  return (
    <button
      type="button"
      className="btn-secondary !py-0.5 !px-2 text-xs shrink-0"
      disabled={addMutation.isPending}
      onClick={() => addMutation.mutate(groupId)}
      title={`Add '${serviceAccount.name}' (this dashboard's service account) to this group`}
    >
      <UserPlus size={12} /> {addMutation.isPending ? 'Adding…' : 'Add service account'}
    </button>
  )
}
