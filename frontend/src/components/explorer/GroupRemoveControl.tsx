import { useState } from 'react'

interface Props {
  groupName: string
  userName: string
  /** Other policies this group also backs: removal takes that access away too. */
  otherPolicyCount: number
  pending: boolean
  onConfirm: () => void
  /** Visible text of the trigger: "Remove" in the rail, "Remove from group" in a resource view. */
  label?: string
}

/** Remove one user from one group, with its own confirm step (destructive,
 * same as every other delete in this app) and the blast-radius warning when
 * the group also backs other policies. The actual mutation is the caller's
 * (useRemoveUserFromGroup); this is only the inline control. */
export function GroupRemoveControl({ groupName, userName, otherPolicyCount, pending, onConfirm, label = 'Remove' }: Props) {
  const [confirming, setConfirming] = useState(false)
  return (
    <>
      <button
        type="button"
        className="xp-linkbtn"
        title={`Remove '${userName}' from '${groupName}'`}
        aria-label={`${label} ${userName} from ${groupName}`}
        aria-expanded={confirming}
        onClick={() => setConfirming(c => !c)}
      >
        {label}
      </button>
      {confirming && (
        <div className="xp-confirm" role="group" aria-label={`Confirm removing ${userName} from ${groupName}`}>
          <span>
            Remove '{userName}' from '{groupName}'?
            {otherPolicyCount > 0 && (
              <>
                {' '}
                This group also backs {otherPolicyCount} other polic{otherPolicyCount === 1 ? 'y' : 'ies'} — removing
                takes away that access too, not just this one.
              </>
            )}
          </span>
          <button type="button" className="btn-danger !py-0.5 !px-2 shrink-0" disabled={pending} onClick={onConfirm}>
            {pending ? 'Removing…' : 'Yes, remove'}
          </button>
          <button type="button" className="btn-secondary !py-0.5 !px-2 shrink-0" disabled={pending} onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      )}
    </>
  )
}
