import { useEffect, useMemo, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, Plus } from 'lucide-react'
import { assignFolderPolicy } from '../api/client'
import { useGroups, useResourceGroupSecurityPolicies, useWorkloadRoles } from '../api/hooks'
import { useCreateGroup } from '../hooks/useCreateGroup'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, FolderAccessEntry, FolderSecurityPolicy, NamedRef } from '../types'
import { DialogCloseButton } from './DialogCloseButton'
import { GroupCreateForm } from './GroupCreateForm'
import { Select } from './Select'
import { ServiceAccountGroupStatus } from './ServiceAccountGroupStatus'
import { computeBlastRadius, describeBlastRadius } from '../utils/blastRadius'

const PRIVILEGE_GROUPS: { label: string; fields: { key: string; label: string }[] }[] = [
  { label: 'Access', fields: [{ key: 'list', label: 'List contents' }] },
  {
    label: 'Secrets',
    fields: [
      { key: 'secret_create', label: 'Create' },
      { key: 'secret_update', label: 'Update' },
      { key: 'secret_delete', label: 'Delete' },
      { key: 'secret_reveal', label: 'Reveal' },
    ],
  },
  {
    label: 'Folders',
    fields: [
      { key: 'folder_create', label: 'Create' },
      { key: 'folder_update', label: 'Update' },
      { key: 'folder_delete', label: 'Delete' },
    ],
  },
]

function MultiSelect({
  options,
  selectedIds,
  onToggle,
  emptyText,
}: {
  options: NamedRef[]
  selectedIds: Set<string>
  onToggle: (id: string) => void
  emptyText: string
}) {
  return (
    <div className="border border-border rounded-md max-h-32 overflow-y-auto p-1.5 flex flex-col gap-0.5">
      {options.length === 0 && <span className="text-xs text-text-faint px-1 py-1">{emptyText}</span>}
      {options.map(opt => (
        <label key={opt.id} className="flex items-center gap-2 text-sm text-text-dim px-1 py-0.5 rounded hover:bg-bg-hover cursor-pointer">
          <input type="checkbox" checked={selectedIds.has(opt.id)} onChange={() => onToggle(opt.id)} />
          {opt.name}
        </label>
      ))}
    </div>
  )
}

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  resourceGroupId: string
  projectId: string
  folderId: string
  folderName: string
  /** UI-01 (external review, 2026-10-05): the rule(s) that ALREADY grant
   * access to this folder, from FolderBuilder's own accessByPath (built
   * by utils/folderAccess.resolveFolderAccess) -- lets this dialog
   * prefill from the rule it's about to replace instead of always
   * starting blank. Undefined when the folder has no existing rule at
   * all (a genuine first-time assignment, where a blank form is
   * correct). */
  existingAccess?: FolderAccessEntry[]
  onSaved: (policy: FolderSecurityPolicy) => void
}

export function AssignAccessDialog({ open, onOpenChange, resourceGroupId, projectId, folderId, folderName, existingAccess, onSaved }: Props) {
  const [mode, setMode] = useState<'existing' | 'new'>('existing')
  const [policyId, setPolicyId] = useState<string | undefined>(undefined)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [groupIds, setGroupIds] = useState<Set<string>>(new Set())
  const [creatingGroup, setCreatingGroup] = useState(false)
  const [workloadRoleIds, setWorkloadRoleIds] = useState<Set<string>>(new Set())
  const [privileges, setPrivileges] = useState<Record<string, boolean>>({})
  const [requireMfa, setRequireMfa] = useState(false)
  const [mfaReauthSeconds, setMfaReauthSeconds] = useState(1800)
  const [mfaAcrValues, setMfaAcrValues] = useState('urn:okta:loa:2fa:any')
  // Tracks which policyId the form fields were last prefilled FROM, so
  // the prefill effect below only fires once per policy selection (not
  // on every keystroke after the user starts editing the prefilled
  // values).
  const [prefilledForPolicyId, setPrefilledForPolicyId] = useState<string | undefined>(undefined)

  const { data: policies } = useResourceGroupSecurityPolicies(resourceGroupId, open)
  const { data: allGroups } = useGroups(open)
  const { data: workloadRoles } = useWorkloadRoles(open)
  // Memoised (UI-20): rebuilt on every render it defeated every memo below.
  const groups = useMemo(() => (allGroups ?? []).filter(g => g.name !== 'everyone'), [allGroups])

  const selectedPolicy = policies?.find(p => p.id === policyId)
  const existingEntryForSelectedPolicy = existingAccess?.find(e => e.policyId === policyId)

  // Prefill privileges/MFA/groups/workload-roles from the rule this
  // save is actually about to replace, the moment the admin picks a
  // policy that already has one -- a blank-start form is what let
  // AssignAccessDialog silently drop an existing MFA condition (and
  // every unticked privilege) before this fix. Runs once per policy
  // selection, not on every render, so it doesn't fight the admin's own
  // edits afterward.
  useEffect(() => {
    if (mode !== 'existing' || !existingEntryForSelectedPolicy || prefilledForPolicyId === policyId) return
    setPrefilledForPolicyId(policyId)
    const entry = existingEntryForSelectedPolicy
    setGroupIds(new Set(entry.groups.map(g => g.id)))
    setWorkloadRoleIds(new Set(entry.workloadRoles.map(w => w.id)))
    const privilegeFlags: Record<string, boolean> = {}
    for (const p of entry.privileges) for (const flag of p.flags) privilegeFlags[flag] = true
    setPrivileges(privilegeFlags)
    const mfaCondition = entry.conditions.find(c => c.condition_type === 'mfa')
    setRequireMfa(!!mfaCondition)
    if (mfaCondition) {
      const value = mfaCondition.condition_value as { re_auth_frequency_in_seconds?: number; acr_values?: string }
      if (typeof value.re_auth_frequency_in_seconds === 'number') setMfaReauthSeconds(value.re_auth_frequency_in_seconds)
      if (typeof value.acr_values === 'string') setMfaAcrValues(value.acr_values)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, policyId, existingEntryForSelectedPolicy])

  const toggleGroup = (id: string) =>
    setGroupIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const toggleWorkloadRole = (id: string) =>
    setWorkloadRoleIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const togglePrivilege = (key: string) => setPrivileges(prev => ({ ...prev, [key]: !prev[key] }))

  const createGroupMutation = useCreateGroup(group => {
    setGroupIds(prev => new Set(prev).add(group.id))
    setCreatingGroup(false)
  })

  // Blast-radius warning: principals apply to the WHOLE policy, so adding
  // a group/role that isn't already a principal grants it every other
  // rule already in that policy too — not just this folder.
  const blastRadius = useMemo(
    () => (mode === 'existing' ? computeBlastRadius(selectedPolicy, groupIds, workloadRoleIds, folderId, groups, workloadRoles ?? []) : null),
    [mode, selectedPolicy, groupIds, workloadRoleIds, folderId, groups, workloadRoles],
  )

  const mutation = useMutation({
    mutationFn: () => {
      const group_refs: NamedRef[] = groups.filter(g => groupIds.has(g.id)).map(g => ({ id: g.id, name: g.name }))
      const workload_role_refs: NamedRef[] = (workloadRoles ?? [])
        .filter(w => workloadRoleIds.has(w.id))
        .map(w => ({ id: w.id, name: w.name }))
      return assignFolderPolicy(resourceGroupId, projectId, folderId, {
        mode,
        policy_id: mode === 'existing' ? policyId : undefined,
        name: mode === 'new' ? name.trim() : undefined,
        description: mode === 'new' ? description.trim() : undefined,
        folder_name: folderName,
        group_refs,
        workload_role_refs,
        privileges,
        mfa: requireMfa ? { reauth_seconds: mfaReauthSeconds, acr_values: mfaAcrValues } : null,
      })
    },
    onSuccess: (resp) => {
      toast({ title: `Access saved for '${folderName}'`, variant: 'success' })
      onSaved(resp.policy)
      onOpenChange(false)
    },
    onError: (err: Error & { body?: ApiErrorBody }) =>
      toast({ title: 'Could not save access', description: err.body?.error ?? err.message, variant: 'error' }),
  })

  // UI-01: the server refuses this exact case (MultiTargetRuleError) --
  // blocking Save here just saves the admin a round trip to find out.
  const targetsSharedRule = !!existingEntryForSelectedPolicy && existingEntryForSelectedPolicy.targetCount > 1
  const canSave =
    (mode === 'existing' ? !!policyId : name.trim().length > 0) &&
    (groupIds.size > 0 || workloadRoleIds.size > 0) &&
    Object.values(privileges).some(Boolean) &&
    !targetsSharedRule

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content aria-describedby={undefined} className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] sm:w-[34rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Assign access — {folderName}</Dialog.Title>
            <DialogCloseButton />
          </div>

          <div className="flex flex-col gap-4">
            <div className="flex gap-4">
              <label className="flex items-center gap-1.5 text-sm text-text-dim cursor-pointer">
                <input type="radio" checked={mode === 'existing'} onChange={() => setMode('existing')} />
                Use existing policy
              </label>
              <label className="flex items-center gap-1.5 text-sm text-text-dim cursor-pointer">
                <input type="radio" checked={mode === 'new'} onChange={() => setMode('new')} />
                Create new policy
              </label>
            </div>

            {mode === 'existing' ? (
              <div className="flex flex-col gap-1">
                <span className="section-label">Policy (scoped to this resource group)</span>
                <Select ariaLabel="Policy"
                  value={policyId}
                  onValueChange={setPolicyId}
                  placeholder="Select a policy"
                  options={(policies ?? []).map(p => ({ value: p.id, label: p.name }))}
                />
                {selectedPolicy && selectedPolicy.principals.user_groups.length > 0 && (
                  <div className="flex flex-col gap-1 mt-1">
                    <span className="text-xs text-text-faint">
                      This policy's current principal group{selectedPolicy.principals.user_groups.length === 1 ? '' : 's'}:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {selectedPolicy.principals.user_groups.map(g => (
                        <div key={g.id} className="flex items-center gap-1.5 text-xs text-text-dim bg-bg-hover rounded px-1.5 py-1">
                          {g.name}
                          <ServiceAccountGroupStatus groupId={g.id} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {/* UI-01: this save REPLACES the rule below -- the form
                    above is now prefilled from it, but the admin should
                    still see explicitly what's about to be overwritten,
                    especially for a rule whose own name differs from
                    what this dialog would otherwise generate. */}
                {existingEntryForSelectedPolicy && (
                  existingEntryForSelectedPolicy.targetCount > 1 ? (
                    <div className="flex items-start gap-2 text-xs text-loss bg-loss/10 border border-loss/40 rounded-md p-2 mt-1">
                      <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                      <span>
                        The matched rule &ldquo;{existingEntryForSelectedPolicy.ruleName}&rdquo; also covers{' '}
                        {existingEntryForSelectedPolicy.targetCount - 1} other folder
                        {existingEntryForSelectedPolicy.targetCount - 1 === 1 ? '' : 's'}. Saving here would be
                        refused by the server — edit this rule directly in OPA instead to avoid dropping access to
                        the others.
                      </span>
                    </div>
                  ) : (
                    <div className="text-xs text-text-faint mt-1">
                      This will replace the existing rule &ldquo;{existingEntryForSelectedPolicy.ruleName}
                      &rdquo; — fields above are prefilled from it.
                    </div>
                  )
                )}
              </div>
            ) : (
              <>
                <div className="flex flex-col gap-1">
                  <span className="section-label">Name</span>
                  <input aria-label="Name" value={name} onChange={e => setName(e.target.value)} className="text-input" placeholder="Policy name" />
                </div>
                <div className="flex flex-col gap-1">
                  <span className="section-label">Description (optional)</span>
                  <input aria-label="Description" value={description} onChange={e => setDescription(e.target.value)} className="text-input" />
                </div>
              </>
            )}

            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span className="section-label">Group(s)</span>
                {!creatingGroup && (
                  <button type="button" className="btn-secondary !py-0.5 !px-2 text-xs" onClick={() => setCreatingGroup(true)}>
                    <Plus size={12} /> New Group
                  </button>
                )}
              </div>
              <MultiSelect options={groups} selectedIds={groupIds} onToggle={toggleGroup} emptyText="No groups found" />
              {groupIds.size > 0 && (
                <div className="flex flex-wrap gap-2 mt-1">
                  {groups.filter(g => groupIds.has(g.id)).map(g => (
                    <div key={g.id} className="flex items-center gap-1.5 text-xs text-text-dim bg-bg-hover rounded px-1.5 py-1">
                      {g.name}
                      <ServiceAccountGroupStatus groupId={g.id} />
                    </div>
                  ))}
                </div>
              )}
              {creatingGroup && (
                <GroupCreateForm mutation={createGroupMutation} onCancel={() => setCreatingGroup(false)} />
              )}
            </div>

            <div className="flex flex-col gap-1">
              <span className="section-label">Workload role(s) (service identities, optional)</span>
              <MultiSelect
                options={workloadRoles ?? []}
                selectedIds={workloadRoleIds}
                onToggle={toggleWorkloadRole}
                emptyText="No workload roles defined for this team"
              />
            </div>

            {blastRadius && (
              <div className="flex items-start gap-2 text-xs text-warn bg-warn/10 border border-warn/40 rounded-md p-2">
                <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                <span>{describeBlastRadius(blastRadius)}</span>
              </div>
            )}

            <div className="flex flex-col gap-2">
              <span className="section-label">Privileges</span>
              {PRIVILEGE_GROUPS.map(group => (
                <div key={group.label} className="flex flex-col gap-1">
                  <span className="text-xs text-text-faint">{group.label}</span>
                  <div className="flex flex-wrap gap-3">
                    {group.fields.map(f => (
                      <label key={f.key} className="flex items-center gap-1.5 text-sm text-text-dim cursor-pointer">
                        <input type="checkbox" checked={!!privileges[f.key]} onChange={() => togglePrivilege(f.key)} />
                        {f.label}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex flex-col gap-2">
              <label className="flex items-center gap-1.5 text-sm text-text-dim cursor-pointer">
                <input type="checkbox" checked={requireMfa} onChange={e => setRequireMfa(e.target.checked)} />
                Require MFA
              </label>
              {requireMfa && (
                <div className="flex gap-3 pl-6">
                  <div className="flex flex-col gap-1">
                    <span className="text-xs text-text-faint">Re-auth every (seconds, 0 = once per session)</span>
                    <input
                      aria-label="Re-auth every (seconds, 0 = once per session)"
                      type="number"
                      min={0}
                      value={mfaReauthSeconds}
                      onChange={e => setMfaReauthSeconds(Number(e.target.value))}
                      className="text-input w-32"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-xs text-text-faint">ACR values</span>
                    <input aria-label="ACR values" value={mfaAcrValues} onChange={e => setMfaAcrValues(e.target.value)} className="text-input" />
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-2">
              <Dialog.Close asChild>
                <button type="button" className="btn-secondary">
                  Cancel
                </button>
              </Dialog.Close>
              <button type="button" className="btn-primary" disabled={!canSave || mutation.isPending} onClick={() => mutation.mutate()}>
                {mutation.isPending ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
