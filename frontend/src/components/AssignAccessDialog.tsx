import { useMemo, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, Plus, X } from 'lucide-react'
import { assignFolderPolicy } from '../api/client'
import { useGroups, useResourceGroupSecurityPolicies, useWorkloadRoles } from '../api/hooks'
import { useCreateGroup } from '../hooks/useCreateGroup'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, FolderSecurityPolicy, NamedRef } from '../types'
import { GroupCreateForm } from './GroupCreateForm'
import { Select } from './Select'
import { ServiceAccountGroupStatus } from './ServiceAccountGroupStatus'

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
  onSaved: (policy: FolderSecurityPolicy) => void
}

export function AssignAccessDialog({ open, onOpenChange, resourceGroupId, projectId, folderId, folderName, onSaved }: Props) {
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

  const { data: policies } = useResourceGroupSecurityPolicies(resourceGroupId, open)
  const { data: allGroups } = useGroups(open)
  const { data: workloadRoles } = useWorkloadRoles(open)
  const groups = (allGroups ?? []).filter(g => g.name !== 'everyone')

  const selectedPolicy = policies?.find(p => p.id === policyId)

  const toggleGroup = (id: string) =>
    setGroupIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  const toggleWorkloadRole = (id: string) =>
    setWorkloadRoleIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
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
  const blastRadius = useMemo(() => {
    if (mode !== 'existing' || !selectedPolicy) return null
    const existingGroupIds = new Set(selectedPolicy.principals.user_groups.map(g => g.id))
    const existingRoleIds = new Set(selectedPolicy.principals.workload_roles.map(r => r.id))
    const newGroups = [...groupIds].filter(id => !existingGroupIds.has(id))
    const newRoles = [...workloadRoleIds].filter(id => !existingRoleIds.has(id))
    if (newGroups.length === 0 && newRoles.length === 0) return null
    const otherRules = selectedPolicy.rules.filter(
      r => !r.targets.some(t => t.kind === 'resolved' && t.id === folderId)
    )
    if (otherRules.length === 0) return null
    return { newGroupNames: groups.filter(g => newGroups.includes(g.id)).map(g => g.name), otherRuleCount: otherRules.length }
  }, [mode, selectedPolicy, groupIds, workloadRoleIds, folderId, groups])

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

  const canSave =
    (mode === 'existing' ? !!policyId : name.trim().length > 0) &&
    (groupIds.size > 0 || workloadRoleIds.size > 0) &&
    Object.values(privileges).some(Boolean)

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/60 z-40" />
        <Dialog.Content className="card fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[34rem] max-h-[85vh] overflow-y-auto p-5">
          <div className="flex items-center justify-between mb-3">
            <Dialog.Title className="text-sm font-semibold text-text">Assign access — {folderName}</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" className="text-text-faint hover:text-text-dim">
                <X size={16} />
              </button>
            </Dialog.Close>
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
                <Select
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
              </div>
            ) : (
              <>
                <div className="flex flex-col gap-1">
                  <span className="section-label">Name</span>
                  <input value={name} onChange={e => setName(e.target.value)} className="text-input" placeholder="Policy name" />
                </div>
                <div className="flex flex-col gap-1">
                  <span className="section-label">Description (optional)</span>
                  <input value={description} onChange={e => setDescription(e.target.value)} className="text-input" />
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
                <span>
                  {blastRadius.newGroupNames.join(', ')} {blastRadius.newGroupNames.length === 1 ? 'is' : 'are'} not
                  currently a principal on this policy. Adding {blastRadius.newGroupNames.length === 1 ? 'it' : 'them'}{' '}
                  will also grant access to {blastRadius.otherRuleCount} other rule
                  {blastRadius.otherRuleCount === 1 ? '' : 's'} already in this policy — principals apply policy-wide,
                  not per-rule.
                </span>
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
                      type="number"
                      min={0}
                      value={mfaReauthSeconds}
                      onChange={e => setMfaReauthSeconds(Number(e.target.value))}
                      className="text-input w-32"
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-xs text-text-faint">ACR values</span>
                    <input value={mfaAcrValues} onChange={e => setMfaAcrValues(e.target.value)} className="text-input" />
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
