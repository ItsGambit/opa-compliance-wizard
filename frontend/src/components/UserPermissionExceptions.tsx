import { useId, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { isStepUpRequired, saveSharedPermissions } from '../api/client'
import { toast } from '../hooks/useToast'
import type {
  Environment, GrantUser, PermissionSetting, SharedCapabilityKey, SharedPermissionsResponse,
} from '../types'
import { SOURCE_LABELS, changedSettings, groupGrants, orgLabel, userKey, valueLabel } from '../utils/sharedPermissions'
import { beginStepUp } from '../utils/stepUp'
import { PermissionSettingsList } from './PermissionSettingsList'

type Settings = Partial<Record<SharedCapabilityKey, PermissionSetting>>

// The shapes the server accepts (create_secret_folders.SHARED_GRANT_*):
// a login gate's Okta issuer, and an Okta user id.
const ISSUER = /^https:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(\/oauth2\/[A-Za-z0-9]{1,64})?$/
const SUBJECT = /^[A-Za-z0-9]{1,64}$/
const MANUAL = '__manual__'

/** 5.43.0, admin-only: exceptions for one user on one environment -- they
 * beat the environment's own setting, for that user only. A user is the
 * Okta org that signed them in (the gate's issuer) plus their Okta user id
 * there; an id alone could belong to someone in another org. */
export function UserPermissionExceptions({ env, data, draftUser, draft }: {
  env: Environment
  data: SharedPermissionsResponse
  /** A user exception restored after an MFA approval that didn't complete. */
  draftUser?: GrantUser
  draft?: Settings
}) {
  const queryClient = useQueryClient()
  const base = useId()
  const row = data.environments[env.id]
  const grants = row?.grants ?? []
  const identities = data.identities ?? []
  const knownKeys = new Set(identities.map(userKey))

  const storedFor = (user: GrantUser | null): Settings => {
    const out: Settings = {}
    for (const cap of data.capabilities) out[cap.key] = 'inherit'
    if (user) for (const g of grants) if (g.issuer === user.issuer && g.subject === user.subject) out[g.capability] = g.value
    return out
  }
  // What the edited values were seeded from: the user and their stored
  // exceptions -- a different user, or new data from the server, re-seeds.
  const seedKey = (user: GrantUser | null) => (user ? `${userKey(user)}|${JSON.stringify(storedFor(user))}` : '')

  const [choice, setChoice] = useState<string>(() =>
    draftUser ? (knownKeys.has(userKey(draftUser)) ? userKey(draftUser) : MANUAL) : '')
  const [manual, setManual] = useState<GrantUser>(() =>
    draftUser && !knownKeys.has(userKey(draftUser)) ? draftUser : { issuer: '', subject: '' })
  // A typed user takes effect only on "Use this user", so editing the id
  // after choosing settings never silently re-seeds them.
  const [committed, setCommitted] = useState<GrantUser | null>(() =>
    draftUser && !knownKeys.has(userKey(draftUser)) ? draftUser : null)
  const manualValid = ISSUER.test(manual.issuer.trim()) && SUBJECT.test(manual.subject.trim())
  const [settings, setSettings] = useState<Settings>(() => (draftUser && draft ? { ...draft } : {}))
  const [seededFor, setSeededFor] = useState<string>(() => seedKey(draftUser ?? null))

  const selected: GrantUser | null =
    choice === MANUAL
      ? committed
      : choice
        ? (() => { const [issuer, subject] = choice.split(' '); return { issuer, subject } })()
        : null

  const currentSeed = seedKey(selected)
  if (currentSeed !== seededFor) {
    setSeededFor(currentSeed)
    setSettings(storedFor(selected))
  }

  const changes = selected ? changedSettings(storedFor(selected), settings) : {}
  const save = useMutation({
    mutationFn: () => saveSharedPermissions(changes, env.id, selected!),
    onSuccess: (resp) => {
      if (isStepUpRequired(resp)) {
        beginStepUp(resp.action_id, {
          kind: 'environment_change', action: resp.action, label: `A user exception on '${env.name}'`,
          startedAt: Date.now(), reopen: 'environments',
          permissionsDraft: { environmentId: env.id, user: selected!, settings },
        })
        return
      }
      toast({ title: `User exception on '${env.name}' saved`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['shared_permissions'] })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
    onError: (err: Error) => toast({ title: 'Could not save the user exception', description: err.message, variant: 'error' }),
  })

  // An older server sends no grants and would ignore `user`, saving the
  // change for EVERY shared user -- never offer the section there.
  if (!row || row.grants === undefined) return null
  const who = selected ? (identities.find(i => userKey(i) === userKey(selected))?.email ?? selected.subject) : ''
  const groups = groupGrants(grants)
  const label = (cap: SharedCapabilityKey) => data.capabilities.find(c => c.key === cap)?.label ?? cap
  return (
    <section className="flex flex-col gap-2 border-t border-border-sub pt-2" aria-labelledby={`${base}-title`}>
      <h4 id={`${base}-title`} className="text-xs font-semibold text-text">Per-user exceptions</h4>
      <p className="text-[0.6875rem] text-text-dim">
        Allow or refuse one user something on '{env.name}', whatever the setting above says. A user is the Okta
        org that signed them in plus their Okta user id there, so the same person signing in through another
        login address (another Okta org) is someone else.
      </p>
      {groups.length > 0 ? (
        <ul className="flex flex-col gap-1" aria-label={`Users with exceptions on ${env.name}`}>
          {groups.map(g => (
            <li key={userKey(g.user)} className="card p-2 flex flex-wrap items-center gap-2 text-[0.6875rem]">
              <span className="font-medium text-text" title={`${g.user.issuer} · ${g.user.subject}`}>
                {g.email ?? 'E-mail not seen yet'}
              </span>
              <span className="text-text-dim">{orgLabel(g.user.issuer)} · {g.user.subject}</span>
              <span className="flex-1 text-text-dim">
                {g.grants.map(x => `${label(x.capability)}: ${valueLabel(x.value).toLowerCase()}`).join(' · ')}
              </span>
              <button
                type="button"
                className="btn-secondary !py-0.5 !px-1.5 text-[0.6875rem]"
                aria-label={`Edit the exceptions for ${g.email ?? g.user.subject}`}
                onClick={() => {
                  if (knownKeys.has(userKey(g.user))) setChoice(userKey(g.user))
                  else { setManual(g.user); setCommitted(g.user); setChoice(MANUAL) }
                }}
              >
                Edit
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[0.6875rem] text-text-dim">No user has an exception here.</p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={`${base}-user`} className="text-xs font-medium text-text">User</label>
        <select
          id={`${base}-user`}
          className="text-input !py-1 text-xs min-w-[14rem]"
          value={choice}
          disabled={save.isPending}
          onChange={e => { setChoice(e.target.value); setCommitted(null) }}
        >
          <option value="">Choose a user…</option>
          {identities.map(i => (
            <option key={userKey(i)} value={userKey(i)}>
              {i.email ?? 'no e-mail'} — {orgLabel(i.issuer)} · {i.subject}
            </option>
          ))}
          <option value={MANUAL}>Enter an Okta issuer and user id…</option>
        </select>
      </div>
      {identities.length === 0 && (
        <p className="text-[0.6875rem] text-text-dim">
          The list shows users who have signed in since this version was installed.
        </p>
      )}
      {choice === MANUAL && (
        <div className="flex flex-wrap gap-2">
          <label className="flex flex-col gap-0.5 text-[0.6875rem] text-text-dim flex-1 min-w-[14rem]">
            Okta issuer (the login gate's)
            <input
              className="text-input !py-1 text-xs"
              placeholder="https://your-org.okta.com/oauth2/default"
              value={manual.issuer}
              disabled={save.isPending}
              onChange={e => setManual(m => ({ ...m, issuer: e.target.value }))}
              aria-invalid={manual.issuer !== '' && !ISSUER.test(manual.issuer.trim())}
            />
          </label>
          <label className="flex flex-col gap-0.5 text-[0.6875rem] text-text-dim min-w-[10rem]">
            Okta user id
            <input
              className="text-input !py-1 text-xs"
              placeholder="00u…"
              value={manual.subject}
              disabled={save.isPending}
              onChange={e => setManual(m => ({ ...m, subject: e.target.value }))}
              aria-invalid={manual.subject !== '' && !SUBJECT.test(manual.subject.trim())}
            />
          </label>
          <button
            type="button"
            className="btn-secondary self-end !py-0.5 !px-2 text-xs"
            disabled={!manualValid || save.isPending ||
              (committed !== null && userKey(committed) === `${manual.issuer.trim()} ${manual.subject.trim()}`)}
            onClick={() => setCommitted({ issuer: manual.issuer.trim(), subject: manual.subject.trim() })}
          >
            Use this user
          </button>
        </div>
      )}
      {selected && (
        <div className="flex flex-col gap-2" role="group" aria-label={`Exceptions for ${who} on ${env.name}`}>
          <PermissionSettingsList
            capabilities={data.capabilities}
            settings={settings}
            onChange={(key, value) => setSettings(s => ({ ...s, [key]: value }))}
            inherited={key => ({ value: row.effective[key].value, from: 'this environment' })}
            current={key => {
              const own = storedFor(selected)[key]
              return own && own !== 'inherit'
                ? { value: own, from: 'this user’s exception' }
                : { value: row.effective[key].value, from: SOURCE_LABELS[row.effective[key].source] }
            }}
            disabled={save.isPending}
          />
          <button
            type="button"
            className="btn-primary self-start !py-0.5 !px-2 text-xs"
            disabled={Object.keys(changes).length === 0 || save.isPending}
            onClick={() => save.mutate()}
            aria-label={`Verify & save the exceptions for ${who}`}
          >
            Verify &amp; Save
          </button>
        </div>
      )}
    </section>
  )
}
