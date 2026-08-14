import { useEffect, useState, type ChangeEvent } from 'react'
import type { Environment, EnvironmentFormValues } from '../types'

interface Props {
  initial?: Environment
  submitLabel: string
  onSubmit: (values: EnvironmentFormValues) => void
  isSubmitting: boolean
  errorMessage?: string
}

const EMPTY: EnvironmentFormValues = {
  name: '', base_domain: '', team_name: '', key_id: '', key_secret: '', okta_url: '', okta_api_token: '',
}

export function EnvironmentForm({ initial, submitLabel, onSubmit, isSubmitting, errorMessage }: Props) {
  const [values, setValues] = useState<EnvironmentFormValues>(
    initial ? { ...EMPTY, ...initial, key_secret: '', okta_api_token: '' } : EMPTY
  )

  useEffect(() => {
    setValues(initial ? { ...EMPTY, ...initial, key_secret: '', okta_api_token: '' } : EMPTY)
  }, [initial])

  const isEditing = !!initial
  const set = (field: keyof EnvironmentFormValues) => (e: ChangeEvent<HTMLInputElement>) =>
    setValues(v => ({ ...v, [field]: e.target.value }))

  const canSubmit = values.name.trim() && values.base_domain.trim() && values.team_name.trim() && values.key_id.trim()
    && (isEditing || values.key_secret.trim())

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={e => { e.preventDefault(); onSubmit(values) }}
    >
      <div className="flex flex-col gap-1">
        <span className="section-label">Label</span>
        <input
          value={values.name}
          onChange={set('name')}
          disabled={isEditing}
          placeholder="dev / uat / prod"
          className="text-input disabled:opacity-60"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Base Domain</span>
        <input
          value={values.base_domain}
          onChange={set('base_domain')}
          placeholder="yourorg.pam.okta.com"
          className="text-input"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Team Name</span>
        <input value={values.team_name} onChange={set('team_name')} placeholder="yourteam-pam" className="text-input" />
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Key ID</span>
        <input value={values.key_id} onChange={set('key_id')} placeholder="service user API key ID" className="text-input" />
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Key Secret</span>
        <input
          type="password"
          value={values.key_secret}
          onChange={set('key_secret')}
          placeholder={isEditing ? 'leave blank to keep existing' : 'service user API key secret'}
          className="text-input"
        />
      </div>

      <div className="border-t border-border-sub pt-3 mt-1">
        <span className="section-label">Okta (optional — only needed to create new groups)</span>
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Okta URL</span>
        <input
          value={values.okta_url}
          onChange={set('okta_url')}
          placeholder="https://yourorg.okta.com"
          className="text-input"
        />
      </div>
      <div className="flex flex-col gap-1">
        <span className="section-label">Okta API Token</span>
        <input
          type="password"
          value={values.okta_api_token}
          onChange={set('okta_api_token')}
          placeholder={isEditing ? 'leave blank to keep existing' : 'Okta API token'}
          className="text-input"
        />
      </div>

      {errorMessage && <div className="text-xs text-loss">{errorMessage}</div>}

      <button type="submit" className="btn-primary self-start" disabled={!canSubmit || isSubmitting}>
        {isSubmitting ? 'Connecting…' : submitLabel}
      </button>
    </form>
  )
}
