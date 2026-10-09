import { useState, type ChangeEvent } from 'react'
import type { Environment, EnvironmentFormValues } from '../types'
import { Field } from './Field'

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

/** Callers key this form by the environment being edited, so switching rows
 * (or "Add environment") always starts from that row's values. */
export function EnvironmentForm({ initial, submitLabel, onSubmit, isSubmitting, errorMessage }: Props) {
  const [values, setValues] = useState<EnvironmentFormValues>(
    initial ? { ...EMPTY, ...initial, key_secret: '', okta_api_token: '' } : EMPTY
  )

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
      <Field label="Label">
        {id => (
          <input
            id={id}
            value={values.name}
            onChange={set('name')}
            disabled={isEditing}
            placeholder="dev / uat / prod"
            className="text-input disabled:opacity-60"
          />
        )}
      </Field>
      <Field label="Base Domain">
        {id => <input id={id} value={values.base_domain} onChange={set('base_domain')} placeholder="yourorg.pam.okta.com" className="text-input" />}
      </Field>
      <Field label="Team Name">
        {id => <input id={id} value={values.team_name} onChange={set('team_name')} placeholder="yourteam-pam" className="text-input" />}
      </Field>
      <Field label="Key ID">
        {id => <input id={id} value={values.key_id} onChange={set('key_id')} placeholder="service user API key ID" className="text-input" />}
      </Field>
      <Field label="Key Secret">
        {id => (
          <input
            id={id}
            type="password"
            autoComplete="off"
            value={values.key_secret}
            onChange={set('key_secret')}
            placeholder={isEditing ? 'leave blank to keep existing' : 'service user API key secret'}
            className="text-input"
          />
        )}
      </Field>

      <div className="border-t border-border-sub pt-3 mt-1">
        <span className="section-label">Okta (optional — only needed to create new groups)</span>
      </div>
      <Field label="Okta URL">
        {id => <input id={id} value={values.okta_url} onChange={set('okta_url')} placeholder="https://yourorg.okta.com" className="text-input" />}
      </Field>
      <Field label="Okta API Token">
        {id => (
          <input
            id={id}
            type="password"
            autoComplete="off"
            value={values.okta_api_token}
            onChange={set('okta_api_token')}
            placeholder={isEditing ? 'leave blank to keep existing' : 'Okta API token'}
            className="text-input"
          />
        )}
      </Field>

      {errorMessage && <div className="text-xs text-loss" role="alert">{errorMessage}</div>}

      <button type="submit" className="btn-primary self-start" disabled={!canSubmit || isSubmitting}>
        {isSubmitting ? 'Connecting…' : submitLabel}
      </button>
    </form>
  )
}
