/** 5.53.0: the environment form asks "Who can build evidence packages" as a required, explicit, preselected choice. */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { SettingsEnvironment } from '../types'
import { EnvironmentForm } from './EnvironmentForm'

const fill = () => {
  for (const [label, value] of [['Label', 'dev'], ['Base Domain', 'x.example'], ['Team Name', 't'], ['Key ID', 'k'], ['Key Secret', 's']] as const) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } })
  }
}

describe('Who can build evidence packages', () => {
  it('offers both choices, with "Environment owner only" preselected, and says what a package holds', () => {
    render(<EnvironmentForm submitLabel="Save" onSubmit={() => {}} isSubmitting={false} />)
    const group = screen.getByRole('group', { name: 'Who can build evidence packages' })
    expect((screen.getByRole('radio', { name: 'Environment owner only' }) as HTMLInputElement).checked).toBe(true)
    expect((screen.getByRole('radio', { name: 'Owner and people this environment is shared with' }) as HTMLInputElement).checked).toBe(false)
    expect(group.textContent).toMatch(/names and activity/)
    expect(group.textContent).toMatch(/not encrypted and not signed/)
    expect(group.textContent).toMatch(/needs MFA/)
  })

  it('submits the explicit choice with the rest of the form', () => {
    const onSubmit = vi.fn()
    render(<EnvironmentForm submitLabel="Save" onSubmit={onSubmit} isSubmitting={false} />)
    fill()
    fireEvent.submit(screen.getByRole('button', { name: 'Save' }).closest('form') as HTMLFormElement)
    expect(onSubmit).toHaveBeenLastCalledWith(expect.objectContaining({ evidence_builders: 'owner' }))
    fireEvent.click(screen.getByRole('radio', { name: 'Owner and people this environment is shared with' }))
    fireEvent.submit(screen.getByRole('button', { name: 'Save' }).closest('form') as HTMLFormElement)
    expect(onSubmit).toHaveBeenLastCalledWith(expect.objectContaining({ evidence_builders: 'shared' }))
  })

  it('an edit starts from the stored choice, and a restored draft keeps the typed one', () => {
    const initial = { id: 'e1', name: 'dev', base_domain: 'x.example', team_name: 't', key_id: 'k', okta_url: '', has_okta_token: false, evidence_builders: 'shared' } as SettingsEnvironment
    const { unmount } = render(<EnvironmentForm initial={initial} submitLabel="Save" onSubmit={() => {}} isSubmitting={false} />)
    expect((screen.getByRole('radio', { name: 'Owner and people this environment is shared with' }) as HTMLInputElement).checked).toBe(true)
    unmount()
    render(<EnvironmentForm initial={initial} draft={{ evidence_builders: 'owner' }} submitLabel="Save" onSubmit={() => {}} isSubmitting={false} />)
    expect((screen.getByRole('radio', { name: 'Environment owner only' }) as HTMLInputElement).checked).toBe(true)
  })
})
