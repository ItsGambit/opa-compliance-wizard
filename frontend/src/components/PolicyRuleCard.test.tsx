/** The rule card (used inside expanded policy rows). The "last accessed" lookup
 * states it used to carry (UI-12) now live in explorer/LastAccessed and are
 * tested in explorer/explorer.test.tsx. */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { PolicyRule } from '../types'
import { PolicyRuleCard } from './PolicyRuleCard'

const rule: PolicyRule = {
  name: 'r', resource_type: 'secret', resource_type_label: 'Secret',
  privileges: [{ privilege_type: 'reveal_password', flags: ['reveal_password'] }],
  conditions: [{ condition_type: 'mfa', condition_value: {} }],
  resolutions: [
    { kind: 'resolved', id: 'sec-1', name: 'db-password', resource_kind: 'secret', project_id: 'p', project_name: 'P', resource_group_id: 'g' },
    { kind: 'condition', description: 'Servers labeled role=bastion' },
  ],
} as PolicyRule

describe('PolicyRuleCard', () => {
  it('shows what the rule applies to, its privileges and its conditions', () => {
    render(<PolicyRuleCard rule={rule} policyName="Example Policy" />)
    expect(screen.getByText('db-password — P')).toBeTruthy()
    expect(screen.getByText('Servers labeled role=bastion')).toBeTruthy()
    expect(screen.getByText('reveal_password: reveal_password')).toBeTruthy()
    expect(screen.getByText(/MFA required/)).toBeTruthy()
    expect(screen.getByText('via Example Policy')).toBeTruthy()
  })

  it('never shows a "Last accessed" section (that lives on the resource rows)', () => {
    render(<PolicyRuleCard rule={rule} />)
    expect(screen.queryByText(/Last accessed/)).toBeNull()
    expect(screen.queryByText('loading…')).toBeNull()
  })
})
