import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { layoutForWidth, WIDE_MIN_WIDTH } from './layout'
import { UserDetail } from './UserDetail'
import { grantsText } from '../../utils/userGrants'
import { exampleModel } from '../../test/accessFixtures'
import { rulesGrantedToGroupIds } from '../../utils/policy'

describe('the Users view layout (the approved design: a 300 px rail with the detail beside it)', () => {
  it('can be asked to sit side by side from 900 px, the other views keep 1100', () => {
    expect(layoutForWidth(960)).toBe('narrow')
    expect(layoutForWidth(960, 900)).toBe('wide')
    expect(layoutForWidth(899, 900)).toBe('narrow')
    expect(layoutForWidth(WIDE_MIN_WIDTH)).toBe('wide')
  })
})

describe('grantsText', () => {
  it('counts what a rule resolves to, by kind and project, and says so for a selector', () => {
    const rule = { resource_type_label: 'Servers', resource_type: 'server', resolutions: [
      { kind: 'resolved', id: 'a', resource_kind: 'individual_server', project_name: 'payments-prod' },
      { kind: 'resolved', id: 'b', resource_kind: 'individual_server', project_name: 'payments-prod' },
      { kind: 'resolved', id: 'c', resource_kind: 'secret_folder', project_name: 'finance' },
      { kind: 'condition', description: 'label env=prod' },
    ] } as never
    expect(grantsText([rule])).toBe('2 servers in payments-prod; 1 secret folder in finance; Servers (by selector)')
    expect(grantsText([{ resolutions: [] } as never])).toBe('nothing resolved')
  })
})

describe('UserDetail', () => {
  const user = exampleModel.users[0]
  const groupIds = new Set(user.groups.map(g => g.id))
  const grants = rulesGrantedToGroupIds(exampleModel.policies, groupIds)

  it('has the name, the summary line, the evidence button and a Policy / Via group / Grants / Conditions table with no invented column', () => {
    render(<UserDetail user={user} model={exampleModel as never} grants={grants} groupIds={groupIds} reach="2 servers" evidenceTarget="x"
      okta={{ state: 'ACTIVE', flag: null, capturedAt: '2026-10-21T02:31:00.000Z' }} />)
    const card = screen.getByRole('region', { name: 'Selected user' })
    expect(within(card).getByText(/→ .*polic.* → 2 servers/)).toBeTruthy()
    expect(within(card).getByRole('link', { name: 'Resource evidence (live + archive)' })).toBeTruthy()
    expect(within(card).getAllByRole('columnheader').map(h => h.textContent)).toEqual(['Policy', 'Via group', 'Grants', 'Conditions'])
    expect(within(card).getByText(/^Okta: active, read /)).toBeTruthy()
    expect(within(card).getAllByRole('row').length).toBeGreaterThan(1)
  })
})
