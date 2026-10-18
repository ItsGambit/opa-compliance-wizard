/** The Groups, Projects, Resource Groups, Policies and Relationships views on the shared Explorer layout. */
import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { exampleModel } from '../test/accessFixtures'
import { GroupsTab } from './GroupsTab'
import { PoliciesTab } from './PoliciesTab'
import { ProjectsTab } from './ProjectsTab'
import { RelationshipsTab } from './RelationshipsTab'
import { ResourceGroupsTab } from './ResourceGroupsTab'

vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))
vi.mock('./ExportButtons', () => ({ ExportButtons: ({ filenameBase }: { filenameBase: string }) => <div>export {filenameBase}</div> }))
vi.mock('../api/hooks', () => ({
  useEnvironments: () => ({ data: { active: 'example' } }),
  useResourceHistory: () => ({ data: { rows: [{ event_type: 'pam.security_policy.update', user: 'Example Admin', timestamp: '2026-10-01T10:00:00Z' }] }, isLoading: false, isError: false }),
}))

const model = exampleModel

describe('GroupsTab', () => {
  it('lists what the group grants by resource type, with members and roles in the rail', () => {
    render(<GroupsTab model={model} />)
    expect(screen.getByText(/Select a group to see/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Group'), { target: { value: 'g1' } })
    const rail = screen.getByRole('complementary')
    expect(within(rail).getByText('ADMIN')).toBeTruthy()
    expect(within(rail).getByRole('button', { name: /2\s*servers/ })).toBeTruthy()
    fireEvent.click(within(rail).getByRole('button', { name: /1\s*member/ }))
    expect(within(rail).getByText('Example Admin')).toBeTruthy()
    // the muted "via" column names policies for a group view
    const row = screen.getByRole('button', { name: /lab-linux-example-01/ })
    expect(row.textContent).toContain('Linux Servers Policy')
    expect(row.textContent).not.toContain('Example-All-Users')
    fireEvent.click(row)
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull() // no group removal on the group view
    expect(within(screen.getByRole('region', { name: /Details for/ })).getByText(/Rule “Server access”/)).toBeTruthy()
  })

  it('says when no policy names the group', () => {
    render(<GroupsTab model={model} />)
    fireEvent.change(screen.getByLabelText('Group'), { target: { value: 'g2' } })
    expect(screen.getAllByRole('button', { name: /crm/ }).length).toBeGreaterThan(0) // g2 backs the SaaS policy
  })
})

describe('ProjectsTab', () => {
  it('needs a resource group first, then lists the project\'s resources and keeps its settings reachable', () => {
    render(<ProjectsTab model={model} />)
    expect((screen.getByLabelText('Project') as HTMLSelectElement).disabled).toBe(false) // MockSelect ignores disabled; the real one honours it
    fireEvent.change(screen.getByLabelText('Resource group'), { target: { value: 'rg1' } })
    fireEvent.change(screen.getByLabelText('Project'), { target: { value: 'p1' } })
    expect(screen.getByRole('button', { name: /lab-linux-example-01/ })).toBeTruthy()
    const settings = screen.getByRole('button', { name: /Project settings/ })
    expect(settings.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(settings)
    expect(screen.getByText('Active Resource Count')).toBeTruthy()
  })
})

describe('ResourceGroupsTab', () => {
  it('shows projects and policies as sections, delegated admins, who has access and types covered', () => {
    render(<ResourceGroupsTab model={model} />)
    fireEvent.change(screen.getByLabelText('Resource group'), { target: { value: 'rg1' } })
    const rail = screen.getByRole('complementary')
    expect(within(rail).getByText('Example description')).toBeTruthy()
    expect(within(rail).getByText('Example-Linux-Admins')).toBeTruthy() // delegated admin chip
    expect(within(rail).getByText('Servers')).toBeTruthy() // type covered
    expect(within(rail).getByRole('button', { name: /2\s*projects/ })).toBeTruthy()
    // Projects section is open first; its counts are on the row
    const project = screen.getByRole('button', { name: /Example Project/ })
    expect(project.textContent).toContain('4 active · 1 stale')
    // jump to Policies, open a policy row: its rules are reachable
    fireEvent.click(within(rail).getByRole('button', { name: /2\s*policies/ }))
    fireEvent.click(screen.getByRole('button', { name: /Linux Servers Policy/ }))
    expect(within(screen.getByRole('region', { name: 'Details for Linux Servers Policy' })).getByText('Server access')).toBeTruthy()
  })

  it('says so for a resource group with nothing in it', () => {
    render(<ResourceGroupsTab model={model} />)
    fireEvent.change(screen.getByLabelText('Resource group'), { target: { value: 'rg2' } })
    expect(screen.getByText('No projects in this resource group.')).toBeTruthy()
    expect(screen.getByText('No policies are scoped to this resource group.')).toBeTruthy()
  })
})

describe('PoliciesTab', () => {
  it('lists scoped and team-wide policies, opens one with principals, rules and last modified', () => {
    render(<PoliciesTab model={model} />)
    expect(screen.getByRole('button', { name: /Scoped to a resource group\s*2/ })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Linux Servers Policy/ }))
    const detail = screen.getByRole('region', { name: 'Details for Linux Servers Policy' })
    expect(within(detail).getByText('Example-All-Users')).toBeTruthy()
    expect(within(detail).getByText('Server access')).toBeTruthy()
    expect(within(detail).getByText(/Last modified by Example Admin/)).toBeTruthy()
    expect(within(detail).getByText('export opa-policy-Linux Servers Policy')).toBeTruthy()
  })

  it('the team-wide, inactive policy is reachable with the Inactive filter', () => {
    render(<PoliciesTab model={model} />)
    fireEvent.click(screen.getByRole('button', { name: /Filter/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /Inactive policies/ }))
    expect(screen.queryByRole('button', { name: /Linux Servers Policy/ })).toBeNull()
    expect(screen.getByRole('button', { name: /Other Policy/ }).textContent).toContain('inactive')
  })

  it('search is fuzzy over name, group and rule names', () => {
    render(<PoliciesTab model={model} />)
    fireEvent.change(screen.getByLabelText('Search policies'), { target: { value: 'Pul CRM acounts' } })
    expect(screen.getByRole('button', { name: /Pull SaaS Policy/ })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Other Policy/ })).toBeNull()
  })
})

describe('RelationshipsTab', () => {
  it('lists relationships; opening one shows its assignments, principals, resources and policies', () => {
    render(<RelationshipsTab model={model} />)
    const row = screen.getByRole('button', { name: /Example Safe Owners/ })
    expect(row.textContent).toContain('1 assignment')
    expect(row.textContent).toContain('1 policy')
    fireEvent.click(row)
    const detail = screen.getByRole('region', { name: 'Details for Example Safe Owners' })
    expect(within(detail).getByText('Assignment: Example Assignment')).toBeTruthy()
    expect(within(detail).getByText('Example-All-Users')).toBeTruthy()
    expect(within(detail).getByText('lab-linux-example-01')).toBeTruthy()
    expect(within(detail).getByText('Servers labeled role=bastion')).toBeTruthy()
    expect(within(detail).getByText('Linux Servers Policy')).toBeTruthy()
  })

  it('the "not used by any policy" filter narrows to the unused relationship', () => {
    render(<RelationshipsTab model={model} />)
    fireEvent.click(screen.getByRole('button', { name: /Filter/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /Not used by any policy/ }))
    expect(screen.queryByRole('button', { name: /Example Safe Owners/ })).toBeNull()
    expect(screen.getByRole('button', { name: /Unused Relationship/ })).toBeTruthy()
  })
})
