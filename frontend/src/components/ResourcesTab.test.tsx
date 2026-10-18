/** UI-19: resource rows open their history from the keyboard (now an expandable row). */
import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { AccessModel } from '../types'
import { ResourcesTab } from './ResourcesTab'

vi.mock('./ResourceHistoryPanel', () => ({ ResourceHistoryPanel: ({ resourceLabel, onClose }: { resourceLabel: string; onClose: () => void }) => <div>history for {resourceLabel}<button onClick={onClose}>Close history</button></div> }))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))

const model = {
  servers: [
    { id: 's1', hostname: 'win-01', os: 'Windows', os_type: 'windows', access_address: '10.0.0.1', state: 'ACTIVE', resource_group_name: 'rg', project_name: 'p' },
    { id: 's2', hostname: 'win-02', os: 'Windows', os_type: 'windows', access_address: null, state: 'DISABLED', resource_group_name: 'rg', project_name: 'p' },
  ],
  gateways: [], clients: [], devices: [], okta_accounts: [], saas_accounts: [], active_directory_accounts: [], database_accounts: [],
  workload_roles: [], workload_connections: [], database_connections: [], saas_app_connections: [], active_directory_connections: [],
} as unknown as AccessModel

describe('ResourcesTab', () => {
  it('each row is a real button (aria-expanded) that opens its history inline, reachable by keyboard', () => {
    render(<ResourcesTab model={model} />)
    const button = screen.getByRole('button', { name: /win-01/ })
    expect(button.getAttribute('aria-expanded')).toBe('false')
    button.focus()
    expect(document.activeElement).toBe(button)
    fireEvent.click(button)
    expect(screen.getByText('history for win-01')).toBeTruthy()
    expect(button.getAttribute('aria-expanded')).toBe('true')
  })

  it('keeps every column: a calm one-line summary, and all columns once the row is open', () => {
    render(<ResourcesTab model={model} />)
    const row = screen.getByRole('button', { name: /win-01/ })
    expect(row.textContent).toContain('Windows · 10.0.0.1') // summary
    expect(row.textContent).toContain('rg / p') // where
    expect(row.textContent).toContain('ACTIVE') // state
    fireEvent.click(row)
    const detail = screen.getByRole('region', { name: 'Details for win-01' })
    for (const h of ['Hostname', 'OS', 'Access Address', 'State', 'Resource Group', 'Project']) expect(within(detail).getByText(h)).toBeTruthy()
  })

  it('an empty column shows a dash once opened', () => {
    render(<ResourcesTab model={model} />)
    fireEvent.click(screen.getByRole('button', { name: /win-02/ }))
    expect(within(screen.getByRole('region', { name: 'Details for win-02' })).getByText('—')).toBeTruthy()
  })

  it('one row open at a time, and the history panel Close closes the row', () => {
    render(<ResourcesTab model={model} />)
    fireEvent.click(screen.getByRole('button', { name: /win-01/ }))
    fireEvent.click(screen.getByRole('button', { name: /win-02/ }))
    expect(screen.queryByText('history for win-01')).toBeNull()
    expect(screen.getByText('history for win-02')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Close history' }))
    expect(screen.queryByText('history for win-02')).toBeNull()
  })

  it('the quick view switches kind and lists only kinds that have resources', () => {
    render(<ResourcesTab model={model} />)
    const quick = screen.getByRole('navigation', { name: 'Quick view' })
    expect(within(quick).getAllByRole('button').length).toBe(1)
    expect(within(quick).getByRole('button', { name: /2\s*windows servers/i })).toBeTruthy()
  })

  it('names its search box and searches fuzzily', () => {
    render(<ResourcesTab model={model} />)
    fireEvent.change(screen.getByLabelText('Search windows servers'), { target: { value: 'wni-02' } }) // typo
    expect(screen.getByRole('button', { name: /win-02/ })).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Search windows servers'), { target: { value: 'qqqqzzzz' } })
    expect(screen.queryByRole('button', { name: /win-0/ })).toBeNull()
    expect(screen.getByText(/No resources match/)).toBeTruthy()
  })
})
