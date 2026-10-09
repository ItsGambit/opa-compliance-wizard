/** UI-19: resource rows open their history from the keyboard. */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { AccessModel } from '../types'
import { ResourcesTab } from './ResourcesTab'

vi.mock('./ResourceHistoryPanel', () => ({ ResourceHistoryPanel: ({ resourceLabel }: { resourceLabel: string }) => <div>history for {resourceLabel}</div> }))
vi.mock('./Select', async () => ({ Select: (await import('../test/MockSelect')).MockSelect }))

const model = {
  servers: [{ id: 's1', hostname: 'win-01', os: 'Windows', os_type: 'windows', access_address: null, state: 'ACTIVE', resource_group_name: 'rg', project_name: 'p' }],
  gateways: [],
} as unknown as AccessModel

describe('ResourcesTab', () => {
  it('each clickable row has a real, named button that opens its history', () => {
    render(<ResourcesTab model={model} />)
    const button = screen.getByRole('button', { name: 'Show access history for win-01' })
    expect(button.getAttribute('aria-pressed')).toBe('false')
    button.focus()
    expect(document.activeElement).toBe(button)
    fireEvent.click(button)
    expect(screen.getByText('history for win-01')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Show access history for win-01' }).getAttribute('aria-pressed')).toBe('true')
  })

  it('names its search box', () => {
    render(<ResourcesTab model={model} />)
    expect(screen.getByLabelText('Search windows servers')).toBeTruthy()
  })
})
