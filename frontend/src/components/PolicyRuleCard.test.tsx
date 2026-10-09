/** UI-12: "last accessed" never says "loading…" forever. */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { PolicyRule } from '../types'
import { PolicyRuleCard } from './PolicyRuleCard'

const rule: PolicyRule = {
  name: 'r', resource_type: 'secret', resource_type_label: 'Secret', privileges: [], conditions: [],
  resolutions: [{ kind: 'resolved', id: 'sec-1', name: 'db-password', resource_kind: 'secret', project_id: 'p', project_name: 'P', resource_group_id: 'g' }],
} as PolicyRule

describe('PolicyRuleCard access lookup', () => {
  it('no lookup (service account): no "Last accessed" section at all', () => {
    render(<PolicyRuleCard rule={rule} />)
    expect(screen.queryByText(/Last accessed/)).toBeNull()
    expect(screen.queryByText('loading…')).toBeNull()
  })

  it('a failed lookup says unavailable and offers Retry', () => {
    const onRetry = vi.fn()
    render(<PolicyRuleCard rule={rule} accessLookup={{ status: 'error', message: 'Access model not loaded yet', onRetry }} />)
    expect(screen.getByText(/unavailable: Access model not loaded yet/)).toBeTruthy()
    expect(screen.queryByText('loading…')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('a finished lookup with no entry for a resource says so', () => {
    render(<PolicyRuleCard rule={rule} accessLookup={{ status: 'ready', byId: new Map() }} />)
    expect(screen.getByText('no result returned for this resource')).toBeTruthy()
  })

  it('while loading, says loading', () => {
    render(<PolicyRuleCard rule={rule} accessLookup={{ status: 'loading' }} />)
    expect(screen.getByText('loading…')).toBeTruthy()
  })
})
