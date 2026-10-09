/** UI-05 (review round 1, finding 1): a mounted view must not keep showing
 * the previous tenant's cached data after the environment changes. */
import { screen } from '@testing-library/react'
import { useQuery } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import { renderWithClient, testQueryClient } from '../test/renderWithClient'
import { EnvironmentScope } from './EnvironmentScope'

let tenant = 'A'
function ResourceGroups() {
  const { data } = useQuery({ queryKey: ['resource_groups'], queryFn: async () => `rg-of-${tenant}`, staleTime: 30_000 })
  return <div>{data ?? 'loading'}</div>
}

describe('EnvironmentScope', () => {
  it('drops the old tenant cache before the remounted view reads it', async () => {
    const client = testQueryClient()
    tenant = 'A'
    const { rerender } = renderWithClient(<EnvironmentScope scopeKey="env-A"><ResourceGroups /></EnvironmentScope>, client)
    expect(await screen.findByText('rg-of-A')).toBeTruthy()
    tenant = 'B'
    rerender(<EnvironmentScope scopeKey="env-B"><ResourceGroups /></EnvironmentScope>)
    expect(await screen.findByText('rg-of-B')).toBeTruthy()
    expect(screen.queryByText('rg-of-A')).toBeNull()
  })

  it('keeps global queries and does nothing while the key is unchanged', async () => {
    const client = testQueryClient()
    client.setQueryData(['whoami'], { email: 'x' })
    tenant = 'A'
    const { rerender } = renderWithClient(<EnvironmentScope scopeKey="k"><ResourceGroups /></EnvironmentScope>, client)
    await screen.findByText('rg-of-A')
    tenant = 'B'
    rerender(<EnvironmentScope scopeKey="k"><ResourceGroups /></EnvironmentScope>)
    expect(screen.getByText('rg-of-A')).toBeTruthy()
    rerender(<EnvironmentScope scopeKey="k2"><ResourceGroups /></EnvironmentScope>)
    await screen.findByText('rg-of-B')
    expect(client.getQueryData(['whoami'])).toEqual({ email: 'x' })
  })

  it('first load (undefined -> key) does not wipe anything', async () => {
    const client = testQueryClient()
    client.setQueryData(['groups'], ['g'])
    const { rerender } = renderWithClient(<EnvironmentScope scopeKey={undefined}><div>x</div></EnvironmentScope>, client)
    rerender(<EnvironmentScope scopeKey="env-A"><div>x</div></EnvironmentScope>)
    expect(client.getQueryData(['groups'])).toEqual(['g'])
  })
})
