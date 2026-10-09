/** After removing a user from a group, views derived from membership refresh. */
import { act } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { removeUserFromGroup } from '../api/client'
import { renderHookWithClient } from '../test/renderWithClient'
import { useRemoveUserFromGroup } from './useRemoveUserFromGroup'

vi.mock('../api/client', () => ({ removeUserFromGroup: vi.fn() }))

describe('useRemoveUserFromGroup', () => {
  it('refreshes groups, the service account and "last accessed"', async () => {
    vi.mocked(removeUserFromGroup).mockResolvedValue({ removed: true, group_id: 'g1', user_name: 'u' })
    const onRemoved = vi.fn()
    const { result, client } = renderHookWithClient(() => useRemoveUserFromGroup(onRemoved))
    const spy = vi.spyOn(client, 'invalidateQueries')
    await act(async () => { await result.current.mutateAsync({ groupId: 'g1', userName: 'u' }) })
    const keys = spy.mock.calls.map(c => (c[0] as { queryKey: string[] }).queryKey[0])
    expect(keys).toEqual(expect.arrayContaining(['service_account', 'groups', 'user_resource_access']))
    expect(onRemoved).toHaveBeenCalledWith('g1')
  })
})
