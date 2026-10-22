import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { AccessModel } from '../../types'
import { UserRail } from './UserRail'

const user = (id: string, name: string, extra: Record<string, unknown> = {}) => ({ id, name, user_type: 'human', status: 'ACTIVE', groups: [], details: { email: `${name}@example.com`, full_name: name }, ...extra })
const users = [user('u1', 'Avery Example'), user('u2', 'Blake Example'), user('u3', 'Casey Example', { groups_error: true }), user('u4', 'svc-reporting', { user_type: 'service', details: {} })] as unknown as AccessModel['users']

describe('UserRail (the Users view list, P4)', () => {
  it('lists people with their e-mail, a service user as such, and says in words when groups could not be read', () => {
    render(<UserRail users={users} onSelect={vi.fn()} />)
    expect(screen.getAllByRole('option')).toHaveLength(4)
    expect(screen.getByText('Avery Example@example.com')).toBeTruthy()
    expect(screen.getByText('service user · API key')).toBeTruthy()
    expect(screen.getByText('Groups could not be read')).toBeTruthy()
    expect(screen.getByPlaceholderText('Search 4 users')).toBeTruthy()
  })

  it('searching narrows the list by name or e-mail and says when nothing matches', () => {
    render(<UserRail users={users} onSelect={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Search users'), { target: { value: 'casey' } })
    expect(screen.getAllByRole('option').map(o => o.textContent)).toEqual([expect.stringContaining('Casey Example')])
    fireEvent.change(screen.getByLabelText('Search users'), { target: { value: 'zzzzqq' } })
    expect(screen.queryAllByRole('option')).toHaveLength(0)
    expect(screen.getByRole('status').textContent).toMatch(/No user matches/)
  })

  it('is one tab stop; arrows, Home and End move, Enter and Space pick; the picked person is aria-selected', () => {
    const onSelect = vi.fn()
    const { rerender } = render(<UserRail users={users} onSelect={onSelect} />)
    const list = screen.getByRole('listbox', { name: 'Users' })
    const opts = screen.getAllByRole('option')
    expect(opts.filter(o => o.tabIndex === 0)).toHaveLength(1)
    opts[0].focus()
    fireEvent.keyDown(list, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(opts[1])
    fireEvent.keyDown(list, { key: 'End' })
    expect(document.activeElement).toBe(opts[3])
    fireEvent.keyDown(list, { key: 'ArrowDown' })  // stays on the last
    expect(document.activeElement).toBe(opts[3])
    fireEvent.keyDown(list, { key: 'Home' })
    expect(document.activeElement).toBe(opts[0])
    fireEvent.keyDown(list, { key: 'ArrowDown' })
    fireEvent.keyDown(list, { key: 'Enter' })
    expect(onSelect).toHaveBeenLastCalledWith('u2')
    fireEvent.keyDown(list, { key: ' ' })
    expect(onSelect).toHaveBeenCalledTimes(2)
    rerender(<UserRail users={users} selectedId="u2" onSelect={onSelect} />)
    expect(screen.getAllByRole('option').map(o => o.getAttribute('aria-selected'))).toEqual(['false', 'true', 'false', 'false'])
    expect(screen.getAllByRole('option').find(o => o.tabIndex === 0)).toBe(screen.getAllByRole('option')[1])  // the tab stop follows the selection
  })

  it('shows at most 50 people and says how many more there are', () => {
    const many = Array.from({ length: 80 }, (_, i) => user(`u${i}`, `Person ${i}`)) as unknown as AccessModel['users']
    render(<UserRail users={many} onSelect={vi.fn()} />)
    expect(screen.getAllByRole('option')).toHaveLength(50)
    expect(screen.getByText(/… 30 more: search to narrow the list/)).toBeTruthy()
  })
})
