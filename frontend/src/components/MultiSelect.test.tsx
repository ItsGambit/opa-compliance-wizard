/** AssignAccessDialog's checkbox list uses the shared fuzzy hook once long
 * (fictional data only). */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MultiSelect } from './AssignAccessDialog'

const many = ['Admins', 'Auditors', 'Builders', 'Cooks', 'Drivers', 'Editors', 'Finance', 'Guests'].map((name, i) => ({ id: `g${i}`, name }))

describe('MultiSelect fuzzy search', () => {
  it('has no search box for a short list', () => {
    render(<MultiSelect options={many.slice(0, 3)} selectedIds={new Set()} onToggle={() => {}} emptyText="none" />)
    expect(screen.queryByLabelText('Search options')).toBeNull()
  })
  it('shows all when empty, tolerates a typo, matches partial, and reports no match', () => {
    render(<MultiSelect options={many} selectedIds={new Set()} onToggle={() => {}} emptyText="none" />)
    const box = screen.getByLabelText('Search options')
    expect(screen.getAllByRole('checkbox')).toHaveLength(8)
    fireEvent.change(box, { target: { value: 'Auditrs' } })
    expect(screen.getAllByRole('checkbox')).toHaveLength(1)
    fireEvent.change(box, { target: { value: 'Fina' } })
    expect(screen.getAllByRole('checkbox')[0].closest('label')?.textContent).toBe('Finance')
    fireEvent.change(box, { target: { value: 'zzzzqqqq' } })
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.getByText('No options')).toBeTruthy()
  })
  it('keeps selections and still toggles a filtered row', () => {
    const onToggle = vi.fn()
    render(<MultiSelect options={many} selectedIds={new Set(['g0'])} onToggle={onToggle} emptyText="none" />)
    fireEvent.change(screen.getByLabelText('Search options'), { target: { value: 'Guest' } })
    fireEvent.click(screen.getByRole('checkbox'))
    expect(onToggle).toHaveBeenCalledWith('g7')
  })
})
