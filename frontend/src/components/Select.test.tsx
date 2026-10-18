/** The shared Select picker: fuzzy typo-tolerant search over label, value
 * and hidden keywords (fictional data only). */
import { fireEvent, render, screen } from '@testing-library/react'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { Select, type SelectOption } from './Select'

// Radix's popper needs layout APIs jsdom lacks.
beforeAll(() => {
  Element.prototype.scrollIntoView = vi.fn()
  Element.prototype.hasPointerCapture = vi.fn(() => false)
  Element.prototype.releasePointerCapture = vi.fn()
  globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver
})

const OPTIONS: SelectOption[] = [
  { value: 'u1', label: 'Alice Johnson', keywords: ['alice@example.com', 'ajohnson'] },
  { value: 'u2', label: 'Bob Smith', keywords: ['bob@example.com'] },
  { value: 'u3', label: 'Carol Davies' },
  { value: 'u4', label: 'Dan Evans' },
  { value: 'u5', label: 'Erin Fox' },
  { value: 'u6', label: 'Frank Green' },
  { value: 'u7', label: 'Grace Hill' },
  { value: 'u8', label: 'Heidi Ives' },
]

function open() {
  render(<Select ariaLabel="Pick" options={OPTIONS} onValueChange={() => {}} placeholder="Choose" />)
  fireEvent.keyDown(screen.getByLabelText('Pick'), { key: 'Enter' })
  return screen.getByLabelText('Search options')
}
const labels = () => screen.queryAllByRole('option').map(o => o.textContent)

describe('Select fuzzy search', () => {
  it('shows every option when the query is empty', () => {
    open()
    expect(labels()).toHaveLength(8)
  })
  it('tolerates a typo', () => {
    fireEvent.change(open(), { target: { value: 'Jonhson' } })
    expect(labels()).toEqual(['Alice Johnson'])
  })
  it('matches a partial word', () => {
    fireEvent.change(open(), { target: { value: 'Dav' } })
    expect(labels()).toContain('Carol Davies')
  })
  it('matches hidden keywords such as an e-mail', () => {
    fireEvent.change(open(), { target: { value: 'bob@example.com' } })
    expect(labels()[0]).toBe('Bob Smith')
  })
  it('shows "No options" when nothing matches', () => {
    fireEvent.change(open(), { target: { value: 'zzzzqqqq' } })
    expect(labels()).toEqual([])
    expect(screen.getByText('No options')).toBeTruthy()
  })
})
