import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ActionMenu } from './ActionMenu'

const setup = () => {
  const csv = vi.fn(); const letter = vi.fn()
  render(<><button type="button">before</button><ActionMenu label="Export…" items={[
    { key: 'csv', label: 'Counts as CSV', onSelect: csv },
    { key: 'a4', label: 'Paper size: A4', kind: 'radio', checked: true, separated: true, onSelect: vi.fn() },
    { key: 'letter', label: 'Paper size: Letter', kind: 'radio', checked: false, onSelect: letter },
  ]} /></>)
  return { csv, letter, button: screen.getByRole('button', { name: /Export…/ }) }
}

describe('ActionMenu (the Overview Export… menu)', () => {
  it('announces a menu, opens on click or ArrowDown, focuses the first item, and moves with the arrow keys, Home and End', () => {
    const { button } = setup()
    expect(button.getAttribute('aria-haspopup')).toBe('menu')
    fireEvent.keyDown(button, { key: 'ArrowDown' })
    expect(button.getAttribute('aria-expanded')).toBe('true')
    const items = [screen.getByRole('menuitem', { name: 'Counts as CSV' }), ...screen.getAllByRole('menuitemradio')]
    expect(document.activeElement).toBe(items[0])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'End' })
    expect(document.activeElement).toBe(items[2])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[0])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(button)
  })

  it('a choice runs, closes and returns focus to the button; the paper size is a radio choice that says which is current', () => {
    const { button, csv, letter } = setup()
    fireEvent.click(button)
    expect(screen.getByRole('menuitemradio', { name: /A4/ }).getAttribute('aria-checked')).toBe('true')
    expect(screen.getByRole('menuitemradio', { name: /Letter/ }).getAttribute('aria-checked')).toBe('false')
    fireEvent.click(screen.getByRole('menuitemradio', { name: /Letter/ }))
    expect(letter).toHaveBeenCalled()
    expect(document.activeElement).toBe(button)
    fireEvent.click(button)
    fireEvent.click(screen.getByRole('menuitem', { name: 'Counts as CSV' }))
    expect(csv).toHaveBeenCalled()
  })

  it('Tab and a click outside close it', () => {
    const { button } = setup()
    fireEvent.click(button)
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Tab' })
    expect(screen.queryByRole('menu')).toBeNull()
    fireEvent.click(button)
    fireEvent.mouseDown(screen.getByRole('button', { name: 'before' }))
    expect(screen.queryByRole('menu')).toBeNull()
  })
})
