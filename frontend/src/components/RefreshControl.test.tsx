/** The Overview's split Refresh button: a real menu button (WCAG 2.1.1, 4.1.2) and a disabled state whose reason can be read (WCAG 1.3.1). */
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { RefreshControl } from './RefreshControl'

const extras = [{ key: 'verify', label: 'Verify the chain', hint: 'no reads', onSelect: vi.fn() }]
const setup = (over: Partial<Parameters<typeof RefreshControl>[0]> = {}) => {
  const onRefresh = vi.fn()
  render(<><button type="button">before</button><RefreshControl running={false} disabledReason="" onRefresh={onRefresh} extras={extras} {...over} /><button type="button">after</button></>)
  return { onRefresh, caret: screen.getByRole('button', { name: 'More refresh options' }) }
}
const items = () => screen.getAllByRole('menuitem')

describe('RefreshControl menu keyboard (M3)', () => {
  it('the caret announces a menu: aria-haspopup, aria-expanded follows open and closed', () => {
    const { caret } = setup()
    expect(caret.getAttribute('aria-haspopup')).toBe('menu')
    expect(caret.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(caret)
    expect(caret.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByRole('menu')).toBeTruthy()
    fireEvent.click(caret)
    expect(caret.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('opening focuses the first item; Down and Up move and wrap; Home and End jump', () => {
    const { caret } = setup()
    fireEvent.click(caret)
    const list = items()
    expect(document.activeElement).toBe(list[0])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowDown' })
    expect(document.activeElement).toBe(list[1])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'End' })
    expect(document.activeElement).toBe(list[list.length - 1])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowDown' })  // wraps to the first
    expect(document.activeElement).toBe(list[0])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowUp' })    // wraps to the last
    expect(document.activeElement).toBe(list[list.length - 1])
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Home' })
    expect(document.activeElement).toBe(list[0])
  })

  it('Escape closes the menu and returns focus to the caret', () => {
    const { caret } = setup()
    fireEvent.click(caret)
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowDown' })
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(caret)
  })

  it('ArrowDown on the closed caret opens the menu; Tab and a click outside close it', () => {
    const { caret } = setup()
    fireEvent.keyDown(caret, { key: 'ArrowDown' })
    expect(screen.getByRole('menu')).toBeTruthy()
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Tab' })
    expect(screen.queryByRole('menu')).toBeNull()
    fireEvent.click(caret)
    expect(screen.getByRole('menu')).toBeTruthy()
    fireEvent.mouseDown(screen.getByRole('button', { name: 'after' }))
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('choosing an item runs it and closes the menu: one part, or an extra', () => {
    const { caret, onRefresh } = setup()
    fireEvent.click(caret)
    fireEvent.click(screen.getByRole('menuitem', { name: /Okta scan only/ }))
    expect(onRefresh).toHaveBeenCalledWith(['okta'])
    expect(screen.queryByRole('menu')).toBeNull()
    fireEvent.click(caret)
    fireEvent.click(screen.getByRole('menuitem', { name: /Verify the chain/ }))
    expect(extras[0].onSelect).toHaveBeenCalledTimes(1)
  })

  it('while a refresh runs the refresh items do nothing but the extras stay usable', () => {
    const { caret, onRefresh } = setup({ running: true })
    fireEvent.click(caret)
    fireEvent.click(screen.getByRole('menuitem', { name: /OPA scan only/ }))
    expect(onRefresh).not.toHaveBeenCalled()
    expect(screen.getByRole('menuitem', { name: /Verify the chain/ }).getAttribute('aria-disabled')).toBe('false')
  })

  it('the caret is at least 32 px wide (m3) and every control shows a focus ring through the app rule (no outline:none)', () => {
    const { caret } = setup()
    expect(caret.className).toMatch(/min-w-8/)
    expect(caret.className).not.toMatch(/outline-none/)
  })
})

describe('RefreshControl disabled with a reason (M4)', () => {
  it('is aria-disabled but still focusable, points at the reason text, and clicking does nothing', () => {
    const { onRefresh } = setup({ disabledReason: 'Refreshing needs the Sync now permission on this environment.' })
    const main = screen.getByRole('button', { name: /^Refresh$/ }) as HTMLButtonElement
    expect(main.disabled).toBe(false)
    expect(main.getAttribute('aria-disabled')).toBe('true')
    main.focus()
    expect(document.activeElement).toBe(main)
    expect(document.getElementById(main.getAttribute('aria-describedby')!)!.textContent).toMatch(/needs the Sync now permission/)
    fireEvent.click(main)
    expect(onRefresh).not.toHaveBeenCalled()
  })

  it('without a reason the button runs the whole refresh', () => {
    const { onRefresh } = setup()
    const main = screen.getByRole('button', { name: /^Refresh$/ })
    expect(main.getAttribute('aria-describedby')).toBeNull()
    fireEvent.click(main)
    expect(onRefresh).toHaveBeenCalledWith()
  })
})

describe('RefreshControl focus (U17)', () => {
  it('after a menu choice (Enter or click) focus returns to the main Refresh button, not the page body', () => {
    const { caret, onRefresh } = setup()
    fireEvent.click(caret)
    const item = screen.getByRole('menuitem', { name: /OPA scan only/ })
    item.focus()
    fireEvent.click(item)
    expect(onRefresh).toHaveBeenCalledWith(['opa'])
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /^Refresh$/ }))
    // an extra (Verify the chain) does the same
    fireEvent.click(caret)
    fireEvent.click(screen.getByRole('menuitem', { name: /Verify the chain/ }))
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /^Refresh$/ }))
  })
})
