/** UI-15: two toasts in one tick get distinct ids. */
import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { toast, useToastMessages } from './useToast'

describe('toast', () => {
  it('gives same-millisecond toasts distinct ids, and dismissing one keeps the other', () => {
    const { result } = renderHook(() => useToastMessages())
    act(() => {
      toast({ title: 'Group created', variant: 'success' })
      toast({ title: 'Service account not added automatically', variant: 'default', duration: 8000 })
    })
    const [a, b] = result.current.messages
    expect(a.id).not.toBe(b.id)
    act(() => { result.current.dismiss(a.id) })
    expect(result.current.messages.map(m => m.title)).toEqual(['Service account not added automatically'])
  })
})
