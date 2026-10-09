/** UI-06 (external review, 2026-10-05): a local-mode operator (can_admin
 * true, is_admin false) sees the Audit Log and banner settings the server
 * already serves them; Access Control stays hidden (it needs the hosted
 * step-up MFA flow). */
import { render, screen } from '@testing-library/react'
import { beforeAll, describe, expect, it } from 'vitest'
import { SideNav } from './SideNav'

beforeAll(() => {
  // jsdom has no matchMedia; SideNav's desktop-breakpoint hook needs one.
  window.matchMedia = ((query: string) => ({
    matches: true, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {},
    addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
})

function renderNav(flags: { isAdmin?: boolean; canAdmin?: boolean }) {
  const noop = () => {}
  return render(
    <SideNav
      activeTab="reports" onTabChange={noop}
      accessSubTabs={[]} accessSubTab="" onAccessSubTabChange={noop}
      reportsSubTab="browse" onReportsSubTabChange={noop}
      onOpenEnvironments={noop} onOpenBanner={noop} onOpenAccessControl={noop} onOpenAbout={noop}
      {...flags}
    />,
  )
}

describe('SideNav admin entries', () => {
  it('shows Audit Log and banner settings to a local-mode operator, but not Access control', () => {
    renderNav({ isAdmin: false, canAdmin: true })
    expect(screen.queryAllByText('Audit Log').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Announcement banner').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Access control')).toHaveLength(0)
  })

  it('shows all three to a verified admin', () => {
    renderNav({ isAdmin: true, canAdmin: true })
    expect(screen.queryAllByText('Audit Log').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Announcement banner').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Access control').length).toBeGreaterThan(0)
  })

  it('shows none of them to an ordinary hosted user', () => {
    renderNav({ isAdmin: false, canAdmin: false })
    expect(screen.queryAllByText('Audit Log')).toHaveLength(0)
    expect(screen.queryAllByText('Announcement banner')).toHaveLength(0)
    expect(screen.queryAllByText('Access control')).toHaveLength(0)
  })
})
