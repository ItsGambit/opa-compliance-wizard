/** The shared Access Explorer pieces: layout switch, zebra rows, one open row,
 * sections, filters, group removal and last accessed. */
import { act, cleanup, fireEvent, render, renderHook, screen, within } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { aggregateResources, lastUsedFor, type AccessLookup } from '../../utils/accessResources'
import { lastUsedText } from './lastUsedText'
import { rulesGrantedToGroupIds } from '../../utils/policy'
import { exampleModel } from '../../test/accessFixtures'
import { ExplorerLayout } from './ExplorerLayout'
import { useExplorerLayout } from './explorerContext'
import { ExplorerRows, type ExplorerRowData } from './ExplorerRows'
import { GrantsMain } from './GrantsMain'
import { GroupRemoveControl } from './GroupRemoveControl'
import { LastAccessed } from './LastAccessed'
import { CountList, FilterMenu } from './RailParts'
import { ResourceAccessView } from './ResourceAccessView'
import { TypeSection } from './TypeSection'
import { COMPACT_MAX_WIDTH, WIDE_MIN_WIDTH, layoutForWidth, stripeFor } from './layout'
import { firstPlusMore } from '../../utils/format'
import { ResultsNote } from './ExplorerToolbar'
import { useFilterState } from './useFilterState'
import { useGrantsExplorer } from './useGrantsExplorer'
import { useSectionState } from './useSectionState'

type RoCallback = (entries: { contentRect: { width: number } }[]) => void
let roCallback: RoCallback | null = null
const realRO = globalThis.ResizeObserver

beforeEach(() => {
  roCallback = null
  globalThis.ResizeObserver = class {
    constructor(cb: RoCallback) { roCallback = cb }
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})
afterEach(() => { globalThis.ResizeObserver = realRO })

function resizeTo(width: number) {
  act(() => { roCallback?.([{ contentRect: { width } }]) })
}

describe('layout switch', () => {
  it('is wide from 1100 px of content width, compact under 560, narrow between', () => {
    expect(layoutForWidth(WIDE_MIN_WIDTH)).toBe('wide')
    expect(layoutForWidth(WIDE_MIN_WIDTH - 1)).toBe('narrow')
    expect(layoutForWidth(COMPACT_MAX_WIDTH)).toBe('narrow')
    expect(layoutForWidth(COMPACT_MAX_WIDTH - 1)).toBe('compact')
    expect(layoutForWidth(0)).toBe('narrow') // unmeasurable
  })

  it('follows the measured width of the wrapper, not the window', () => {
    const { container } = render(<ExplorerLayout rail={<div>rail</div>}>main</ExplorerLayout>)
    const wrap = container.querySelector('.xp-wrap')!
    expect(wrap.getAttribute('data-layout')).toBe('narrow')
    resizeTo(1400)
    expect(wrap.getAttribute('data-layout')).toBe('wide')
    resizeTo(900)
    expect(wrap.getAttribute('data-layout')).toBe('narrow')
    resizeTo(400)
    expect(wrap.getAttribute('data-layout')).toBe('compact')
  })

  it('renders the rail as its own landmark beside the main pane', () => {
    render(<ExplorerLayout rail={<div>rail content</div>} railLabel="Test rail">main content</ExplorerLayout>)
    const rail = screen.getByRole('complementary', { name: 'Test rail' })
    expect(within(rail).getByText('rail content')).toBeTruthy()
    expect(within(rail).queryByText('main content')).toBeNull()
  })

  it('the container observed is an outer wrapper, never the grid itself', () => {
    const { container } = render(<ExplorerLayout rail={null}>x</ExplorerLayout>)
    expect(container.querySelector('.xp-wrap > .xp-page')).toBeTruthy()
  })
})

function makeRows(names: string[]): ExplorerRowData[] {
  return names.map(n => ({ id: n, label: n, can: `can ${n}`, via: 'Group', used: 'Never used', detail: () => <div>detail of {n}</div> }))
}

describe('ExplorerRows', () => {
  it('stripes dark, light, dark ... over the rows it is given', () => {
    const { container } = render(<ExplorerLayout rail={null}><ExplorerRows rows={makeRows(['a', 'b', 'c', 'd'])} /></ExplorerLayout>)
    const stripes = [...container.querySelectorAll('.xp-row')].map(r => r.getAttribute('data-stripe'))
    expect(stripes).toEqual(['dark', 'light', 'dark', 'light'])
    expect(stripeFor(0)).toBe('dark')
    expect(stripeFor(1)).toBe('light')
  })

  it('restripes when rows are hidden (stripes follow the VISIBLE rows)', () => {
    const { container, rerender } = render(<ExplorerLayout rail={null}><ExplorerRows rows={makeRows(['a', 'b', 'c', 'd'])} /></ExplorerLayout>)
    rerender(<ExplorerLayout rail={null}><ExplorerRows rows={makeRows(['a', 'c', 'd'])} /></ExplorerLayout>)
    const rows = [...container.querySelectorAll('.xp-row')]
    expect(rows.map(r => r.getAttribute('data-stripe'))).toEqual(['dark', 'light', 'dark'])
    expect(rows.map(r => r.querySelector('.xp-name')!.textContent)).toEqual(['a', 'c', 'd'])
  })

  it('opens one row at a time with aria-expanded, and closes it again', () => {
    render(<ExplorerLayout rail={null}><ExplorerRows rows={makeRows(['a', 'b'])} /></ExplorerLayout>)
    const [a, b] = screen.getAllByRole('button')
    expect(a.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(a)
    expect(a.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByRole('region', { name: 'Details for a' })).toBeTruthy()
    fireEvent.click(b)
    expect(a.getAttribute('aria-expanded')).toBe('false')
    expect(b.getAttribute('aria-expanded')).toBe('true')
    expect(screen.queryByText('detail of a')).toBeNull()
    expect(screen.getByText('detail of b')).toBeTruthy()
    fireEvent.click(b)
    expect(screen.queryByRole('region')).toBeNull()
  })

  it('one open row across several sections of a view', () => {
    render(
      <ExplorerLayout rail={null}>
        <ExplorerRows rows={makeRows(['a'])} />
        <ExplorerRows rows={makeRows(['z'])} />
      </ExplorerLayout>
    )
    const [a, z] = screen.getAllByRole('button')
    fireEvent.click(a)
    fireEvent.click(z)
    expect(screen.getAllByRole('region').length).toBe(1)
    expect(screen.getByText('detail of z')).toBeTruthy()
  })

  it('the open row is framed (data-open) and its detail is not built while closed', () => {
    const detail = vi.fn(() => <div>d</div>)
    const { container } = render(<ExplorerLayout rail={null}><ExplorerRows rows={[{ id: 'x', label: 'x', detail }]} /></ExplorerLayout>)
    expect(detail).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button'))
    expect(container.querySelector('.xp-row')!.getAttribute('data-open')).toBe('true')
    expect(detail).toHaveBeenCalled()
  })
})

function SectionsHarness() {
  const sections = useSectionState(['one', 'two', 'three'])
  return (
    <div>
      <button onClick={() => sections.jumpTo('three')}>jump</button>
      <button onClick={sections.expandAll}>expand</button>
      <button onClick={sections.collapseAll}>collapse</button>
      {['one', 'two', 'three'].map(id => (
        <TypeSection key={id} id={id} title={id} count={2} open={sections.isOpen(id)} onToggle={() => sections.toggle(id)}>
          <div>body {id}</div>
        </TypeSection>
      ))}
    </div>
  )
}

describe('sections', () => {
  it('opens only the first section by default, headers carry aria-expanded', () => {
    render(<SectionsHarness />)
    expect(screen.getByRole('button', { name: /one/ }).getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByRole('button', { name: /two/ }).getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByText('body two')).toBeNull()
  })

  it('toggles a section, expands all and collapses all', () => {
    render(<SectionsHarness />)
    fireEvent.click(screen.getByRole('button', { name: /two/ }))
    expect(screen.getByText('body two')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /one/ }))
    expect(screen.queryByText('body one')).toBeNull()
    fireEvent.click(screen.getByText('expand'))
    expect(screen.getAllByText(/^body /).length).toBe(3)
    fireEvent.click(screen.getByText('collapse'))
    expect(screen.queryAllByText(/^body /).length).toBe(0)
  })

  it('a section jump opens that section and moves focus to its header', () => {
    render(<SectionsHarness />)
    fireEvent.click(screen.getByText('jump'))
    expect(screen.getByText('body three')).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: /three/ }))
  })
})

describe('FilterMenu', () => {
  const items = [{ id: 'a', label: 'No approval or MFA', count: 3 }, { id: 'b', label: 'Not tracked', count: 1, disabled: true }]

  function Probe({ width }: { width: number }) {
    return (
      <ExplorerLayout rail={<FilterMenu items={items} active={new Set(['a'])} onToggle={() => undefined} />}>
        <span>w{width}</span>
      </ExplorerLayout>
    )
  }

  it('is a disclosure when stacked', () => {
    render(<Probe width={800} />)
    resizeTo(800)
    expect(screen.queryByRole('checkbox')).toBeNull()
    const button = screen.getByRole('button', { name: /Filter \(1\)/ })
    expect(button.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(button)
    expect(screen.getAllByRole('checkbox').length).toBe(2)
  })

  it('is an always-open checkbox list in the wide rail, with disabled entries kept disabled', () => {
    render(<Probe width={1400} />)
    resizeTo(1400)
    expect(screen.queryByRole('button', { name: /Filter/ })).toBeNull()
    const boxes = screen.getAllByRole('checkbox') as HTMLInputElement[]
    expect(boxes.map(b => b.checked)).toEqual([true, false])
    expect(boxes[1].disabled).toBe(true)
  })
})

describe('CountList', () => {
  it('calls back with the clicked type', () => {
    const onSelect = vi.fn()
    render(<CountList items={[{ id: 'servers', label: 'servers', count: 4 }, { id: 'domain', label: 'domain', count: 1 }]} onSelect={onSelect} />)
    fireEvent.click(screen.getByRole('button', { name: /4\s*servers/ }))
    expect(onSelect).toHaveBeenCalledWith('servers')
  })
})

const grants = rulesGrantedToGroupIds(exampleModel.policies, new Set(['g1', 'g2']))
const resources = aggregateResources(grants, { groupsFor: p => p.principals.user_groups.filter(g => ['g1', 'g2'].includes(g.id)) })

function Harness({ lookup }: { lookup?: AccessLookup }) {
  const ex = useGrantsExplorer({ resources, lookup, resetKey: 'u1' })
  const { wide } = useExplorerLayout()
  return (
    <div>
      <span data-testid="wide">{String(wide)}</span>
      <CountList items={ex.countItems} onSelect={ex.jump} />
      <FilterMenu items={ex.filterItems} active={ex.active} onToggle={ex.toggleFilter} />
      <GrantsMain ex={ex} now={Date.parse('2026-10-18T12:00:00Z')} searchLabel="Search access" emptyMessage="nothing" renderDetail={r => <ResourceAccessView resource={r} now={0} />} />
    </div>
  )
}
function renderHarness(lookup?: AccessLookup) {
  const view = render(<ExplorerLayout rail={null}><Harness lookup={lookup} /></ExplorerLayout>)
  resizeTo(1400) // wide: the filter list is always open
  return view
}

describe('resource sections (GrantsMain)', () => {
  it('shows a section per resource type with its count and one row per resource', () => {
    const { container } = renderHarness()
    expect(screen.getByRole('button', { name: /Servers\s*2/ }).getAttribute('aria-expanded')).toBe('true')
    expect(container.querySelectorAll('.xp-row').length).toBe(2)
    expect(screen.getByRole('button', { name: /Managed SaaS app accounts\s*3/ }).getAttribute('aria-expanded')).toBe('false')
  })

  it('the count list "Go to section" jumps to and opens its section', () => {
    renderHarness()
    fireEvent.click(screen.getByRole('button', { name: /3\s*managed saas app accounts/i }))
    expect(screen.getByRole('button', { name: /Managed SaaS app accounts\s*3/ }).getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(within(screen.getByRole('group', { name: /managed saas app accounts list/i })).getByRole('button', { name: 'Go to section' }))
    expect(screen.getByRole('button', { name: /Managed SaaS app accounts\s*3/ }).getAttribute('aria-expanded')).toBe('true')
    expect(document.querySelector('.xp-main')!.textContent).toContain('crm-svc@example.test')
  })

  describe('type dropdowns in the rail', () => {
    const saas = () => screen.getByRole('button', { name: /3\s*managed saas app accounts/i })
    const servers = () => screen.getByRole('button', { name: /2\s*servers/i })

    it('are collapsed by default, toggle with aria-expanded and list the resources of the type', () => {
      renderHarness()
      expect(saas().getAttribute('aria-expanded')).toBe('false')
      expect(screen.queryByRole('group', { name: /managed saas app accounts list/i })).toBeNull()
      fireEvent.click(saas())
      expect(saas().getAttribute('aria-expanded')).toBe('true')
      const list = within(screen.getByRole('group', { name: /managed saas app accounts list/i }))
      expect(list.getAllByRole('listitem').length).toBe(3)
      expect(list.getByRole('button', { name: 'crm-svc@example.test' }).getAttribute('title')).toBe('crm-svc@example.test')
      fireEvent.click(saas())
      expect(saas().getAttribute('aria-expanded')).toBe('false')
      expect(screen.queryByRole('group', { name: /managed saas app accounts list/i })).toBeNull()
    })

    it('several can be open at once', () => {
      renderHarness()
      fireEvent.click(saas())
      fireEvent.click(servers())
      expect(saas().getAttribute('aria-expanded')).toBe('true')
      expect(servers().getAttribute('aria-expanded')).toBe('true')
      const list = within(screen.getByRole('group', { name: /servers list/i }))
      expect(list.getByRole('button', { name: 'lab-linux-example-01' })).toBeTruthy()
    })

    it('are real buttons, so Enter and Space work, and stay in the tab order', () => {
      renderHarness()
      saas().focus()
      expect(document.activeElement).toBe(saas())
      expect(saas().tagName).toBe('BUTTON')
      expect(saas().getAttribute('type')).toBe('button')
      fireEvent.click(saas())
      const entry = within(screen.getByRole('group', { name: /managed saas app accounts list/i })).getByRole('button', { name: 'crm-svc@example.test' })
      expect(entry.tagName).toBe('BUTTON')
      expect(entry.getAttribute('tabindex')).toBeNull()
    })

    it('clicking a name opens its section and row, focuses it and keeps one row open', () => {
      renderHarness()
      fireEvent.click(saas())
      fireEvent.click(within(screen.getByRole('group', { name: /managed saas app accounts list/i })).getByRole('button', { name: 'crm-svc@example.test' }))
      expect(screen.getByRole('button', { name: /Managed SaaS app accounts\s*3/ }).getAttribute('aria-expanded')).toBe('true')
      const row = document.activeElement as HTMLElement
      expect(row.classList.contains('xp-sum')).toBe(true)
      expect(row.textContent).toContain('crm-svc@example.test')
      expect(row.getAttribute('aria-expanded')).toBe('true')
      expect(document.querySelectorAll('.xp-sum[aria-expanded="true"]').length).toBe(1)
      // a second pick elsewhere moves the single open row
      fireEvent.click(servers())
      fireEvent.click(within(screen.getByRole('group', { name: /servers list/i })).getByRole('button', { name: 'lab-linux-example-01' }))
      const next = document.activeElement as HTMLElement
      expect(next.textContent).toContain('lab-linux-example-01')
      expect(next.getAttribute('aria-expanded')).toBe('true')
      expect(document.querySelectorAll('.xp-sum[aria-expanded="true"]').length).toBe(1)
    })

    it('list only what is visible and show "visible of total" while a filter hides some', () => {
      renderHarness()
      fireEvent.click(servers())
      fireEvent.click(screen.getByRole('checkbox', { name: /No approval or MFA/ }))
      const button = screen.getByRole('button', { name: /0 of 2\s*servers/i })
      expect(button.getAttribute('aria-expanded')).toBe('true')
      const list = within(screen.getByRole('group', { name: /servers list/i }))
      expect(list.queryByRole('button', { name: 'lab-linux-example-01' })).toBeNull()
      expect(list.getByText(/None match/)).toBeTruthy()
      expect(list.getByRole('button', { name: 'Go to section' })).toBeTruthy()
      fireEvent.click(saas())
      expect(within(screen.getByRole('group', { name: /managed saas app accounts list/i })).getAllByRole('listitem').length).toBe(3)
    })

    it('search narrows the list to the matching resources', () => {
      renderHarness()
      fireEvent.change(screen.getByLabelText('Search access'), { target: { value: 'crm-redonly' } })
      fireEvent.click(screen.getByRole('button', { name: /1 of 3\s*managed saas app accounts/i }))
      const list = within(screen.getByRole('group', { name: /managed saas app accounts list/i }))
      expect(list.getAllByRole('listitem').length).toBe(1)
      expect(list.getByRole('button', { name: 'crm-readonly@example.test' })).toBeTruthy()
    })

    it('when stacked the open lists are panels under the band, not inside the entries', () => {
      const { container } = render(<ExplorerLayout rail={null}><Harness /></ExplorerLayout>)
      resizeTo(900)
      expect(screen.getByTestId('wide').textContent).toBe('false')
      fireEvent.click(saas())
      const panel = screen.getByRole('group', { name: /managed saas app accounts list/i })
      expect(panel.closest('li')).toBeNull()
      expect(container.querySelector('.xp-counts')!.contains(panel)).toBe(false)
      expect(saas().getAttribute('aria-controls')).toBe(panel.id)
      fireEvent.click(within(panel).getByRole('button', { name: 'crm-svc@example.test' }))
      expect((document.activeElement as HTMLElement).textContent).toContain('crm-svc@example.test')
    })
  })

  it('the "No approval or MFA" filter hides rows, drops empty sections and restripes', () => {
    const { container } = renderHarness()
    fireEvent.click(screen.getByRole('button', { name: 'Expand all' }))
    expect(container.querySelectorAll('.xp-row').length).toBe(5)
    fireEvent.click(screen.getByRole('checkbox', { name: /No approval or MFA/ }))
    // the two servers' rule has MFA: only the three SaaS accounts remain
    expect(screen.queryByText('lab-linux-example-01')).toBeNull()
    expect(screen.queryByRole('button', { name: /^Servers/ })).toBeNull()
    const rows = [...container.querySelectorAll('.xp-row')]
    expect(rows.length).toBe(3)
    expect(rows.map(r => r.getAttribute('data-stripe'))).toEqual(['dark', 'light', 'dark'])
    expect(screen.getByText(/Showing 3 of 5/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    fireEvent.click(screen.getByRole('button', { name: 'Expand all' }))
    expect(container.querySelectorAll('.xp-row').length).toBe(5)
  })

  it('search is fuzzy (typo tolerant), restripes and opens the sections with matches', () => {
    const { container } = renderHarness()
    fireEvent.change(screen.getByLabelText('Search access'), { target: { value: 'crm-redonly' } })
    const rows = [...container.querySelectorAll('.xp-row')]
    expect(rows.length).toBe(1)
    expect(rows[0].getAttribute('data-stripe')).toBe('dark')
    expect(rows[0].textContent).toContain('crm-readonly@example.test')
  })

  it('says when nothing matches', () => {
    renderHarness()
    fireEvent.change(screen.getByLabelText('Search access'), { target: { value: 'zzzzqqqq' } })
    expect(screen.getByText('Nothing matches the current search and filters.')).toBeTruthy()
  })

  it('usage filters are only offered with a last-accessed lookup, and wait until it is ready', () => {
    renderHarness()
    expect(screen.queryByRole('checkbox', { name: /Used in the last 90 days/ })).toBeNull()
    cleanupAndRender({ status: 'loading' })
    expect((screen.getByRole('checkbox', { name: /Used in the last 90 days/ }) as HTMLInputElement).disabled).toBe(true)
  })

  it('usage filters narrow to used / never used / not tracked', () => {
    const now = '2026-10-10T00:00:00Z'
    const lookup: AccessLookup = {
      status: 'ready',
      byId: new Map([
        ['a1', { resource_kind: 'individual_managed_saas_app_account', supported: true, events: [{ published: now, request_id: 'req-1', outcome: 'SUCCESS' }] }],
        ['a2', { resource_kind: 'individual_managed_saas_app_account', supported: true, events: [] }],
        ['a3', { resource_kind: 'individual_managed_saas_app_account', supported: true, events: [] }],
      ]),
    }
    const { container } = renderHarness(lookup)
    fireEvent.click(screen.getByRole('checkbox', { name: /Used in the last 90 days/ }))
    expect([...container.querySelectorAll('.xp-row')].map(r => r.textContent)).toEqual([expect.stringContaining('crm-svc@example.test')])
    fireEvent.click(screen.getByRole('checkbox', { name: /Used in the last 90 days/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /Not used in 90 days/ }))
    expect(container.querySelectorAll('.xp-row').length).toBe(2)
  })
})

function cleanupAndRender(lookup: AccessLookup) {
  cleanup()
  renderHarness(lookup)
}

describe('ResourceAccessView', () => {
  it('shows what it is, what they can do, conditions and every way they get it', () => {
    const server = resources.find(r => r.name === 'lab-linux-example-01')!
    render(<ResourceAccessView resource={server} now={0} />)
    expect(screen.getByText('What it is')).toBeTruthy()
    expect(screen.getByText('View the password')).toBeTruthy()
    expect(screen.getByText('reveal_password: reveal_password')).toBeTruthy()
    expect(screen.getByText(/MFA required/)).toBeTruthy()
    expect(screen.getByText(/Rule “Server access” · policy Linux Servers Policy/)).toBeTruthy()
    expect(screen.queryByText(/Last accessed/)).toBeNull() // no lookup in this view
  })

  it('offers the per-group action and a "no conditions" line', () => {
    const crm = resources.find(r => r.name === 'crm-svc@example.test')!
    render(<ResourceAccessView resource={crm} now={0} renderGroupAction={g => <button>remove {g.name}</button>} />)
    expect(screen.getByText(/None\. No MFA, approval or gateway/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'remove Example-All-Users' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'remove Example-Linux-Admins' })).toBeTruthy()
  })

  it('a tracked account shows its last accessed, with copy-able request ids and an older fold', () => {
    const [acct] = aggregateResources(rulesGrantedToGroupIds([
      { ...exampleModel.policies[1], rules: [{ ...exampleModel.policies[1].rules[0], resolutions: [{ ...exampleModel.policies[1].rules[0].resolutions[0] as object, kind: 'resolved', access_tracking_id: 'trk' } as never] }] },
    ], new Set(['g1'])))
    const lookup: AccessLookup = {
      status: 'ready',
      byId: new Map([['trk', {
        resource_kind: 'x', supported: true,
        events: [
          { published: '2026-10-15T09:00:00Z', request_id: '2b7e1c40-5a9d-4f3e-8b21-7c0d9e6f1a23', outcome: 'SUCCESS' },
          { published: '2026-10-02T09:00:00Z', request_id: '6f1a9c3d-2e8b-4d57-a0c4-3b9e7d2f5e61', outcome: 'FAILURE' },
        ],
      }]]),
    }
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<ResourceAccessView resource={acct} lookup={lookup} now={Date.parse('2026-10-18T09:00:00Z')} />)
    expect(screen.getByText('3 days ago')).toBeTruthy()
    expect(screen.getByText('1 older')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Copy request id 2b7e1c40-5a9d-4f3e-8b21-7c0d9e6f1a23' }))
    expect(writeText).toHaveBeenCalledWith('2b7e1c40-5a9d-4f3e-8b21-7c0d9e6f1a23')
  })
})

describe('LastAccessed states (UI-12: never "loading…" forever)', () => {
  const targets = [{ id: 'sec-1', label: 'db-password' }]

  it('a failed lookup says unavailable and offers Retry', () => {
    const onRetry = vi.fn()
    render(<LastAccessed lookup={{ status: 'error', message: 'Access model not loaded yet', onRetry }} targets={targets} now={0} />)
    expect(screen.getByText(/unavailable: Access model not loaded yet/)).toBeTruthy()
    expect(screen.queryByText('loading…')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('a finished lookup with no entry for a resource says so', () => {
    render(<LastAccessed lookup={{ status: 'ready', byId: new Map() }} targets={targets} now={0} />)
    expect(screen.getByText('no result returned for this resource')).toBeTruthy()
  })

  it('while loading, says loading', () => {
    render(<LastAccessed lookup={{ status: 'loading' }} targets={targets} now={0} />)
    expect(screen.getByText('loading…')).toBeTruthy()
  })

  it('not tracked, not accessed and incomplete each have their own message', () => {
    const base = { resource_kind: 'secret', events: [] }
    const lookup = (info: object): AccessLookup => ({ status: 'ready', byId: new Map([['sec-1', { ...base, supported: true, ...info }]]) })
    const { rerender } = render(<LastAccessed lookup={lookup({ supported: false })} targets={targets} now={0} />)
    expect(screen.getByText('access tracking not available for this resource type')).toBeTruthy()
    rerender(<LastAccessed lookup={lookup({})} targets={targets} now={0} />)
    expect(screen.getByText('not accessed (or not within the last 90 days)')).toBeTruthy()
    rerender(<LastAccessed lookup={lookup({ complete: false })} targets={targets} now={0} />)
    expect(screen.getByText(/lookup hit its page limit/)).toBeTruthy()
  })

  it('a folder folds its secrets', () => {
    render(<LastAccessed lookup={{ status: 'ready', byId: new Map() }} targets={[...targets, { id: 'sec-2', label: 'other' }]} folder now={0} />)
    expect(screen.getByText('2 secrets in this folder')).toBeTruthy()
  })
})

describe('LastAccessed for database selector rules', () => {
  const targets = [{ id: 'database_accounts', label: 'Any database account this user accessed (the rule is a selector, so this is not limited to the rule\'s connection or name pattern)', kind: 'account_selector' as const }]
  const ev = (published: string, name: string, request_id: string) => ({ published, request_id, outcome: 'SUCCESS', account_name: name })

  it('says what it covers and lists newest time, outcome and request id per account name', () => {
    const lookup: AccessLookup = {
      status: 'ready',
      byId: new Map([['database_accounts', {
        resource_kind: 'database_account', supported: true, complete: true,
        events: [ev('2026-10-17T00:00:00Z', 'example-db-a', 'req-a-new'), ev('2026-10-16T00:00:00Z', 'example-db-b', 'req-b'), ev('2026-10-10T00:00:00Z', 'example-db-a', 'req-a-old')],
      }]]),
    }
    render(<LastAccessed lookup={lookup} targets={targets} now={Date.parse('2026-10-18T00:00:00Z')} />)
    expect(screen.getByText(/the rule is a selector, so this is not limited/)).toBeTruthy()
    expect(screen.getByText('example-db-a')).toBeTruthy()
    expect(screen.getByText('example-db-b')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Copy request id req-a-new' })).toBeTruthy()
    expect(screen.getByText('1 older')).toBeTruthy()
  })

  it('shows never and page-limit states', () => {
    const lookup = (info: object): AccessLookup => ({ status: 'ready', byId: new Map([['database_accounts', { resource_kind: 'database_account', supported: true, events: [], ...info }]]) })
    const { rerender } = render(<LastAccessed lookup={lookup({ complete: true })} targets={targets} now={0} />)
    expect(screen.getByText('not accessed (or not within the last 90 days)')).toBeTruthy()
    rerender(<LastAccessed lookup={lookup({ complete: false })} targets={targets} now={0} />)
    expect(screen.getByText(/lookup hit its page limit/)).toBeTruthy()
  })

  it('the expanded row shows it instead of "Not tracked"', () => {
    const [res] = aggregateResources(rulesGrantedToGroupIds([{
      id: 'pd', name: 'Db Policy', description: '', active: true, type: 'SECURITY_POLICY', resource_group: { id: 'rg', name: 'RG' },
      principals: { user_groups: [{ id: 'g1', name: 'G' }], workload_roles: [] }, last_updated: null, last_updated_by: null,
      rules: [{ name: 'Db', resource_type: 'database_based_resource', resource_type_label: 'Database accounts', privileges: [], conditions: [], resolutions: [{ kind: 'condition', description: 'Database accounts in example-conn' }] }],
    } as never], new Set(['g1'])))
    render(<ResourceAccessView resource={res} lookup={{ status: 'loading' }} now={0} />)
    expect(screen.queryByText(/Not tracked/)).toBeNull()
    expect(screen.getByText(/Any database account this user accessed/)).toBeTruthy()
  })
})

describe('Active Directory rows and ambiguous last used (5.44.6)', () => {
  const adAcct = {
    kind: 'resolved' as const, id: 'd1', name: 'svc_one', resource_kind: 'individual_active_directory_account', project_id: 'p1', project_name: 'Example Project',
    resource_group_id: 'rg', access_tracking_id: 'd1', sub_label: 'example.test', via_selector: 'AD accounts in domain(s): example.test', account_name: 'svc_one', name_unique: false,
  }
  const [res] = aggregateResources(rulesGrantedToGroupIds([{
    id: 'pa', name: 'Ad Policy', description: '', active: true, type: 'SECURITY_POLICY', resource_group: { id: 'rg', name: 'RG' },
    principals: { user_groups: [{ id: 'g1', name: 'G' }], workload_roles: [] }, last_updated: null, last_updated_by: null,
    rules: [{ name: 'Ad', resource_type: 'active_directory_based_resource', resource_type_label: 'Active Directory accounts', privileges: [], conditions: [], resolutions: [adAcct] }],
  } as never], new Set(['g1'])))

  it('the opened row shows the domain and the rule, while the name stays the account name', () => {
    render(<ResourceAccessView resource={res} now={0} />)
    expect(screen.getByText(/Domain: example\.test/)).toBeTruthy()
    expect(screen.getByText(/Matched by the rule selector: AD accounts in domain\(s\): example\.test/)).toBeTruthy()
    expect(res.name).toBe('svc_one')
    expect(res.hint).toBe('Example Project')
  })

  it('says it cannot tell which account when the name is shared, and the row text is not "Never used"', () => {
    const lookup: AccessLookup = { status: 'ready', byId: new Map([['d1', { resource_kind: 'individual_active_directory_account', supported: true, events: [], complete: true, ambiguous: true }]]) }
    render(<ResourceAccessView resource={res} lookup={lookup} now={0} />)
    expect(screen.getByText(/cannot tell which account/)).toBeTruthy()
    expect(lastUsedText(lastUsedFor(res, lookup), 0).text).toBe('Unknown')
  })
})

describe('GroupRemoveControl', () => {
  function Wrap({ others, onConfirm }: { others: number; onConfirm: () => void }) {
    const [pending] = useState(false)
    return <GroupRemoveControl groupName="Example-All-Users" userName="admin@example.test" otherPolicyCount={others} pending={pending} onConfirm={onConfirm} />
  }

  it('needs a confirm step, warns about other policies, and cancels', () => {
    const onConfirm = vi.fn()
    render(<Wrap others={6} onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove admin@example.test from Example-All-Users' }))
    expect(onConfirm).not.toHaveBeenCalled()
    expect(screen.getByText(/also backs 6 other policies/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByText(/Remove 'admin@example.test'/)).toBeNull()
    expect(onConfirm).not.toHaveBeenCalled()
  })

  it('removes only after "Yes, remove" and has no warning when no other policy uses the group', () => {
    const onConfirm = vi.fn()
    render(<Wrap others={0} onConfirm={onConfirm} />)
    fireEvent.click(screen.getByRole('button', { name: /^Remove admin@example.test/ }))
    expect(screen.queryByText(/also backs/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Yes, remove' }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })
})

describe('filter state helpers', () => {
  it('useFilterState toggles entries, builds the auto-open key and clears', () => {
    const { result } = renderHook(() => useFilterState())
    expect(result.current.filtering).toBe(false)
    expect(result.current.autoOpenKey).toBe('')
    act(() => result.current.toggle('risk'))
    act(() => result.current.setQuery(' crm '))
    expect(result.current.filtering).toBe(true)
    expect(result.current.autoOpenKey).toBe('crm|risk')
    act(() => result.current.toggle('risk'))
    expect(result.current.active.size).toBe(0)
    act(() => result.current.clear())
    expect(result.current.query).toBe('')
    expect(result.current.autoOpenKey).toBe('')
  })

  it('firstPlusMore shows the first name and the rest as +N', () => {
    expect(firstPlusMore([])).toBe('')
    expect(firstPlusMore(['A'])).toBe('A')
    expect(firstPlusMore(['A', 'B', 'C'])).toBe('A +2')
  })

  it('ResultsNote announces the count and clears', () => {
    const onClear = vi.fn()
    render(<ResultsNote shown={2} total={9} onClear={onClear} />)
    expect(screen.getByRole('status').textContent).toContain('Showing 2 of 9')
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onClear).toHaveBeenCalled()
  })
})
