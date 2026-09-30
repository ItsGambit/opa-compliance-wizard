import { useEffect, useState } from 'react'
import {
  ClipboardCheck,
  FolderTree,
  Info,
  KeyRound,
  ListChecks,
  Megaphone,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings,
  Sun,
} from 'lucide-react'

const THEME_STORAGE_KEY = 'opa-compliance-wizard-theme'
const COLLAPSED_STORAGE_KEY = 'opa-compliance-wizard-nav-collapsed'

/** Tracks Tailwind's `md` breakpoint (768px) so JS-driven layout choices
 * (the desktop collapse below) can be scoped to exactly the same
 * viewport range as the `md:` classes already used throughout this
 * component -- collapse is a desktop-only concept; the mobile drawer is
 * always full-width/full-label regardless of a collapsed state persisted
 * from a prior desktop session. */
function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(() => window.matchMedia('(min-width: 768px)').matches)
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 768px)')
    const listener = (e: MediaQueryListEvent) => setIsDesktop(e.matches)
    mq.addEventListener('change', listener)
    return () => mq.removeEventListener('change', listener)
  }, [])
  return isDesktop
}

function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    return stored === 'light' ? 'light' : 'dark'
  })

  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light')
    } else {
      document.documentElement.removeAttribute('data-theme')
    }
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  }, [theme])

  return { theme, toggle: () => setTheme(t => (t === 'light' ? 'dark' : 'light')) }
}

export interface AccessSubTab {
  value: string
  label: string
}

// Exported so App.tsx can drive which panel renders under the Compliance
// Reports top-level nav item -- Secrets Access Dashboard is a SUB-item here
// (per-project secret/folder drill-down), not its own top-level tab, since
// it now reads from the same compliance archive as the report cards do
// (see build_project_secrets_report_from_archive in create_secret_folders.py)
// and belongs conceptually under the same umbrella rather than sitting
// alongside it as an unrelated dashboard.
export const REPORTS_SUB_TABS = [
  { value: 'browse', label: 'Browse Reports' },
  { value: 'secrets_access', label: 'Secrets Access' },
]

interface Props {
  activeTab: string
  onTabChange: (value: string) => void
  accessSubTabs: AccessSubTab[]
  accessSubTab: string
  onAccessSubTabChange: (value: string) => void
  reportsSubTab: string
  onReportsSubTabChange: (value: string) => void
  onOpenEnvironments: () => void
  // Gates whether the Audit Log top-level nav item renders at all -- a
  // non-admin viewer sees no trace of an audit log existing, matching the
  // previous dialog's own admin gate (converted from a modal popup to a
  // full page 2026-09-30, per user feedback that it deserved the same
  // real-page treatment as Compliance Reports).
  isAdmin?: boolean
  onOpenBanner: () => void
  onOpenAbout: () => void
}

const TOP_LEVEL_ICON: Record<string, typeof FolderTree> = {
  reports: ClipboardCheck,
  access: Search,
  builder: FolderTree,
  audit_log: ListChecks,
}

const TOP_LEVEL_LABEL: Record<string, string> = {
  reports: 'Compliance Reports',
  access: 'Access Explorer',
  builder: 'Folder Builder',
  audit_log: 'Audit Log',
}

/** One top-level nav row. When `collapsed`, renders icon-only (centered,
 * square) with a title tooltip as the only label; expanded renders the
 * ordinary icon+label row. Used for both this row and (via NavItem below)
 * sub-items, which never render in collapsed mode at all -- see SideNav. */
function NavItem({
  active,
  label,
  icon,
  onClick,
  collapsed,
}: {
  active: boolean
  label: string
  icon?: typeof FolderTree
  onClick: () => void
  collapsed?: boolean
}) {
  const Icon = icon
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={onClick}
        title={label}
        className={`w-9 h-9 mx-auto flex items-center justify-center rounded-md transition-colors ${
          active ? 'bg-accent text-white' : 'text-text-faint hover:bg-bg-hover hover:text-text-dim'
        }`}
      >
        {Icon && <Icon size={16} />}
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm text-left transition-colors ${
        active ? 'bg-accent-dim text-accent font-medium' : 'text-text-dim hover:bg-bg-hover'
      }`}
    >
      {Icon && <Icon size={15} className="shrink-0" />}
      <span className="truncate">{label}</span>
    </button>
  )
}

// Pill-shaped, semi-transparent utility button -- same treatment as the
// theme toggle originally had, now applied consistently to every utility
// action (Environments, Audit Log, Announcement banner, About, theme) so
// they read as one coherent group rather than the theme toggle looking
// like a one-off. Collapses to an icon-only square, same treatment as
// NavItem above, when the sidebar is collapsed.
function UtilityPill({
  label,
  icon,
  onClick,
  collapsed,
}: {
  label: string
  icon: typeof FolderTree
  onClick: () => void
  collapsed?: boolean
}) {
  const Icon = icon
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={onClick}
        title={label}
        className="w-9 h-9 mx-auto flex items-center justify-center rounded-full text-text-dim
          bg-[color-mix(in_srgb,var(--color-text)_6%,transparent)]
          hover:bg-[color-mix(in_srgb,var(--color-text)_10%,transparent)] transition-colors"
      >
        <Icon size={14} />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 px-2.5 py-2 rounded-full text-sm text-text-dim
        bg-[color-mix(in_srgb,var(--color-text)_6%,transparent)]
        hover:bg-[color-mix(in_srgb,var(--color-text)_10%,transparent)] transition-colors"
    >
      <Icon size={14} />
      {label}
    </button>
  )
}

export function SideNav({
  activeTab,
  onTabChange,
  accessSubTabs,
  accessSubTab,
  onAccessSubTabChange,
  reportsSubTab,
  onReportsSubTabChange,
  onOpenEnvironments,
  isAdmin,
  onOpenBanner,
  onOpenAbout,
}: Props) {
  const { theme, toggle } = useTheme()

  // Desktop collapse (persisted -- a deliberate "make it narrower and
  // leave it that way" choice, distinct from the mobile drawer below,
  // which is always closed on load). Real regression this replaces: an
  // earlier revision rendered a permanent icon-only rail AND the full
  // labeled panel as two separate always-visible columns, which is what
  // actually widened the sidebar on desktop -- this is one single column
  // that toggles between the two states instead of showing both at once.
  const [collapsedPref, setCollapsedPref] = useState(() => localStorage.getItem(COLLAPSED_STORAGE_KEY) === 'true')
  useEffect(() => {
    localStorage.setItem(COLLAPSED_STORAGE_KEY, String(collapsedPref))
  }, [collapsedPref])
  const isDesktop = useIsDesktop()
  // The actual effective collapsed state -- only ever true on desktop,
  // regardless of what's persisted, so a collapsed preference saved on a
  // wide screen never leaks into the mobile drawer's rendering.
  const collapsed = isDesktop && collapsedPref

  // Below md, collapsed/expanded doesn't apply at all -- the panel is
  // hidden by default and toggled open as a fixed overlay drawer instead
  // (closes itself on any nav click, or the backdrop, so it never lingers
  // open over the page underneath).
  const [drawerOpen, setDrawerOpen] = useState(false)
  const closeDrawer = () => setDrawerOpen(false)

  return (
    <div className="flex h-full shrink-0">
      {/* Mobile-only rail: just the hamburger, no icon rail duplicate of
          the panel below it (that duplication was the desktop bug). */}
      <div className="md:hidden w-12 bg-bg-elevated border-r border-border flex flex-col items-center pt-3">
        <button
          type="button"
          onClick={() => setDrawerOpen(o => !o)}
          className="w-8 h-8 flex items-center justify-center rounded-md text-text-faint hover:bg-bg-hover hover:text-text-dim"
          title="Toggle menu"
        >
          <Menu size={16} />
        </button>
      </div>

      {/* Mobile-only backdrop, closes the drawer on outside click */}
      {drawerOpen && <div className="md:hidden fixed inset-0 bg-black/50 z-30" onClick={closeDrawer} />}

      {/* The one sidebar column -- fixed overlay drawer below md when
          open; an ordinary flex sibling at md and above, width toggling
          between collapsed (icon rail) and expanded (labeled panel). */}
      <div
        className={`${drawerOpen ? 'flex' : 'hidden'} md:flex ${collapsed ? 'md:w-14' : 'md:w-64'} w-64
          bg-bg-elevated border-r border-border flex-col p-3 fixed md:relative top-0 left-0 h-full z-40 transition-[width] duration-150`}
      >
        <div className={`flex items-center mb-3 ${collapsed ? 'md:justify-center' : 'justify-between'} px-2`}>
          {!collapsed && <div className="text-sm font-semibold text-text truncate">OPA Compliance Wizard</div>}
          <button
            type="button"
            onClick={() => setCollapsedPref(c => !c)}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="hidden md:flex w-7 h-7 shrink-0 items-center justify-center rounded-md text-text-faint hover:bg-bg-hover hover:text-text-dim"
          >
            {collapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}
          </button>
        </div>
        {/* Mobile drawer always shows the full title -- collapsed only
            ever applies at md and above (mobile has its own always-full
            drawer state, distinct from this desktop toggle). */}
        {collapsed && <div className="md:hidden text-sm font-semibold text-text px-2 mb-3">OPA Compliance Wizard</div>}

        <div className="flex flex-col gap-0.5">
          <NavItem
            active={activeTab === 'reports'}
            label={TOP_LEVEL_LABEL.reports}
            icon={TOP_LEVEL_ICON.reports}
            onClick={() => { onTabChange('reports'); closeDrawer() }}
            collapsed={collapsed}
          />
          {!collapsed && activeTab === 'reports' && (
            <div className="pl-6 flex flex-col gap-0.5 mb-1">
              {REPORTS_SUB_TABS.map(sub => (
                <NavItem
                  key={sub.value}
                  active={reportsSubTab === sub.value}
                  label={sub.label}
                  icon={sub.value === 'secrets_access' ? KeyRound : undefined}
                  onClick={() => { onReportsSubTabChange(sub.value); closeDrawer() }}
                />
              ))}
            </div>
          )}

          <NavItem
            active={activeTab === 'access'}
            label={TOP_LEVEL_LABEL.access}
            icon={TOP_LEVEL_ICON.access}
            onClick={() => { onTabChange('access'); closeDrawer() }}
            collapsed={collapsed}
          />
          {!collapsed && activeTab === 'access' && (
            <div className="pl-6 flex flex-col gap-0.5 mb-1">
              {accessSubTabs.map(sub => (
                <NavItem
                  key={sub.value}
                  active={accessSubTab === sub.value}
                  label={sub.label}
                  onClick={() => { onAccessSubTabChange(sub.value); closeDrawer() }}
                />
              ))}
            </div>
          )}

          <NavItem
            active={activeTab === 'builder'}
            label={TOP_LEVEL_LABEL.builder}
            icon={TOP_LEVEL_ICON.builder}
            onClick={() => { onTabChange('builder'); closeDrawer() }}
            collapsed={collapsed}
          />

          {isAdmin && (
            <NavItem
              active={activeTab === 'audit_log'}
              label={TOP_LEVEL_LABEL.audit_log}
              icon={TOP_LEVEL_ICON.audit_log}
              onClick={() => { onTabChange('audit_log'); closeDrawer() }}
              collapsed={collapsed}
            />
          )}
        </div>

        <div className="flex-1" />

        {/* Utility row -- everything that used to live as icon buttons in
            the page header (Environments' gear icon, banner settings,
            About) now lives here as one consistent group of pill-shaped
            buttons, alongside the theme toggle. Audit Log moved OUT of
            this group 2026-09-30 -- it's a full top-level nav item/page
            now, not a dialog trigger. */}
        <div className="flex flex-col gap-1 pt-2 border-t border-border-sub">
          <UtilityPill label="Environments" icon={Settings} onClick={() => { onOpenEnvironments(); closeDrawer() }} collapsed={collapsed} />
          <UtilityPill label="Announcement banner" icon={Megaphone} onClick={() => { onOpenBanner(); closeDrawer() }} collapsed={collapsed} />
          <UtilityPill label="About" icon={Info} onClick={() => { onOpenAbout(); closeDrawer() }} collapsed={collapsed} />
          <UtilityPill
            label={theme === 'light' ? 'Light mode' : 'Dark mode'}
            icon={theme === 'light' ? Sun : Moon}
            onClick={toggle}
            collapsed={collapsed}
          />
        </div>
      </div>
    </div>
  )
}
