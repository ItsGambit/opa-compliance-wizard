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
  Search,
  Settings,
  Sun,
} from 'lucide-react'

const THEME_STORAGE_KEY = 'opa-compliance-wizard-theme'

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

function NavItem({ active, label, icon, onClick }: { active: boolean; label: string; icon?: typeof FolderTree; onClick: () => void }) {
  const Icon = icon
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
// like a one-off.
function UtilityPill({ label, icon, onClick }: { label: string; icon: typeof FolderTree; onClick: () => void }) {
  const Icon = icon
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
  const topLevelTabs = isAdmin
    ? (['reports', 'access', 'builder', 'audit_log'] as const)
    : (['reports', 'access', 'builder'] as const)
  // Below md, the labeled panel (w-64) doesn't fit alongside real content
  // on a phone-width viewport -- it's hidden by default and toggled open
  // as a fixed overlay drawer instead (closes itself on any nav click, or
  // the backdrop, so it never lingers open over the page underneath).
  // Above md, this is pixel-identical to the original always-visible
  // panel -- drawerOpen is simply never consulted there.
  const [drawerOpen, setDrawerOpen] = useState(false)

  const closeDrawer = () => setDrawerOpen(false)

  return (
    <div className="flex h-full shrink-0">
      {/* Icon rail */}
      <div className="w-12 bg-bg-elevated border-r border-border flex flex-col items-center pt-3 gap-1.5">
        <button
          type="button"
          onClick={() => setDrawerOpen(o => !o)}
          className="md:hidden w-8 h-8 flex items-center justify-center rounded-md text-text-faint hover:bg-bg-hover hover:text-text-dim mb-1"
          title="Toggle menu"
        >
          <Menu size={16} />
        </button>
        {topLevelTabs.map(tab => {
          const Icon = TOP_LEVEL_ICON[tab]
          const isActive = activeTab === tab
          return (
            <button
              key={tab}
              type="button"
              onClick={() => onTabChange(tab)}
              className={`w-8 h-8 flex items-center justify-center rounded-md transition-colors ${
                isActive ? 'bg-accent text-white' : 'text-text-faint hover:bg-bg-hover hover:text-text-dim'
              }`}
            >
              <Icon size={16} />
            </button>
          )
        })}
      </div>

      {/* Mobile-only backdrop, closes the drawer on outside click */}
      {drawerOpen && (
        <div className="md:hidden fixed inset-0 bg-black/50 z-30" onClick={closeDrawer} />
      )}

      {/* Sidebar panel -- fixed overlay drawer below md when open, ordinary
          flex sibling (unchanged from before) at md and above. */}
      <div
        className={`${drawerOpen ? 'flex' : 'hidden'} md:flex w-64 bg-bg-elevated border-r border-border flex-col p-3 fixed md:relative top-0 left-12 h-full z-40`}
      >
        <div className="text-sm font-semibold text-text px-2 mb-3">OPA Compliance Wizard</div>

        <div className="flex flex-col gap-0.5">
          <NavItem
            active={activeTab === 'reports'}
            label="Compliance Reports"
            icon={ClipboardCheck}
            onClick={() => { onTabChange('reports'); closeDrawer() }}
          />
          {activeTab === 'reports' && (
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
            label="Access Explorer"
            icon={Search}
            onClick={() => { onTabChange('access'); closeDrawer() }}
          />
          {activeTab === 'access' && (
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
            label="Folder Builder"
            icon={FolderTree}
            onClick={() => { onTabChange('builder'); closeDrawer() }}
          />

          {isAdmin && (
            <NavItem
              active={activeTab === 'audit_log'}
              label="Audit Log"
              icon={ListChecks}
              onClick={() => { onTabChange('audit_log'); closeDrawer() }}
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
          <UtilityPill label="Environments" icon={Settings} onClick={() => { onOpenEnvironments(); closeDrawer() }} />
          <UtilityPill label="Announcement banner" icon={Megaphone} onClick={() => { onOpenBanner(); closeDrawer() }} />
          <UtilityPill label="About" icon={Info} onClick={() => { onOpenAbout(); closeDrawer() }} />
          <UtilityPill
            label={theme === 'light' ? 'Light mode' : 'Dark mode'}
            icon={theme === 'light' ? Sun : Moon}
            onClick={toggle}
          />
        </div>
      </div>
    </div>
  )
}
