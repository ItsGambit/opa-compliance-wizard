import { useEffect, useState } from 'react'
import { FolderTree, KeyRound, Moon, Search, Settings, Sun } from 'lucide-react'

const THEME_STORAGE_KEY = 'opa-secrets-wizard-theme'

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

interface Props {
  activeTab: string
  onTabChange: (value: string) => void
  accessSubTabs: AccessSubTab[]
  accessSubTab: string
  onAccessSubTabChange: (value: string) => void
  // "Environments" has no dedicated page/tab of its own -- it's the existing
  // EnvironmentManagerDialog (gear icon in the topbar). This just opens that
  // same dialog from the sidebar instead of duplicating its content as a tab.
  onOpenEnvironments: () => void
}

const TOP_LEVEL_ICON: Record<string, typeof FolderTree> = {
  builder: FolderTree,
  access: Search,
  secrets_access: KeyRound,
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

export function SideNav({
  activeTab,
  onTabChange,
  accessSubTabs,
  accessSubTab,
  onAccessSubTabChange,
  onOpenEnvironments,
}: Props) {
  const { theme, toggle } = useTheme()

  return (
    <div className="flex h-full shrink-0">
      {/* Icon rail */}
      <div className="w-12 bg-bg-elevated border-r border-border flex flex-col items-center pt-3 gap-1.5">
        {(['builder', 'access', 'secrets_access'] as const).map(tab => {
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

      {/* Sidebar panel */}
      <div className="w-64 bg-bg-elevated border-r border-border flex flex-col p-3">
        <div className="text-sm font-semibold text-text px-2 mb-3">OPA Secrets Wizard</div>

        <div className="flex flex-col gap-0.5">
          <NavItem
            active={activeTab === 'builder'}
            label="Folder Builder"
            icon={FolderTree}
            onClick={() => onTabChange('builder')}
          />

          <NavItem
            active={activeTab === 'access'}
            label="Access Explorer"
            icon={Search}
            onClick={() => onTabChange('access')}
          />
          {activeTab === 'access' && (
            <div className="pl-6 flex flex-col gap-0.5 mb-1">
              {accessSubTabs.map(sub => (
                <NavItem
                  key={sub.value}
                  active={accessSubTab === sub.value}
                  label={sub.label}
                  onClick={() => onAccessSubTabChange(sub.value)}
                />
              ))}
            </div>
          )}

          <NavItem
            active={activeTab === 'secrets_access'}
            label="Secrets Access Dashboard"
            icon={KeyRound}
            onClick={() => onTabChange('secrets_access')}
          />
        </div>

        {/* Theme toggle -- docked right below nav items, per user feedback on the
            mockup (not pushed to the bottom via margin-top: auto). */}
        <button
          type="button"
          onClick={toggle}
          className="flex items-center gap-2 mt-2.5 px-2.5 py-2 rounded-md text-sm text-text-dim
            bg-[color-mix(in_srgb,var(--color-text)_6%,transparent)]
            hover:bg-[color-mix(in_srgb,var(--color-text)_10%,transparent)] transition-colors"
        >
          {theme === 'light' ? <Sun size={14} /> : <Moon size={14} />}
          {theme === 'light' ? 'Light mode' : 'Dark mode'}
        </button>

        <div className="flex-1" />

        <NavItem active={false} label="Environments" icon={Settings} onClick={onOpenEnvironments} />
      </div>
    </div>
  )
}
