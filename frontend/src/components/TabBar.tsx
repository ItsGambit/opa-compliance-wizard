export interface Tab {
  value: string
  label: string
}

interface Props {
  tabs: Tab[]
  value: string
  onChange: (value: string) => void
}

export function TabBar({ tabs, value, onChange }: Props) {
  return (
    <div role="tablist" className="flex gap-1 border-b border-border">
      {tabs.map(tab => {
        const isActive = tab.value === value
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(tab.value)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              isActive
                ? 'text-text border-accent'
                : 'text-text-faint border-transparent hover:text-text-dim'
            }`}
          >
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}
