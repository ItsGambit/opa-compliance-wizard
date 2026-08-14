import { Download } from 'lucide-react'
import type { ExportSection } from '../utils/export'
import { exportSections } from '../utils/export'

interface Props {
  sections: ExportSection[]
  filenameBase: string
}

export function ExportButtons({ sections, filenameBase }: Props) {
  const hasData = sections.some(s => s.rows.length > 0)
  return (
    <div className="flex items-center gap-1.5">
      <button
        type="button"
        className="btn-secondary !px-2 text-xs"
        disabled={!hasData}
        onClick={() => exportSections(sections, 'csv', filenameBase)}
        title="Export as CSV"
      >
        <Download size={12} /> CSV
      </button>
      <button
        type="button"
        className="btn-secondary !px-2 text-xs"
        disabled={!hasData}
        onClick={() => exportSections(sections, 'md', filenameBase)}
        title="Export as Markdown"
      >
        <Download size={12} /> MD
      </button>
    </div>
  )
}
