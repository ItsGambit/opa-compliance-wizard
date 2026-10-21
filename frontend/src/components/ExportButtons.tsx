import { Download } from 'lucide-react'
import type { ExportSection } from '../utils/export'
import { exportSections } from '../utils/export'

interface Props {
  sections: ExportSection[]
  filenameBase: string
  /** Why export is unavailable right now (e.g. the rows on screen belong
   * to the previous date range while the new one loads). */
  disabledReason?: string
  /** Called after a file was produced (e.g. to record the export in the audit log). */
  onExport?: (format: 'csv' | 'md') => void
}

export function ExportButtons({ sections, filenameBase, disabledReason, onExport }: Props) {
  const hasData = sections.some(s => s.rows.length > 0) && !disabledReason
  return (
    <div className="flex items-center gap-1.5">
      <button
        type="button"
        className="btn-secondary !px-2 text-xs"
        disabled={!hasData}
        onClick={() => { exportSections(sections, 'csv', filenameBase); onExport?.('csv') }}
        title={disabledReason ?? 'Export as CSV'}
      >
        <Download size={12} aria-hidden="true" /> CSV
      </button>
      <button
        type="button"
        className="btn-secondary !px-2 text-xs"
        disabled={!hasData}
        onClick={() => { exportSections(sections, 'md', filenameBase); onExport?.('md') }}
        title={disabledReason ?? 'Export as Markdown'}
      >
        <Download size={12} aria-hidden="true" /> MD
      </button>
    </div>
  )
}
