export interface ExportSection {
  title: string
  rows: Record<string, string>[]
}

// SECURITY FIX (independent review, 2026-09-30): a value starting with
// =, +, -, @, or a tab/CR is interpreted as a FORMULA by Excel/Sheets/
// LibreOffice when a CSV is opened, not displayed as plain text --
// classic CSV/formula injection. Every exported field here ultimately
// comes from Okta System Log data (actor/resource display names, etc.)
// which can contain attacker-influenced strings (e.g. a user sets their
// own Okta display name to a formula payload) -- prefixing a leading
// apostrophe is the standard neutralization (every major spreadsheet
// treats a leading `'` as "force this cell to text", stripping the
// apostrophe itself from the displayed value) and does not change what
// a plain-text/CSV-aware reader sees.
function neutralizeFormula(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value
}

function csvEscape(value: string): string {
  value = neutralizeFormula(value)
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

/** Multiple sections in one CSV file, separated by a blank line, each
 * preceded by its own title line — opens fine as one sheet in Excel/
 * Sheets (distinct visual blocks) without needing a multi-file export. */
export function toCsv(sections: ExportSection[]): string {
  const blocks = sections
    .filter(s => s.rows.length > 0)
    .map(section => {
      const columns = Object.keys(section.rows[0])
      const lines = [csvEscape(section.title), columns.map(csvEscape).join(',')]
      for (const row of section.rows) {
        lines.push(columns.map(c => csvEscape(row[c] ?? '')).join(','))
      }
      return lines.join('\n')
    })
  return blocks.join('\n\n')
}

export function toMarkdown(sections: ExportSection[]): string {
  const blocks = sections
    .filter(s => s.rows.length > 0)
    .map(section => {
      const columns = Object.keys(section.rows[0])
      const lines = [
        `## ${section.title}`,
        '',
        `| ${columns.join(' | ')} |`,
        `| ${columns.map(() => '---').join(' | ')} |`,
        ...section.rows.map(row => `| ${columns.map(c => (row[c] ?? '').replace(/\|/g, '\\|')).join(' | ')} |`),
      ]
      return lines.join('\n')
    })
  return blocks.join('\n\n')
}

export function downloadTextFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function exportSections(sections: ExportSection[], format: 'csv' | 'md', filenameBase: string): void {
  if (format === 'csv') {
    downloadTextFile(`${filenameBase}.csv`, toCsv(sections), 'text/csv')
  } else {
    downloadTextFile(`${filenameBase}.md`, toMarkdown(sections), 'text/markdown')
  }
}
