import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { useResourceGroups, useProjects, useSecretsAccessReport } from '../api/hooks'
import type { FolderAccessRow, SecretAccessRow } from '../types'
import { formatDateTime } from '../utils/format'
import { secretsAccessReportExportSections } from '../utils/exportSections'
// AuditCell / AuditHistoryCell / status helpers moved to AuditCells.tsx in
// 5.40.0 so the Service Accounts Dashboard renders history identically.
import { statusLabel, statusVariant } from '../utils/accessStatus'
import { AuditCell, AuditHistoryCell } from './AuditCells'
import { ExportButtons } from './ExportButtons'
import { Select } from './Select'
import { StatusBadge } from './StatusBadge'

function SecretsTable({ rows }: { rows: SecretAccessRow[] }) {
  if (rows.length === 0) return <span className="text-xs text-text-faint">No secrets found in this project.</span>
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-xs text-text-faint border-b border-border">
          <th className="py-1.5 pr-3 font-medium">Secret</th>
          <th className="py-1.5 pr-3 font-medium">Status</th>
          <th className="py-1.5 pr-3 font-medium">Created</th>
          <th className="py-1.5 pr-3 font-medium">Updated</th>
          <th className="py-1.5 pr-3 font-medium">Retrieved</th>
          <th className="py-1.5 font-medium">Deleted</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(row => (
          <tr key={row.id} className="border-b border-border/50 align-top">
            <td className="py-1.5 pr-3">
              <div className="text-text-dim">{row.name}</div>
              <div className="text-xs text-text-faint">{row.path}</div>
            </td>
            <td className="py-1.5 pr-3">
              <StatusBadge label={statusLabel(row.status)} variant={statusVariant(row.status)} />
            </td>
            <td className="py-1.5 pr-3">
              <AuditCell entry={row.created} />
            </td>
            <td className="py-1.5 pr-3">
              <AuditHistoryCell entries={row.updated} />
            </td>
            <td className="py-1.5 pr-3">
              <AuditHistoryCell entries={row.reveals} />
            </td>
            <td className="py-1.5">
              <AuditCell entry={row.deleted} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function FoldersTable({ rows }: { rows: FolderAccessRow[] }) {
  if (rows.length === 0) return <span className="text-xs text-text-faint">No folders found in this project.</span>
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-xs text-text-faint border-b border-border">
          <th className="py-1.5 pr-3 font-medium">Folder</th>
          <th className="py-1.5 pr-3 font-medium">Status</th>
          <th className="py-1.5 pr-3 font-medium">Created</th>
          <th className="py-1.5 pr-3 font-medium">Updated</th>
          <th className="py-1.5 font-medium">Deleted</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(row => (
          <tr key={row.id} className="border-b border-border/50 align-top">
            <td className="py-1.5 pr-3">
              <div className="text-text-dim">{row.name}</div>
              <div className="text-xs text-text-faint">{row.path}</div>
            </td>
            <td className="py-1.5 pr-3">
              <StatusBadge label={statusLabel(row.status)} variant={statusVariant(row.status)} />
            </td>
            <td className="py-1.5 pr-3">
              <AuditCell entry={row.created} />
            </td>
            <td className="py-1.5 pr-3">
              <AuditHistoryCell entries={row.updated} />
            </td>
            <td className="py-1.5">
              <AuditCell entry={row.deleted} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function SecretsAccessDashboard() {
  const [rgId, setRgId] = useState<string | undefined>(undefined)
  const [projectId, setProjectId] = useState<string | undefined>(undefined)

  const { data: resourceGroups } = useResourceGroups(true)
  const { data: projects } = useProjects(rgId, true)
  const { data: report, isLoading, isError, error, refetch, isFetching } = useSecretsAccessReport(rgId, projectId)

  const project = projects?.find(p => p.id === projectId)
  const needsOktaToken = isError && (error as (Error & { body?: { error: string } }) | undefined)?.body?.error?.includes('Okta URL/API token')

  const handleRgChange = (id: string) => {
    setRgId(id)
    setProjectId(undefined)
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <span className="section-label">Resource group</span>
            <Select ariaLabel="Resource group"
              value={rgId}
              onValueChange={handleRgChange}
              placeholder="Select a resource group"
              options={(resourceGroups ?? []).map(rg => ({ value: rg.id, label: rg.name }))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-label">Project</span>
            <Select ariaLabel="Project"
              value={projectId}
              onValueChange={setProjectId}
              disabled={!rgId}
              placeholder="Select a project"
              options={(projects ?? []).map(p => ({ value: p.id, label: p.name }))}
            />
          </div>
        </div>
        {report && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn-secondary"
              disabled={isFetching}
              onClick={() => refetch()}
              title="Re-pull this report from OPA and Okta's System Log"
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} /> Refresh
            </button>
            <ExportButtons
              sections={secretsAccessReportExportSections(report.secrets, report.folders)}
              filenameBase={`opa-secrets-access-${project?.name ?? projectId}`}
            />
          </div>
        )}
      </div>

      {!rgId && <span className="text-sm text-text-faint">Pick a resource group and project to see its secrets access report.</span>}

      {rgId && projectId && isLoading && <span className="text-sm text-text-faint">Loading secrets access report…</span>}

      {needsOktaToken && (
        <div className="card p-3 text-sm text-loss">
          This environment has no Okta URL/API token configured. Add them via the gear menu — the Secrets Access
          Dashboard needs Okta's System Log to attribute who retrieved, changed, or deleted a secret.
        </div>
      )}

      {isError && !needsOktaToken && (
        <div className="card p-3 text-sm text-loss">
          Could not load the secrets access report: {(error as Error).message}
        </div>
      )}

      {report && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs text-text-faint">
              {report.local_retention_enabled
                ? <>Supplemented with locally-preserved history back to {formatDateTime(report.oldest_captured_at)} — beyond that
                  (or for anything not yet captured before this was turned on), a secret with no history shown may simply
                  predate local capture, not necessarily be untouched.</>
                : <>Based on the last {report.since_days} days of Okta System Log history (Okta's retention limit) — a secret
                  with no history shown may simply be older than this window, not necessarily untouched.</>}
            </p>
            {report.complete === false && (
              <p className="text-xs text-warn">
                Incomplete: this project has more log events in the window than one lookup reads, so the oldest
                ones (including some creates) are missing. Run a compliance sync to report from the full archive.
              </p>
            )}
          </div>

          <div className="card p-3 flex flex-col gap-2">
            <span className="section-label">Secrets ({report.secrets.length})</span>
            <SecretsTable rows={report.secrets} />
          </div>

          <div className="card p-3 flex flex-col gap-2">
            <span className="section-label">Folders ({report.folders.length})</span>
            <FoldersTable rows={report.folders} />
          </div>
        </>
      )}
    </div>
  )
}
