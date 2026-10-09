import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Save } from 'lucide-react'
import { fetchCsv, saveCsv } from '../api/client'
import { useCsvFiles } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { FolderNode } from '../types'
import { flattenTree, looksLikeFolderTemplate, treeFromRows, treeProblems } from '../utils/tree'
import { Select } from './Select'

interface Props {
  nodes: FolderNode[]
  onLoad: (nodes: FolderNode[]) => void
}

/** UI-21 (external review, 2026-10-05): loading a CSV replaced an edited
 * tree on one click, and saving silently overwrote an existing file (also
 * right after a load, when the name is pre-filled). Both now ask first.
 * FE-11: a CSV that is not a folder template (an Okta System Log export
 * waiting to be imported lives in the same folder) is refused with a
 * message instead of failing silently. FE-13: a tree with an empty,
 * invalid or duplicated name can't be saved -- it would not reload as the
 * same tree. */
export function CsvFileBar({ nodes, onLoad }: Props) {
  const { data: files } = useCsvFiles()
  const [loadFile, setLoadFile] = useState<string | undefined>(undefined)
  const [saveFile, setSaveFile] = useState('folders_template.csv')
  const [confirmingLoad, setConfirmingLoad] = useState(false)
  const [confirmingOverwrite, setConfirmingOverwrite] = useState(false)
  const queryClient = useQueryClient()
  const problems = treeProblems(nodes)

  const loadMutation = useMutation({
    mutationFn: (file: string) => fetchCsv(file),
    onSuccess: (data, file) => {
      setConfirmingLoad(false)
      if (!looksLikeFolderTemplate(data.rows)) {
        toast({
          title: `${file} is not a folder template`,
          description: 'A folder template has a "path" column (and optionally "description"). Pick another file.',
          variant: 'error',
        })
        return
      }
      onLoad(treeFromRows(data.rows))
      setSaveFile(file)
      toast({ title: `Loaded ${file}`, description: `${data.rows.length} row(s)`, variant: 'success' })
    },
    onError: (err: Error) => {
      setConfirmingLoad(false)
      toast({ title: 'Load failed', description: err.message, variant: 'error' })
    },
  })

  const saveMutation = useMutation({
    mutationFn: () => saveCsv(saveFile.trim(), flattenTree(nodes)),
    onSuccess: (data) => {
      setConfirmingOverwrite(false)
      toast({ title: `Saved ${data.file}`, description: `${data.row_count} row(s)`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['csv_files'] })
    },
    onError: (err: Error) => {
      setConfirmingOverwrite(false)
      toast({ title: 'Save failed', description: err.message, variant: 'error' })
    },
  })

  const handleLoadClick = () => {
    if (!loadFile) return
    if (nodes.length > 0) setConfirmingLoad(true)
    else loadMutation.mutate(loadFile)
  }

  const handleSaveClick = () => {
    if ((files ?? []).includes(saveFile.trim())) setConfirmingOverwrite(true)
    else saveMutation.mutate()
  }

  return (
    <div className="card p-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1">
          <span className="section-label">Load existing CSV</span>
          <div className="flex gap-2">
            <Select
              ariaLabel="Load existing CSV"
              value={loadFile}
              onValueChange={v => { setLoadFile(v); setConfirmingLoad(false) }}
              placeholder="Choose a file"
              options={(files ?? []).map(f => ({ value: f, label: f }))}
            />
            <button
              type="button"
              className="btn-secondary"
              disabled={!loadFile || loadMutation.isPending || confirmingLoad}
              onClick={handleLoadClick}
            >
              <Download size={13} aria-hidden="true" /> {loadMutation.isPending ? 'Loading…' : 'Load'}
            </button>
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <span className="section-label">Save tree to CSV</span>
          <div className="flex gap-2">
            <input
              aria-label="Save tree to CSV file name"
              value={saveFile}
              onChange={e => { setSaveFile(e.target.value); setConfirmingOverwrite(false) }}
              placeholder="filename.csv"
              className="text-input w-48"
            />
            <button
              type="button"
              className="btn-secondary"
              disabled={!saveFile.trim() || nodes.length === 0 || problems.length > 0 || saveMutation.isPending || confirmingOverwrite}
              title={problems.length > 0 ? problems.join(' ') : undefined}
              onClick={handleSaveClick}
            >
              <Save size={13} aria-hidden="true" /> {saveMutation.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>

      {problems.length > 0 && nodes.length > 0 && (
        <div className="text-[0.6875rem] text-warn" role="status">Fix before saving: {problems.join(' ')}</div>
      )}

      {confirmingLoad && loadFile && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-warn" role="group" aria-label="Confirm loading a CSV">
          Replace the current tree with {loadFile}? Unsaved changes to the tree will be lost.
          <button type="button" className="btn-primary !py-0.5 !px-2" disabled={loadMutation.isPending} onClick={() => loadMutation.mutate(loadFile)}>
            {loadMutation.isPending ? 'Loading…' : 'Yes, load it'}
          </button>
          <button type="button" className="btn-secondary !py-0.5 !px-2" disabled={loadMutation.isPending} onClick={() => setConfirmingLoad(false)}>
            Cancel
          </button>
        </div>
      )}

      {confirmingOverwrite && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-warn" role="group" aria-label="Confirm overwriting a CSV">
          {saveFile.trim()} already exists. Overwrite it with the current tree?
          <button type="button" className="btn-primary !py-0.5 !px-2" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
            {saveMutation.isPending ? 'Saving…' : 'Yes, overwrite'}
          </button>
          <button type="button" className="btn-secondary !py-0.5 !px-2" disabled={saveMutation.isPending} onClick={() => setConfirmingOverwrite(false)}>
            Cancel
          </button>
        </div>
      )}
    </div>
  )
}
