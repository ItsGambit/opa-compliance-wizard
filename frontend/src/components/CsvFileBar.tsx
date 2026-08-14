import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Save } from 'lucide-react'
import { fetchCsv, saveCsv } from '../api/client'
import { useCsvFiles } from '../api/hooks'
import { toast } from '../hooks/useToast'
import type { FolderNode } from '../types'
import { flattenTree, treeFromRows } from '../utils/tree'
import { Select } from './Select'

interface Props {
  nodes: FolderNode[]
  onLoad: (nodes: FolderNode[]) => void
}

export function CsvFileBar({ nodes, onLoad }: Props) {
  const { data: files } = useCsvFiles()
  const [loadFile, setLoadFile] = useState<string | undefined>(undefined)
  const [saveFile, setSaveFile] = useState('folders_template.csv')
  const queryClient = useQueryClient()

  const loadMutation = useMutation({
    mutationFn: (file: string) => fetchCsv(file),
    onSuccess: (data, file) => {
      onLoad(treeFromRows(data.rows))
      setSaveFile(file)
      toast({ title: `Loaded ${file}`, description: `${data.rows.length} row(s)`, variant: 'success' })
    },
    onError: (err: Error) => toast({ title: 'Load failed', description: err.message, variant: 'error' }),
  })

  const saveMutation = useMutation({
    mutationFn: () => saveCsv(saveFile, flattenTree(nodes)),
    onSuccess: (data) => {
      toast({ title: `Saved ${data.file}`, description: `${data.row_count} row(s)`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['csv_files'] })
    },
    onError: (err: Error) => toast({ title: 'Save failed', description: err.message, variant: 'error' }),
  })

  return (
    <div className="card p-3 flex flex-wrap items-end gap-4">
      <div className="flex flex-col gap-1">
        <span className="section-label">Load existing CSV</span>
        <div className="flex gap-2">
          <Select
            value={loadFile}
            onValueChange={setLoadFile}
            placeholder="Choose a file"
            options={(files ?? []).map(f => ({ value: f, label: f }))}
          />
          <button
            type="button"
            className="btn-secondary"
            disabled={!loadFile || loadMutation.isPending}
            onClick={() => loadFile && loadMutation.mutate(loadFile)}
          >
            <Download size={13} /> Load
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-1">
        <span className="section-label">Save tree to CSV</span>
        <div className="flex gap-2">
          <input
            value={saveFile}
            onChange={e => setSaveFile(e.target.value)}
            placeholder="filename.csv"
            className="text-input w-48"
          />
          <button
            type="button"
            className="btn-secondary"
            disabled={!saveFile.trim() || saveMutation.isPending}
            onClick={() => saveMutation.mutate()}
          >
            <Save size={13} /> Save
          </button>
        </div>
      </div>
    </div>
  )
}
