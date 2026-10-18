import { createContext, useContext } from 'react'
import type { ExplorerLayoutMode } from './layout'

export interface ExplorerContextValue {
  mode: ExplorerLayoutMode
  /** True in the two-pane layout (rail beside the main pane). */
  wide: boolean
  /** The one open row of the whole view (one at a time). */
  openRowId: string | null
  setOpenRowId: (id: string | null) => void
}

export const ExplorerContext = createContext<ExplorerContextValue>({
  mode: 'narrow', wide: false, openRowId: null, setOpenRowId: () => undefined,
})

export function useExplorerLayout(): ExplorerContextValue {
  return useContext(ExplorerContext)
}
