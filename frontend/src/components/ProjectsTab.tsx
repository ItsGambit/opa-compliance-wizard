import { useMemo, useState } from 'react'
import type { AccessModel } from '../types'
import type { ExportSection } from '../utils/export'
import { grantRows, projectFieldRows } from '../utils/exportSections'
import { rulesGrantedForProject } from '../utils/policy'
import { ExportButtons } from './ExportButtons'
import { KeyValueGrid } from './KeyValueGrid'
import { PolicyRuleCard } from './PolicyRuleCard'
import { Select } from './Select'

interface Props {
  model: AccessModel
}

export function ProjectsTab({ model }: Props) {
  const [rgId, setRgId] = useState<string | undefined>(undefined)
  const [projectId, setProjectId] = useState<string | undefined>(undefined)

  const projectsInRg = useMemo(() => model.projects.filter(p => p.resource_group_id === rgId), [model.projects, rgId])
  const project = model.projects.find(p => p.id === projectId)
  const rg = model.resource_groups.find(r => r.id === rgId)

  const grants = useMemo(() => (projectId ? rulesGrantedForProject(model.policies, projectId) : []), [model.policies, projectId])

  const exportSectionsForProject: ExportSection[] = useMemo(() => {
    if (!project) return []
    return [
      { title: `Project: ${project.name}`, rows: projectFieldRows(project) },
      { title: 'Policies Granting Access', rows: grantRows(grants) },
    ]
  }, [project, grants])

  const handleRgChange = (id: string) => {
    setRgId(id)
    setProjectId(undefined)
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="card p-3 flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1">
          <span className="section-label">Resource group</span>
          <Select
            value={rgId}
            onValueChange={handleRgChange}
            placeholder="Select a resource group"
            options={model.resource_groups.map(r => ({ value: r.id, label: r.name }))}
          />
        </div>
        <div className="flex flex-col gap-1">
          <span className="section-label">Project</span>
          <Select
            value={projectId}
            onValueChange={setProjectId}
            disabled={!rgId}
            placeholder="Select a project"
            options={projectsInRg.map(p => ({ value: p.id, label: p.name }))}
          />
        </div>
      </div>

      {project && (
        <>
          <div className="card p-3 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-text">{project.name}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-faint">{rg?.name}</span>
                <ExportButtons sections={exportSectionsForProject} filenameBase={`opa-project-${project.name}`} />
              </div>
            </div>
            <KeyValueGrid data={project} />
          </div>

          <div className="flex flex-col gap-2">
            <span className="section-label">Policies granting access to this project ({grants.length})</span>
            {grants.length === 0 && (
              <span className="text-xs text-text-faint">
                No policy resolves a specific resource in this project. (Resource-group-wide rules — server labels,
                Active Directory, database selectors — may still apply; check the Resource Groups tab for {rg?.name}.)
              </span>
            )}
            {grants.map(({ policy, rule }, i) => (
              <PolicyRuleCard key={`${policy.id}-${i}`} rule={rule} policyName={policy.name} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}
