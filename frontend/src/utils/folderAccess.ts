import type { FolderAccessEntry, FolderSecurityPolicy } from '../types'

/** For every folder whose real OPA ID is known (folderIdByPath), find
 * every policy rule that targets it directly — matches by ID against
 * each rule's "resolved" targets (secret_folder selectors only matter
 * here; dynamic/condition targets never name a specific folder). */
export function resolveFolderAccess(
  policies: FolderSecurityPolicy[],
  folderIdByPath: Map<string, string>
): Map<string, FolderAccessEntry[]> {
  const result = new Map<string, FolderAccessEntry[]>()
  for (const [path, folderId] of folderIdByPath) {
    const entries: FolderAccessEntry[] = []
    for (const policy of policies) {
      for (const rule of policy.rules) {
        const hit = rule.targets.some(t => t.kind === 'resolved' && t.id === folderId)
        if (!hit) continue
        entries.push({
          policyId: policy.id,
          policyName: policy.name,
          policyActive: policy.active,
          ruleName: rule.name,
          groups: policy.principals.user_groups,
          workloadRoles: policy.principals.workload_roles,
          privileges: rule.privileges,
        })
      }
    }
    if (entries.length > 0) result.set(path, entries)
  }
  return result
}
