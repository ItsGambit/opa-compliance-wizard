/** What an admin types to confirm a purge: the first 8 characters of the
 * environment id -- specific to the row (a confirmation typed for one
 * archive can never purge another) without asking for a whole UUID. */
export function purgeConfirmationToken(environmentId: string): string {
  return environmentId.slice(0, 8)
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1 }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[i]}`
}
