// Mirrors NAME_PATTERN in create_secret_folders.py -- OPA rejects anything
// else, so we validate client-side for instant feedback before the user
// ever clicks Preview/Create.
export const NAME_PATTERN = /^[A-Za-z0-9._-]+$/

export function isValidName(name: string): boolean {
  return name.length > 0 && NAME_PATTERN.test(name)
}
