// Mirrors is_valid_folder_name in create_secret_folders.py -- letters,
// digits, "." "_" "-" only, at most FOLDER_NAME_MAX_LEN characters, and
// not "." or ".." -- validated client-side for instant feedback before the
// user ever clicks Preview/Create. The server re-checks every name.
const NAME_PATTERN = /^[A-Za-z0-9._-]+$/
export const FOLDER_NAME_MAX_LEN = 255

export function isValidName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= FOLDER_NAME_MAX_LEN &&
    name !== '.' &&
    name !== '..' &&
    NAME_PATTERN.test(name)
  )
}
