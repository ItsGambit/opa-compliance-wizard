import { describe, expect, it } from 'vitest'
import { FOLDER_NAME_MAX_LEN, isValidName } from './validate'

// Mirrors tests/test_review_batch4_engine.py::test_is_valid_folder_name --
// the server re-checks every name, this only gives instant feedback.
describe('isValidName', () => {
  it.each([
    ['DB', true],
    ['a.b-c_d', true],
    ['x'.repeat(FOLDER_NAME_MAX_LEN), true],
    ['x'.repeat(FOLDER_NAME_MAX_LEN + 1), false],
    ['.', false],
    ['..', false],
    ['a b', false],
    ['', false],
    ['a/b', false],
  ])('%s -> %s', (name, ok) => {
    expect(isValidName(name)).toBe(ok)
  })
})
