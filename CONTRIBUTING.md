# Contributing

Thanks for considering a contribution. This is a community project with
one informal maintainer, not a company with a dedicated review team — a
little extra care in your PR goes a long way toward getting it merged
quickly.

## Before you start

For anything bigger than a small fix (a new feature, a change to the
auth/security flow, a schema change), open an issue first describing
what you want to do. Saves you from building something that gets
redesigned in review, and lets the maintainer flag anything relevant
before you invest time.

## Setting up locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cd frontend && npm ci --ignore-scripts
```

Python 3.9 is the oldest supported version and CI runs the suite on 3.9,
3.12 and 3.14, so keep backend code 3.9-compatible (no `match`, no
`X | Y` annotations evaluated at runtime without
`from __future__ import annotations`). The frontend tests need Node
22.22.2+ or 24.15+; the build alone works from 20.19.

Run it with `python launch.py` from the repo root — see the main
[README](README.md) for the full quickstart.

## Before opening a PR

**There's a backend `pytest` suite** (`tests/`, run with
`pip install -r requirements-dev.txt && pytest` from the repo root) and a
**frontend `vitest` suite** (`frontend/src/**/*.test.{ts,tsx}`, run with
`cd frontend && npm test`) — both run automatically on every push/PR via
GitHub Actions (`.github/workflows/ci.yml`). The backend suite covers
the functions with the most direct history of silent breakage (admin
same-owner-name disambiguation, the P0 header-spoofing fix, the sync
watermark, atomic-write crash safety, the Phase 3 step-up transaction
binding) plus a two-owner collision integration test, and an HTTP
authorization matrix (`tests/test_http_authz_matrix.py`) that drives
**every** route in `server/serve.py` as an unauthenticated caller, a
non-admin, an admin, the local-mode operator and a second owner. Its route
list is parsed out of `serve.py` itself, so **a new route fails CI until
you add a matrix entry for it** (say which kind it is: public, open,
admin, env-scoped or session-scoped). The frontend
suite (72 test files) covers the components (`src/components`, including the
Overview, Access Explorer, Audit Log and Updates pages), the hooks (`src/hooks`,
among them the two with a documented history of a real, once-fixed bug:
`useAccessBootstrapJob`'s polling-stops-too-early fix and `useFuzzyFilter`'s
stale-array-reference behavior), the utilities (`src/utils`) and the API
client (`src/api`). Neither suite is
exhaustive — add a test alongside your fix if you touch
`create_secret_folders.py`/`server/serve.py`/`audit_store.py` on the
backend, or a hook/util with non-trivial state on the frontend. This is
the real bar for a PR to be mergeable (CI runs all of it, but check
locally before pushing so you're not waiting on a CI round-trip to find
out):

```bash
# Backend: run the test suite
pip install -r requirements-dev.txt
pytest

# Backend: confirm every touched Python file still parses
python -c "import ast; ast.parse(open('path/to/file.py', encoding='utf-8').read())"

# Frontend: type-check (build mode -- the root tsconfig.json only holds
# project references, so a plain `tsc --noEmit` checks nothing)
cd frontend && npx tsc -b

# Frontend: run the test suite
npm test

# Frontend: lint
npm run lint

# Frontend: confirm it still builds
npx vite build

# Frontend: known-vulnerable runtime dependencies (CI fails on high or worse)
npm audit --omit=dev --audit-level=high

# Shell scripts (server/*.sh run with sudo on servers): syntax + ShellCheck
git ls-files -z '*.sh' | xargs -0 -n1 bash -n
git ls-files -z '*.sh' | xargs -0 shellcheck --severity=warning

# get-ocw.sh (the one-line installer) is generated from server/get-ocw.sh.in
# with the verifier and key list embedded: check the template and the
# rendered script, which is what users run
bash -n server/get-ocw.sh.in && shellcheck --severity=warning server/get-ocw.sh.in
python3 tools/render_bootstrap.py 0.0.0 /tmp/get-ocw.sh
bash -n /tmp/get-ocw.sh && shellcheck --severity=warning /tmp/get-ocw.sh
```

CI (`.github/workflows/ci.yml`) runs these as separate jobs so one failure
never hides another: the backend suite on Python 3.9, 3.12 and 3.14 with
`OPA_REQUIRE_NGINX_TESTS=1` (the nginx template tests run the real nginx and
fail, rather than skip, if it is missing: install `nginx` to run them
locally the same way); the shell checks above; the frontend checks on Node 24;
`npm audit`; and a build-only job on the oldest Node versions the build accepts
(20.19.0 and 22.12.0).

`server/deploy.sh` and `server/setup-second-gate.sh` have behaviour tests
that run them for real against temp directories with stubbed system
commands (`tests/test_deploy_sh.py`, `tests/test_setup_second_gate_sh.py`);
so do the installer and the one-line installer (`tests/test_install_sh.py`,
`tests/test_install_fresh.py`, `tests/test_bootstrap_sh.py`). Extend them when
you change the script they cover.

Beyond that: **manually exercise the feature you changed.** If you fixed
a bug, reproduce it first, then confirm your fix actually resolves it —
don't rely on the change "looking correct." If you touched a hosted-
deployment code path (`server/auth_gate.py`, `server/serve.py`'s header
trust logic, anything in `server/nginx-opa-secrets-wizard.conf`), say so
explicitly in your PR description — those get extra scrutiny given what
they protect. The same goes for what runs as root or decides what is
trusted: `server/updater/root/` (the root-run updater), `server/install.sh`,
`server/get-ocw.sh.in` (the one-line installer) and `server/release_keys.json`
(the signing keys). Changing those is changing code that runs as root or
that decides which release is accepted, so they are reviewed as such
(see [docs/releasing.md](docs/releasing.md)).

## Code style

- **Comments explain *why*, not *what*.** This codebase leans heavily on
  comments that capture a non-obvious reason, a bug that was found and
  fixed, or a constraint confirmed by live testing — not comments that
  just restate what the next line does. Look at any existing file for
  the pattern before adding new comments.
- **Verify claims against the real API/tenant behavior when you can,
  rather than trusting documentation.** This project has a running list
  of places where Okta/OPA's published docs turned out to be wrong or
  incomplete — see [docs/api-notes.md](docs/api-notes.md). If you find
  another one, add it there.
- Match the existing file's formatting conventions (the frontend's linter
  is oxlint, `npm run lint`, run in CI; the backend has no enforced
  formatter) — consistency with surrounding code matters
  more than any particular personal style preference.

## Versioning

Every real change bumps `SCRIPT_VERSION` **and** the `# Version` header
comment in `create_secret_folders.py` together (they're required to
match), and gets a corresponding entry in [CHANGELOG.md](CHANGELOG.md).
If your PR doesn't include a version bump and changelog entry, the
maintainer will likely ask you to add one before merging.

A few things are checked when a release is built (`tools/release.py build`)
and are easy to miss:

- `CHANGELOG.md` must have a line that starts with `X.Y.Z — ` (the version,
  a space, an em dash, a space) for the release; without one the build stops.
- `ACTIVATOR_VERSION` in `server/updater/root/ocw_activate.py` is the root-run
  updater's version. The build copies it into the release manifest
  (`activator_version`) and the Updates page compares it with the installed
  one; keep it in step with the release when you change files under
  `server/updater/root/`.
- `OCW_INSTALL_SH_REQUIRED_SINCE` near the top of `server/install.sh` names the
  release whose `install.sh` an *existing* install needs. Bump it to the new
  version only when an existing install must re-run the new `install.sh`
  (the build refuses a marker that is missing, malformed or newer than the
  release). A change that only matters for fresh installs does not bump it.

## Database migrations

Every migration in `audit_store.MIGRATIONS` must be declared in
`server/schema_migrations.json` with the release it came in (`since`) and
`rollback_safe`: whether the previous release's code still works on a
database at that schema (true for added tables, columns and indexes; false
for anything older code reads that was dropped or renamed). The release
build refuses an undeclared migration, and
`tests/test_migration_rollback_safety.py` keeps the file in step with the
code by opening a database migrated by your code with the previous release's
`audit_store.py`, kept at `tests/fixtures/previous_release/audit_store.py`.
When a release is cut, refresh that fixture from the tag being replaced (see
[docs/releasing.md](docs/releasing.md)).

## Reporting a security issue

Don't open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md) for how to report it privately.
