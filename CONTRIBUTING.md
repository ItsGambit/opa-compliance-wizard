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
pip install -r requirements.txt
cd frontend && npm install
```

Run it with `python launch.py` from the repo root — see the main
[README](README.md) for the full quickstart.

## Before opening a PR

**There is a small, backend-only `pytest` suite** (`tests/`, run with
`pip install -r requirements-dev.txt && pytest` from the repo root) — it
covers the functions with the most direct history of silent breakage
(admin same-owner-name disambiguation, the P0 header-spoofing fix, the
sync watermark, atomic-write crash safety) plus a two-owner collision
integration test, but it is **not yet comprehensive** — no frontend
tests, no CI. Run it if you touched any of `create_secret_folders.py`,
`server/serve.py`, or `audit_store.py`; add a test alongside your fix if
you can. This is the real bar for a PR to be mergeable:

```bash
# Backend: run the test suite
pip install -r requirements-dev.txt
pytest

# Backend: confirm every touched Python file still parses
python -c "import ast; ast.parse(open('path/to/file.py', encoding='utf-8').read())"

# Frontend: type-check
cd frontend && npx tsc --noEmit

# Frontend: confirm it still builds
npx vite build
```

Beyond that: **manually exercise the feature you changed.** If you fixed
a bug, reproduce it first, then confirm your fix actually resolves it —
don't rely on the change "looking correct." If you touched a hosted-
deployment code path (`server/auth_gate.py`, `server/serve.py`'s header
trust logic, anything in `server/nginx-opa-secrets-wizard.conf`), say so
explicitly in your PR description — those get extra scrutiny given what
they protect.

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
- Match the existing file's formatting conventions (the frontend has no
  enforced linter config beyond TypeScript's own strictness; the backend
  has no enforced formatter) — consistency with surrounding code matters
  more than any particular personal style preference.

## Versioning

Every real change bumps `SCRIPT_VERSION` **and** the `# Version` header
comment in `create_secret_folders.py` together (they're required to
match), and gets a corresponding entry in [CHANGELOG.md](CHANGELOG.md).
If your PR doesn't include a version bump and changelog entry, the
maintainer will likely ask you to add one before merging.

## Reporting a security issue

Don't open a public issue for a vulnerability — see
[SECURITY.md](SECURITY.md) for how to report it privately.
