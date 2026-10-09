#!/usr/bin/env bash
# Mac/Linux launcher -- mirrors "Start OPA Compliance Wizard.bat" for Windows.
# All real logic lives in launch.py; this just finds a Python 3.9+ and calls it.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHON=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    # LNCH-05: check the version before handing over -- launch.py itself
    # can't print a friendly message on an interpreter too old to parse it
    # (a bare `python` can still be Python 2).
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
        PYTHON=$candidate
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "No Python 3.9 or newer found on PATH (tried python3, python)." >&2
    echo "Install it from https://www.python.org/downloads/ (or your package manager) and try again." >&2
    exit 1
fi

exec "$PYTHON" "$DIR/launch.py" "$@"
