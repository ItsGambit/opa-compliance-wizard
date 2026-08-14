#!/usr/bin/env bash
# Mac/Linux launcher -- mirrors "Start OPA Secrets Wizard.bat" for Windows.
# All real logic lives in launch.py; this just finds python3 and calls it.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "python3 not found on PATH. Install Python 3.8+ and try again." >&2
    exit 1
fi

exec "$PYTHON" "$DIR/launch.py" "$@"
