#!/bin/bash
# Ensures a headless gnome-keyring Secret Service is unlocked, then execs serve.py.
# Written for the systemd service (opa-secrets-wizard.service) on the Ubuntu host --
# this box has no desktop/login session, so keyring's SecretService backend needs
# its D-Bus daemon started+unlocked explicitly rather than via a normal login.
set -euo pipefail

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

# Unlocks (or creates, on first run) the login keyring non-interactively.
# --login mode is what actually persists the unlock across process restarts --
# plain --unlock alone was not sufficient (verified live: a set/get round trip
# failed with "Prompt dismissed" until --login was added).
printf '%s' "$KEYRING_UNLOCK_PASSWORD" | /usr/bin/gnome-keyring-daemon --unlock --login --components=secrets

cd "$(dirname "$0")/.."
exec .venv/bin/python server/serve.py --no-browser
