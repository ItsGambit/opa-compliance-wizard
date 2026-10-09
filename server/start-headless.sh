#!/bin/bash
# Ensures a headless gnome-keyring Secret Service is unlocked, then execs serve.py.
# Written for the systemd service (opa-compliance-wizard.service, or an older
# install's opa-secrets-wizard.service -- same file either way) on the Ubuntu host --
# this box has no desktop/login session, so keyring's SecretService backend needs
# its D-Bus daemon started+unlocked explicitly rather than via a normal login.
set -euo pipefail

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

# FIX (confirmed live, 2026-10-01): --login tells the daemon it's being run
# by PAM at an actual login and deliberately does NOT fully initialize --
# per gnome-keyring-daemon(1), it "should later be initialized with a
# gnome-keyring-daemon --start invocation," and --login "may not be used
# together with... --start." This script calls --login on EVERY service
# start/restart (not just a real login), so nothing ever tears down the
# previous invocation first -- confirmed live: 3+ gnome-keyring-daemon
# --unlock --login processes accumulate across repeated restarts (one from
# over a week prior still running), never reaped, each one a brand new
# daemon independently racing to initialize rather than attaching to
# whatever's already there. This box has no desktop/login session at all
# (see this file's own module comment) -- this script is the ONLY thing
# that ever starts a gnome-keyring-daemon here, so killing any stray
# instance before starting a fresh one is safe: nothing else could be
# legitimately depending on a leftover one.
pkill -u "$(id -u)" -f 'gnome-keyring-daemon' 2>/dev/null || true

# Unlocks (or creates, on first run) the login keyring non-interactively.
# --login mode is what actually persists the unlock across process restarts --
# plain --unlock alone was not sufficient (verified live: a set/get round trip
# failed with "Prompt dismissed" until --login was added).
printf '%s' "$KEYRING_UNLOCK_PASSWORD" | /usr/bin/gnome-keyring-daemon --unlock --login --components=secrets

cd "$(dirname "$0")/.."
exec .venv/bin/python server/serve.py --no-browser
