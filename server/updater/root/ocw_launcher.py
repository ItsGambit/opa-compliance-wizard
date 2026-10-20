#!/usr/bin/env python3
"""The fixed entry point of the root-owned updater: <opt>/updater/ocw_activate.py is THIS file.

The real code lives in a versioned directory, <opt>/updater/lib/<id>/, and <opt>/updater/current points at the one in use. A
self-update (after a successful upgrade, from the verified release) builds a new directory, runs its self-test, and then flips
the `current` symlink atomically, so a crash or power loss can never leave a mixture of old and new files; the previous
directory stays for one more release. This launcher is replaced only by `install.sh --refresh-updater`, as root.
"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_target = os.path.join(_here, "current", "ocw_activate.py")
if not os.path.isfile(_target):
    sys.exit("the updater's code directory is missing: re-run server/install.sh --refresh-updater")
os.execv(sys.executable, [sys.executable, "-I", "-B", _target] + sys.argv[1:])
