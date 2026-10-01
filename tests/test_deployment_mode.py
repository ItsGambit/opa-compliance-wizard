"""Covers the DEPLOYMENT_MODE=local|hosted startup guard (fast-follow
Phase 9): server/serve.py must refuse to start in `hosted` mode without
NGINX_PROXY_SECRET also set, fail on any unrecognized value, and leave
`local`/unset behavior completely unchanged.

Each case runs in a FRESH subprocess rather than importlib.reload --
NGINX_PROXY_SECRET/DEPLOYMENT_MODE are read into module-level globals at
import time, and a subprocess is the cleanest way to exercise "fresh
process boots with these exact env vars" without any risk of a prior
test's monkeypatched module state leaking in."""
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_IMPORT_PROBE = (
    "import sys; sys.path.insert(0, r'{root}'); "
    "import server.serve as serve; "
    "print('DEPLOYMENT_MODE=' + serve.DEPLOYMENT_MODE)"
).format(root=REPO_ROOT)


def _run_with_env(env_overrides):
    # Start from a copy of the REAL environment (so Windows-required vars
    # like SYSTEMROOT, and sys.executable's own needs, are present), but
    # explicitly clear the two vars under test first -- an ambient
    # DEPLOYMENT_MODE/NGINX_PROXY_SECRET already set in the dev's own
    # shell must never leak into a case that expects them unset.
    env = dict(os.environ)
    env.pop("DEPLOYMENT_MODE", None)
    env.pop("NGINX_PROXY_SECRET", None)
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_default_mode_is_local_with_no_env_vars_set():
    result = _run_with_env({})
    assert result.returncode == 0, result.stderr
    assert "DEPLOYMENT_MODE=local" in result.stdout


def test_hosted_mode_without_proxy_secret_fails_to_import():
    result = _run_with_env({"DEPLOYMENT_MODE": "hosted"})
    assert result.returncode != 0
    assert "NGINX_PROXY_SECRET" in result.stderr
    assert "RuntimeError" in result.stderr


def test_hosted_mode_with_proxy_secret_imports_cleanly():
    result = _run_with_env({"DEPLOYMENT_MODE": "hosted", "NGINX_PROXY_SECRET": "a-real-secret"})
    assert result.returncode == 0, result.stderr
    assert "DEPLOYMENT_MODE=hosted" in result.stdout


def test_local_mode_explicit_with_no_proxy_secret_imports_cleanly():
    result = _run_with_env({"DEPLOYMENT_MODE": "local"})
    assert result.returncode == 0, result.stderr
    assert "DEPLOYMENT_MODE=local" in result.stdout


def test_unrecognized_mode_fails_fast_rather_than_falling_back_to_local():
    result = _run_with_env({"DEPLOYMENT_MODE": "Hosted"})  # wrong case, a real typo shape
    assert result.returncode != 0
    assert "RuntimeError" in result.stderr
    assert "must be 'local' or 'hosted'" in result.stderr
