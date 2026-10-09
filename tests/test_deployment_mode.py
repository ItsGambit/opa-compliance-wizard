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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_IMPORT_PROBE = (
    "import sys; sys.path.insert(0, r'{root}'); "
    "import server.serve as serve; "
    "print('DEPLOYMENT_MODE=' + serve.DEPLOYMENT_MODE)"
).format(root=REPO_ROOT)


def _run_with_env(env_overrides, cwd=None):
    # Start from a copy of the REAL environment (so Windows-required vars
    # like SYSTEMROOT, and sys.executable's own needs, are present), but
    # explicitly clear the two vars under test first -- an ambient
    # DEPLOYMENT_MODE/NGINX_PROXY_SECRET already set in the dev's own
    # shell must never leak into a case that expects them unset.
    env = dict(os.environ)
    env.pop("DEPLOYMENT_MODE", None)
    env.pop("NGINX_PROXY_SECRET", None)
    # TEST-07: clearing the env dict is not enough -- the engine re-reads a
    # repo-root .env FILE on import. The opt-out stops that, and the probe
    # runs outside the checkout (it puts the repo on sys.path itself).
    env["OPA_WIZARD_SKIP_DOTENV"] = "1"
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        # A fresh private directory, never the shared temp root: `python -c`
        # puts the cwd on sys.path, so a planted module there would load.
        cwd=str(cwd or tempfile.mkdtemp(prefix="opa-probe-")),
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


def test_dotenv_file_is_ignored_when_the_opt_out_is_set(tmp_path):
    """TEST-07: a .env next to the engine with DEPLOYMENT_MODE=hosted (and
    no proxy secret) used to break the suite. Exercised against a COPY of
    the engine in a temp dir -- never by writing a .env into the real
    checkout, which may hold the developer's own."""
    shutil.copy(REPO_ROOT / "create_secret_folders.py", tmp_path / "create_secret_folders.py")
    (tmp_path / ".env").write_text("DEPLOYMENT_MODE=hosted\nOPA_TEST_DOTENV_MARKER=loaded\n", encoding="utf-8")
    probe = (
        "import os, sys; sys.path.insert(0, r'{d}'); import create_secret_folders; "
        "print(os.environ.get('OPA_TEST_DOTENV_MARKER'), os.environ.get('DEPLOYMENT_MODE'))"
    ).format(d=tmp_path)
    base = {k: v for k, v in os.environ.items() if k not in ("DEPLOYMENT_MODE", "OPA_WIZARD_SKIP_DOTENV")}
    loaded = subprocess.run([sys.executable, "-c", probe], cwd=str(tmp_path), env=base,
                            capture_output=True, text=True, timeout=30)
    assert loaded.returncode == 0, loaded.stderr
    assert loaded.stdout.split() == ["loaded", "hosted"]  # the mechanism is real...
    skipped = subprocess.run([sys.executable, "-c", probe], cwd=str(tmp_path), env={**base, "OPA_WIZARD_SKIP_DOTENV": "1"},
                             capture_output=True, text=True, timeout=30)
    assert skipped.returncode == 0, skipped.stderr
    assert skipped.stdout.split() == ["None", "None"]  # ...and the opt-out stops it


def test_suite_runs_with_the_dotenv_opt_out_and_no_ambient_server_vars():
    assert os.environ.get("OPA_WIZARD_SKIP_DOTENV") == "1"
    assert "DEPLOYMENT_MODE" not in os.environ and "NGINX_PROXY_SECRET" not in os.environ
