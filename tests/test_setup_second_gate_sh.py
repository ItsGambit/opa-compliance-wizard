"""server/setup-second-gate.sh: the OPS-13 / OPS-14 pieces, run for real in
bash with stub `sudo` / `nginx` / `cloudflared` (the script itself edits
/etc and needs a real server, so the functions are lifted out of it by name
and run against temp files)."""

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "server" / "setup-second-gate.sh"
TOKEN = "eyJhIjoiVOKEN-not-real-0123456789"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash script")


def _functions(*names):
    text = SCRIPT.read_text()
    out = []
    for line in text.splitlines():
        if re.match(r"^(say|ok|warn|die)\(\)\s+\{", line):
            out.append(line)
    for name in names:
        m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
        assert m, name
        out.append(m.group(0))
    return "\n".join(out)


def _run(tmp_path, body, env_extra=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "sudo").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\nexec "$@"\n')
    # nginx -t answers from a list of exit codes, one per call
    (bin_dir / "nginx").write_text(
        '#!/bin/sh\nrc=$(head -n 1 "$NGINX_RESULTS"); sed -i.bak 1d "$NGINX_RESULTS"\n'
        '[ "$rc" = 0 ] && echo "syntax is ok" || echo "nginx: [emerg] broken site" >&2\nexit "${rc:-0}"\n')
    (bin_dir / "cloudflared").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CF_ARGS"\n'
        '[ "${CF_FAIL:-0}" = 1 ] && { echo "error: invalid token $3" >&2; exit 1; }\nexit 0\n')
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    if not any((Path(p) / "shred").exists() for p in os.environ.get("PATH", "").split(os.pathsep)):
        (bin_dir / "shred").write_text('#!/bin/sh\n[ "$1" = -u ] && shift; exec rm -f "$@"\n')
        (bin_dir / "shred").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "CALLS": str(tmp_path / "sudo-calls"), "NGINX_RESULTS": str(tmp_path / "nginx-results"),
           "CF_ARGS": str(tmp_path / "cf-args"), **(env_extra or {})}
    script = "set -euo pipefail\n_CLEANUP_FILES=()\n" + _functions("_cleanup") + "\ntrap _cleanup EXIT\n" + body
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)


@pytest.fixture
def site(tmp_path):
    new_site = tmp_path / "sites-available" / "opa-two"
    link = tmp_path / "sites-enabled" / "opa-two"
    backups = tmp_path / "backups"
    for d in (new_site.parent, link.parent, backups):
        d.mkdir()
    new_site.write_text("server { secret }\n")
    link.symlink_to(new_site)
    setup = (f'NEW_SITE="{new_site}" LINK="{link}" B="{backups}" NAME=two APP_USER="$(id -un)" APP_GROUP="$(id -gn)"\n'
             + _functions("_validate_site_or_back_out"))
    return new_site, link, backups, setup


def _results(tmp_path, *codes):
    (tmp_path / "nginx-results").write_text("".join(f"{c}\n" for c in codes))


def test_valid_site_stays_enabled(tmp_path, site):
    new_site, link, _, setup = site
    _results(tmp_path, 0)
    proc = _run(tmp_path, setup + "\nCREATED=1\n_validate_site_or_back_out\necho reached\n")
    assert proc.returncode == 0 and "reached" in proc.stdout
    assert new_site.exists() and link.is_symlink()


def test_a_site_that_breaks_nginx_is_removed_and_kept_as_a_private_copy(tmp_path, site):
    new_site, link, backups, setup = site
    _results(tmp_path, 1, 0)  # fails with the site, passes without it
    proc = _run(tmp_path, setup + "\nCREATED=0\n_validate_site_or_back_out\necho reached\n")
    assert proc.returncode == 1 and "reached" not in proc.stdout
    assert "broken site" in proc.stderr and "was removed" in proc.stdout
    assert not new_site.exists() and not link.is_symlink()
    copy = backups / "opa-two.failed-site"
    assert copy.read_text() == "server { secret }\n"
    assert stat.S_IMODE(copy.stat().st_mode) == 0o600


@pytest.mark.parametrize("created,site_kept", [(1, False), (0, True)])
def test_nginx_broken_for_another_reason(tmp_path, site, created, site_kept):
    new_site, link, _, setup = site
    _results(tmp_path, 1, 1)
    proc = _run(tmp_path, setup + f"\nCREATED={created}\n_validate_site_or_back_out\n")
    assert proc.returncode == 1 and "invalid even without this site" in proc.stdout
    assert new_site.exists() is site_kept
    assert link.is_symlink() is site_kept


def _tunnel(tmp_path, fail):
    staged = tmp_path / "tunnel-token"
    staged.write_text(TOKEN)
    staged.chmod(0o600)
    body = _functions("_install_tunnel_connector") + f'\n_install_tunnel_connector "{staged}"\necho installed\n'
    proc = _run(tmp_path, body, {"CF_FAIL": "1" if fail else "0"})
    return staged, proc


def test_tunnel_token_never_reaches_the_sudo_command_line(tmp_path):
    staged, proc = _tunnel(tmp_path, fail=False)
    assert proc.returncode == 0 and "installed" in proc.stdout
    sudo_lines = (tmp_path / "sudo-calls").read_text()
    assert TOKEN not in sudo_lines and str(staged) in sudo_lines
    assert (tmp_path / "cf-args").read_text().strip() == f"service install {TOKEN}"
    assert not staged.exists()


def test_failed_tunnel_install_is_reported_masked_and_the_token_is_shredded(tmp_path):
    staged, proc = _tunnel(tmp_path, fail=True)
    assert proc.returncode == 1 and "installed" not in proc.stdout
    assert "service install failed" in proc.stdout
    assert TOKEN not in proc.stdout + proc.stderr and "<token>" in proc.stderr
    assert not staged.exists()


@pytest.mark.parametrize("line,allowed", [
    ("EXTRA_ALLOWED_ORIGINS=https://opa.example.com", True),
    ("EXTRA_ALLOWED_ORIGINS=https://a.b,https://opa.example.com,https://c.d", True),
    ("EXTRA_ALLOWED_ORIGINS=https://xopa.example.com", False),
    ("EXTRA_ALLOWED_ORIGINS=https://opa.example.com.evil", False),
    ("EXTRA_ALLOWED_ORIGINS=https://opaXexample.com", False),
    ("#EXTRA_ALLOWED_ORIGINS=https://opa.example.com", False),
])
def test_origin_match_is_a_whole_item(tmp_path, line, allowed):
    envfile = tmp_path / "main.env"
    envfile.write_text(line + "\n")
    body = _functions("_origin_already_allowed") + (
        f'\nif _origin_already_allowed opa.example.com "{envfile}"; then echo yes; else echo no; fi\n')
    proc = _run(tmp_path, body)
    assert proc.stdout.strip() == ("yes" if allowed else "no"), proc.stderr
