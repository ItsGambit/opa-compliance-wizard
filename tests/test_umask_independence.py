"""The root updater's files must get the mode it intends whatever umask root runs under (CIS-hardened servers use 077 or 027):
a file created with os.open(..., mode) is masked by the umask unless it is fchmod'ed."""

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT_DIR = str(Path(__file__).resolve().parent.parent / "server" / "updater" / "root")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import ocw_activate as act  # noqa: E402


@pytest.fixture
def strict_umask():
    old = os.umask(0o077)
    yield
    os.umask(old)


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o755, 0o600])
def test_safe_copy_gives_the_intended_mode_under_umask_077(tmp_path, strict_umask, mode):
    src = tmp_path / "src"
    src.write_text("x")
    dst = tmp_path / "dst"
    act.safe_copy(str(src), str(dst), mode)
    assert stat.S_IMODE(dst.stat().st_mode) == mode


def test_the_handoff_copy_is_readable_by_the_staging_group_under_umask_077(tmp_path, strict_umask):
    # what `ocw-updater stage <file>` does for each file: mode 0640, group = the staging account's
    src = tmp_path / "ocw-1.0.0.tar.gz"
    src.write_text("x")
    dst = tmp_path / "handoff-copy"
    act.safe_copy(str(src), str(dst), 0o640, None, None)
    assert stat.S_IMODE(dst.stat().st_mode) & 0o040


def test_every_root_open_with_a_public_mode_is_followed_by_an_fchmod_or_chmod():
    """A guard for the next one: an os.open(..., 0o6xx/0o7xx) in the root updater with a group/world-readable mode must be followed
    (within a few lines) by fchmod/chmod, otherwise a strict umask silently changes it."""
    import re
    offenders = []
    for f in Path(ROOT_DIR).glob("*.py"):
        lines = f.read_text().splitlines()
        for i, line in enumerate(lines):
            literal = re.search(r"\b0o([0-7]{3})\b", line)
            if "os.open(" in line and "O_CREAT" in line and literal and int(literal.group(1), 8) & 0o077:
                if not any("chmod" in nxt for nxt in lines[i:i + 8]):
                    offenders.append(f"{f.name}:{i + 1}")
    assert not offenders, offenders
