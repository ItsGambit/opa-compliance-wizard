"""Covers _atomic_write_json's crash-mid-write safety (external review,
2026-09-30): a reader hitting the file mid-write must never see a
truncated/partial file -- the real exploit shape was access_control.json
read mid-write, JSONDecodeError, silent fallback to the unrestricted
login-bootstrap default."""
import json
import os
import sys
import threading
import time

import create_secret_folders as engine


def test_write_then_read_round_trips(tmp_path):
    path = tmp_path / "data.json"
    engine._atomic_write_json(str(path), {"hello": "world"})
    with open(path, encoding="utf-8") as f:
        assert json.load(f) == {"hello": "world"}


def test_temp_file_created_in_same_directory_as_target(tmp_path, monkeypatch):
    """The atomicity of the final os.replace depends on the temp file
    being on the SAME filesystem as the target -- a cross-filesystem
    rename silently degrades to non-atomic copy+delete."""
    path = tmp_path / "subdir" / "data.json"
    path.parent.mkdir()
    captured = {}
    import tempfile as tempfile_module

    real_mkstemp = tempfile_module.mkstemp

    def spy_mkstemp(*args, **kwargs):
        result = real_mkstemp(*args, **kwargs)
        captured["dir"] = kwargs.get("dir")
        return result

    monkeypatch.setattr(tempfile_module, "mkstemp", spy_mkstemp)
    engine._atomic_write_json(str(path), {"a": 1})
    assert captured["dir"] == str(path.parent)


def test_temp_file_cleaned_up_on_failure(tmp_path, monkeypatch):
    """If os.replace itself raises, the temp file must not be left behind."""
    path = tmp_path / "data.json"
    leaked = {}

    real_replace = os.replace

    def failing_replace(src, dst):
        leaked["temp_path"] = src
        raise OSError("simulated failure")

    monkeypatch.setattr(os, "replace", failing_replace)
    try:
        engine._atomic_write_json(str(path), {"a": 1})
    except OSError:
        pass
    assert "temp_path" in leaked
    assert not os.path.exists(leaked["temp_path"])


def test_concurrent_reader_never_observes_partial_file(tmp_path):
    """The real regression this fix targets: a separate reader process
    (in production, server/auth_gate.py reading access_control.json)
    hitting the file mid-write. Simulated here with a background thread
    reading in a tight loop while the main thread writes repeatedly.

    POSIX-only: confirmed live on this Windows dev machine that
    os.replace() can transiently raise PermissionError (WinError 5) when
    the destination is open for reading by another thread at that exact
    moment -- Windows' rename semantics are weaker than POSIX's here
    (POSIX guarantees os.replace succeeds regardless of concurrent open
    readers; Windows does not). This is a genuine platform difference,
    not a bug in _atomic_write_json or in this test -- and not a
    practical risk for THIS app specifically, since both of its real
    deployment targets (local-run and the hosted Ubuntu server) are
    POSIX. Skipped on Windows rather than weakened, so the real guarantee
    this test protects isn't silently diluted for the platforms that
    matter."""
    if sys.platform.startswith("win"):
        import pytest

        pytest.skip(
            "os.replace() can transiently fail with PermissionError on Windows when the "
            "destination is open for reading elsewhere -- POSIX (this app's real deploy "
            "target) has no such gap. See this test's own docstring."
        )
    path = tmp_path / "data.json"
    engine._atomic_write_json(str(path), {"n": 0})

    errors = []
    stop = threading.Event()

    def reader_loop():
        while not stop.is_set():
            try:
                with open(path, encoding="utf-8") as f:
                    content = f.read()
                if content:
                    json.loads(content)  # must never be partial/truncated
            except (json.JSONDecodeError, FileNotFoundError, OSError) as exc:
                errors.append(exc)

    reader_thread = threading.Thread(target=reader_loop)
    reader_thread.start()
    try:
        for i in range(1, 50):
            engine._atomic_write_json(str(path), {"n": i, "padding": "x" * 500})
    finally:
        stop.set()
        reader_thread.join(timeout=5)

    assert errors == []


def test_permissions_restricted_on_posix(tmp_path):
    if sys.platform.startswith("win"):
        import pytest

        pytest.skip("POSIX chmod bits aren't meaningful on Windows")
    path = tmp_path / "data.json"
    engine._atomic_write_json(str(path), {"a": 1})
    assert oct(os.stat(path).st_mode & 0o777) == oct(0o600)
