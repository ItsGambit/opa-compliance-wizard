"""get-ocw.sh in the release tooling: tools/release.py renders it from the tagged template, verifier and key list, lists its
sha256 in the manifest, signs it (a second signature: four KMS Sign calls per release) and re-renders it to check it.
tools/render_bootstrap.py is pure, so the embedded verifier is also compared with its source byte for byte against the REAL
repository files here. Test keys only; no cloud."""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from release_helpers import TestKey, TestStandby, key_list
from server.updater import keys as keylib

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import render_bootstrap as rb  # noqa: E402

SHELLCHECK = shutil.which("shellcheck") or str(Path(sys.executable).parent / "shellcheck")


def load_tool():
    spec = importlib.util.spec_from_file_location("tool_release_bootstrap", REPO / "tools" / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def real_files():
    files = {rb.TEMPLATE_PATH: (REPO / rb.TEMPLATE_PATH).read_bytes()}
    for _name, path in rb.EMBEDDED:
        files[path] = (REPO / path).read_bytes()
    return files


class RecordingBackend:
    """Signs like the KMS backend (two raw signatures per file) and counts the calls."""

    def __new__(cls, key):
        tool = load_tool()

        class Backend(tool.RawSignerBackend):
            def __init__(self):
                self.key_id = key.key_id
                self.calls = 0
                self.request_ids = []

            def sign_raw(self, message):
                self.calls += 1
                return key.sign_raw(message)
        return Backend()


def test_the_embedded_verifier_is_the_source_byte_for_byte():
    files = real_files()
    script = rb.render("5.52.0", files)
    copies = rb.embedded_copies(script)
    assert set(copies) == {name for name, _ in rb.EMBEDDED}
    for name, path in rb.EMBEDDED:
        assert copies[name] == files[path], f"{name} in get-ocw.sh differs from {path}"
    assert rb.bootstrap_version(script) == "5.52.0"
    assert script == rb.render("5.52.0", files)  # deterministic
    assert b"@@" not in script.split(b"write_verifier() {")[0] and b"@@VERSION@@" not in script and b"@@EMBEDDED" not in script


def test_the_rendered_script_parses_and_is_shellcheck_clean(tmp_path):
    script = tmp_path / "get-ocw.sh"
    script.write_bytes(rb.render("5.52.0", real_files()))
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
    if not os.path.exists(SHELLCHECK):
        pytest.skip("shellcheck is not installed (CI runs it)")
    p = subprocess.run([SHELLCHECK, "--severity=warning", str(script)], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout


def test_the_script_is_safe_if_piped_truncated_and_runs_only_main_last(tmp_path):
    script = rb.render("5.52.0", real_files()).decode()
    assert script.rstrip("\n").endswith('main "$@"')
    assert script.count('\nmain "$@"') == 1
    # a copy cut anywhere before the last line does nothing: nothing outside a function runs commands that act
    for cut in (len(script) // 3, len(script) // 2, script.index("\nmain() {") + 20):
        cut_script = tmp_path / "cut.sh"
        cut_script.write_text(script[:cut])
        p = subprocess.run(["bash", str(cut_script)], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
        assert p.stdout == "" and "get-ocw.sh" not in p.stdout   # no banner, no work: bash stops at the syntax error
        assert p.returncode != 0


def test_render_refuses_unusable_inputs():
    files = real_files()
    with pytest.raises(rb.RenderError):
        rb.render("5.5", files)
    bad = dict(files, **{"server/updater/root/ocw_crypto.py": b"no newline at the end"})
    with pytest.raises(rb.RenderError, match="newline"):
        rb.render("5.52.0", bad)
    sneaky = dict(files, **{"server/updater/root/ocw_crypto.py": b"x\nOCW_EMBEDDED_ocw_crypto_py\nrm -rf /\n"})
    with pytest.raises(rb.RenderError, match="delimiter"):
        rb.render("5.52.0", sneaky)
    crlf = dict(files, **{"server/updater/root/ocw_trust.py": b"x\r\n"})
    with pytest.raises(rb.RenderError, match="carriage"):
        rb.render("5.52.0", crlf)
    with pytest.raises(rb.RenderError, match="missing"):
        rb.render("5.52.0", {k: v for k, v in files.items() if k != "server/release_keys.json"})


def test_the_key_summary_names_the_active_keys_for_the_version_command():
    key, standby = TestKey(), TestStandby()
    summary = rb.key_summary((json.dumps(key_list([key, standby, TestKey(status="retired")])) + "\n").encode())
    assert summary == f"{key.key_id} (release), {standby.key_id} (standby)"


@pytest.fixture
def tagged(tmp_path):
    repo = tmp_path / "repo"
    (repo / "server" / "updater" / "root").mkdir(parents=True)
    (repo / "frontend").mkdir()
    key, standby = TestKey(), TestStandby()
    (repo / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.52.0"\n')
    (repo / "server" / "release_keys.json").write_text(json.dumps(key_list([key, standby])) + "\n")
    for _name, path in rb.EMBEDDED:
        if path != "server/release_keys.json":
            shutil.copy(REPO / path, repo / path)
    shutil.copy(REPO / rb.TEMPLATE_PATH, repo / rb.TEMPLATE_PATH)
    (repo / "frontend" / "package-lock.json").write_text("{}")
    (repo / "CHANGELOG.md").write_text("5.52.0 — **Thing**\nSummary line.\n- **Added.** detail\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"], ["tag", "v5.52.0"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("built")
    return repo, dist, key, standby


def build(tool, tagged, out):
    repo, dist, _k, _s = tagged
    return tool.build_release("5.52.0", repo, out, dist, built_at="2026-05-01T00:00:00Z")


def test_build_renders_get_ocw_sh_and_lists_its_hash(tagged, tmp_path):
    tool = load_tool()
    tar, manifest = build(tool, tagged, tmp_path / "o1")
    script = (tmp_path / "o1" / "get-ocw.sh")
    assert script.is_file() and manifest["bootstrap_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
    tar2, manifest2 = build(tool, tagged, tmp_path / "o2")
    assert (tmp_path / "o2" / "get-ocw.sh").read_bytes() == script.read_bytes() and manifest2 == manifest and tar.read_bytes() == tar2.read_bytes()
    assert tool.check_bootstrap_against_release(tar, script) == "5.52.0"
    # the script carries the key list of THIS tag, not the repository's real one
    key = tagged[2]
    assert key.key_id.encode() in script.read_bytes()


def test_a_tree_without_the_template_still_builds_and_has_no_bootstrap(tmp_path):
    tool = load_tool()
    repo = tmp_path / "repo"
    (repo / "server").mkdir(parents=True)
    (repo / "create_secret_folders.py").write_text('SCRIPT_VERSION = "5.50.0"\n')
    (repo / "server" / "release_keys.json").write_text(json.dumps(key_list()))
    (repo / "CHANGELOG.md").write_text("5.50.0 — **Thing**\nSummary.\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"], ["tag", "v5.50.0"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("x")
    _tar, manifest = tool.build_release("5.50.0", repo, tmp_path / "o", dist)
    assert manifest["bootstrap_sha256"] is None and not (tmp_path / "o" / "get-ocw.sh").exists()


def test_sign_makes_four_kms_calls_and_the_bootstrap_signature_verifies(tagged, tmp_path):
    tool = load_tool()
    repo, _dist, key, standby = tagged
    tar, manifest = build(tool, tagged, tmp_path / "o")
    script = tmp_path / "o" / "get-ocw.sh"
    keys_path = repo / "server" / "release_keys.json"
    backend = RecordingBackend(key)
    tool.sign_release_file(tar, backend, keys_path)
    boot_sig, version = tool.sign_bootstrap_file(script, tar, backend, keys_path)
    assert backend.calls == 4 and version == "5.52.0"
    text = boot_sig.read_text()
    sha = hashlib.sha256(script.read_bytes()).hexdigest()
    assert f"trusted comment: file=get-ocw.sh version=5.52.0 sha256={sha}\n" in text
    eff = keylib.effective_from(keylib.load_key_list(keys_path))
    fields, sig = tool.verify_bootstrap_signature(script, boot_sig, eff)
    assert fields["version"] == "5.52.0" and sig.key_id == key.key_id


def test_a_script_that_is_not_what_the_release_renders_is_never_signed(tagged, tmp_path):
    tool = load_tool()
    repo, _dist, key, _s = tagged
    tar, _m = build(tool, tagged, tmp_path / "o")
    script = tmp_path / "o" / "get-ocw.sh"
    script.write_bytes(script.read_bytes() + b"echo hacked\n")
    backend = RecordingBackend(key)
    with pytest.raises(tool.ReleaseError, match="not what this release renders"):
        tool.sign_bootstrap_file(script, tar, backend, repo / "server" / "release_keys.json")
    assert backend.calls == 0 and not Path(str(script) + ".minisig").exists()


def test_a_bootstrap_signature_made_with_an_unpinned_key_is_removed(tagged, tmp_path):
    tool = load_tool()
    repo, _dist, _key, _s = tagged
    tar, _m = build(tool, tagged, tmp_path / "o")
    script = tmp_path / "o" / "get-ocw.sh"
    with pytest.raises(tool.ReleaseError, match="does NOT verify"):
        tool.sign_bootstrap_file(script, tar, RecordingBackend(TestKey()), repo / "server" / "release_keys.json")
    assert not Path(str(script) + ".minisig").exists()


def test_verify_re_renders_from_the_tarball_and_checks_the_signature(tagged, tmp_path, capsys):
    tool = load_tool()
    repo, _dist, key, _s = tagged
    tar, _m = build(tool, tagged, tmp_path / "o")
    script = tmp_path / "o" / "get-ocw.sh"
    keys_path = repo / "server" / "release_keys.json"
    backend = RecordingBackend(key)
    sig, _info = tool.sign_release_file(tar, backend, keys_path)
    boot_sig, _v = tool.sign_bootstrap_file(script, tar, backend, keys_path)
    argv = ["verify", str(tar), str(sig), "--keys", str(keys_path), "--installed-version", "5.51.0", "--bootstrap", str(script),
            "--bootstrap-sig", str(boot_sig)]
    assert tool.main(argv) == 0
    out = capsys.readouterr().out
    assert "is exactly what release 5.52.0 renders" in out and "signature valid" in out
    # tampered after signing: the re-render comparison and the signature both refuse it
    script.write_bytes(script.read_bytes().replace(b"main \"$@\"", b"main \"$@\" # x"))
    assert tool.main(argv) == 1
    assert "not what this release renders" in capsys.readouterr().err
    # a signature for a different file name is refused
    other = tmp_path / "o" / "other.sh"
    other.write_bytes(b"#!/bin/bash\n")
    with pytest.raises(Exception):
        tool.verify_bootstrap_signature(other, boot_sig, keylib.effective_from(keylib.load_key_list(keys_path)))


def test_the_manifest_and_the_notes_carry_the_evidence_verifier_sha256(tagged, tmp_path):
    tool = load_tool()
    repo, dist, _k, _s = tagged
    verifier = repo / "tools" / "verify_evidence_package.py"
    verifier.parent.mkdir(exist_ok=True)
    verifier.write_bytes((REPO / "tools" / "verify_evidence_package.py").read_bytes())
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    for cmd in (["add", "."], ["commit", "-q", "-m", "verifier"], ["tag", "-f", "v5.52.0"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env, capture_output=True)
    _tar, manifest = tool.build_release("5.52.0", repo, tmp_path / "o", dist, built_at="2026-05-01T00:00:00Z")
    want = hashlib.sha256(verifier.read_bytes()).hexdigest()
    assert manifest["verifier_sha256"] == want == manifest["files"]["tools/verify_evidence_package.py"]
    assert tool.verifier_notes_line(want) in manifest["changelog_excerpt"]
    assert json.loads((tmp_path / "o" / "manifest.json").read_text())["verifier_sha256"] == want


def test_a_tree_without_the_verifier_has_no_verifier_sha256(tagged, tmp_path):
    tool = load_tool()
    _tar, manifest = build(tool, tagged, tmp_path / "o")
    assert manifest["verifier_sha256"] is None and "verifier" not in manifest["changelog_excerpt"]
