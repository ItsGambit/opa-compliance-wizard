"""5.51.0: every updater refusal says what happened, whether anything changed on the server, and what to do, in the updater's own state
(reason_text, changed, next_step) so the command line and the Updates page print the same words. The former tree_mismatch is split:
release_files_mismatch (the prepared files do not match the signed release) and environment_unexpected (the Python environment has
something the updater does not expect). Real temporary trees; nothing here runs as root."""
import json
import os
import re
import tarfile
from pathlib import Path

import pytest

import updater_fakes as uf
import ocw_cli
from updater_fakes import act
from test_updater_hardening import staged

REPO = Path(__file__).resolve().parent.parent
FORBIDDEN = re.compile(r"tamper|attack|malicious|security", re.I)


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def _checked(m):
    """A staged, fully valid tree plus the updater and manifest that check it."""
    staged(m)
    root = m.opt / "staging" / "5.47.0"
    manifest = json.loads(tarfile.open(m.releases_dir / "ocw-5.47.0.tar.gz").extractfile("manifest.json").read())
    up = m.updater()
    up.check_tree(str(root), manifest)  # valid as built
    return up, root, manifest


def _code(up, root, manifest):
    with pytest.raises(act.StepFailed) as e:
        up.check_tree(str(root), manifest)
    return e.value.code, str(e.value)


# -- every raise site maps to the intended code ------------------------------------------------------------------------
def test_a_file_that_differs_is_release_files_mismatch(m):
    up, root, manifest = _checked(m)
    (root / "requirements.lock").write_text("# changed\n")
    assert _code(up, root, manifest)[0] == "release_files_mismatch"


def test_a_missing_file_is_release_files_mismatch(m):
    up, root, manifest = _checked(m)
    os.unlink(root / "requirements.lock")
    code, text = _code(up, root, manifest)
    assert code == "release_files_mismatch" and "missing" in text


def test_an_extra_file_is_release_files_mismatch_with_its_own_message(m):
    up, root, manifest = _checked(m)
    (root / "server" / "planted.py").write_text("x = 1\n")
    code, text = _code(up, root, manifest)
    assert code == "release_files_mismatch" and "server/planted.py is not part of the signed release" in text


def test_a_group_writable_file_is_environment_unexpected(m):
    up, root, manifest = _checked(m)
    os.chmod(root / "requirements.lock", 0o664)
    assert _code(up, root, manifest)[0] == "environment_unexpected"


def test_a_setuid_directory_is_environment_unexpected(m):
    up, root, manifest = _checked(m)
    os.chmod(root / "server", 0o4755)
    assert _code(up, root, manifest)[0] == "environment_unexpected"


def test_a_link_in_the_release_is_environment_unexpected(m):
    up, root, manifest = _checked(m)
    os.symlink("/etc", root / "server" / "link")
    assert _code(up, root, manifest)[0] == "environment_unexpected"


def test_a_hard_linked_file_is_environment_unexpected(m, tmp_path):
    up, root, manifest = _checked(m)
    os.link(root / "requirements.lock", tmp_path / "second-name")
    assert _code(up, root, manifest)[0] == "environment_unexpected"


@pytest.mark.parametrize("shape,build,needle", [
    ("the .venv is a link", lambda root, tmp: (__import__("shutil").move(str(root / ".venv"), str(tmp / "realvenv")), os.symlink(tmp / "realvenv", root / ".venv")), ".venv is a link"),
    ("a link that leaves the release", lambda root, tmp: os.symlink("/etc", root / ".venv" / "lib-evil"), "leaves the release"),
    ("a group-writable file", lambda root, tmp: (open(root / ".venv" / "x.py", "w").close(), os.chmod(root / ".venv" / "x.py", 0o664)), "writable by others"),
    ("a setuid file", lambda root, tmp: (open(root / ".venv" / "y.py", "w").close(), os.chmod(root / ".venv" / "y.py", 0o4755)), "setuid"),
    ("a world-writable directory", lambda root, tmp: (os.mkdir(root / ".venv" / "d"), os.chmod(root / ".venv" / "d", 0o777)), "writable by others"),
    ("a hard link", lambda root, tmp: (open(root / ".venv" / "z.py", "w").close(), os.link(root / ".venv" / "z.py", tmp / "z-other")), "more than one hard link"),
    ("a named pipe", lambda root, tmp: os.mkfifo(root / ".venv" / "pipe"), "not a plain file"),
])
def test_every_virtualenv_shape_is_environment_unexpected(m, tmp_path, shape, build, needle):
    up, root, manifest = _checked(m)
    (root / ".venv").mkdir(exist_ok=True)
    build(root, tmp_path)
    code, text = _code(up, root, manifest)
    assert code == "environment_unexpected" and needle in text, shape


def test_a_failed_ownership_change_is_environment_unexpected(m, monkeypatch):
    staged(m)
    monkeypatch.setattr(m.host, "chown_tree", lambda root: (_ for _ in ()).throw(act.ocw_host.HostError("could not change ownership")))
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000501")) == "failed"
    assert m.read_state()["reason_code"] == "environment_unexpected"


# -- the words are written into the run's state ------------------------------------------------------------------------
def test_a_refusal_records_what_happened_whether_anything_changed_and_what_to_do(m):
    staged(m)
    (m.opt / "staging" / "5.47.0" / "requirements.lock").write_text("# changed\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000502")) == "failed"
    st = m.read_state()
    assert st["reason_code"] == "release_files_mismatch"
    assert st["reason_text"].startswith("The prepared files do not match the signed release")
    assert st["changed"] == act.CHANGED_NONE == "Nothing was changed on the server."
    assert "Download the release again" in st["next_step"]
    hist = [json.loads(line) for line in open(m.cfg().history_path) if line.strip()][-1]
    assert hist["reason_text"] == st["reason_text"] and hist["changed"] == st["changed"] and hist["next_step"] == st["next_step"]


def test_the_environment_message_is_calm_and_names_the_installer_step(m):
    text, changed, step = act.describe_reason("environment_unexpected")
    assert not FORBIDDEN.search(text + step) and changed == act.CHANGED_NONE
    assert "From the unpacked release folder, run `sudo server/install.sh --refresh-updater`" in step
    assert "Python environment" in text


def test_changed_follows_what_the_run_did_not_the_code():
    assert act.describe_reason("migration_failed", "rolled_back")[1] == "The previous release was put back and is running."
    assert act.describe_reason("health_healthz", "rolled_back")[1] == act.CHANGED_BACK
    assert act.describe_reason("signature_invalid", "failed")[1] == act.CHANGED_NONE
    assert act.describe_reason("internal_error", "failed")[1] == act.CHANGED_NONE      # a failure before the switch changed nothing
    assert act.describe_reason("internal_error", "rolled_back")[1] == act.CHANGED_BACK  # after the switch the previous release was put back
    assert act.describe_reason("rollback_failed", "failed_needs_operator")[1] == "Unknown: an operator must check the server."
    assert act.describe_reason("needs_operator")[1] == act.CHANGED_UNKNOWN
    assert {act.CHANGED_NONE, act.CHANGED_BACK, act.CHANGED_UNKNOWN} == {
        "Nothing was changed on the server.", "The previous release was put back and is running.", "Unknown: an operator must check the server."}


def test_health_reasons_read_in_plain_words_and_disk_space_carries_the_numbers():
    text, _c, step = act.describe_reason("health_healthz", "rolled_back")
    assert "the web page did not load" in text and "health_healthz" not in text
    assert "Download the support bundle (Audit Log, the upgrade.failed entry)" in step
    detail = "not enough free disk space (code volume 12 MB free, needs 300 MB; data volume 5 MB free, needs 400 MB)"
    assert "(code volume 12 MB free, needs 300 MB; data volume 5 MB free, needs 400 MB)" in act.describe_reason("disk_space", "failed", detail)[0]
    assert "5.50.0" in act.describe_reason("version_not_newer", "failed", None, "5.50.0")[0]


def test_every_reason_code_has_all_three_plain_sentences_and_no_alarm_words():
    for code in sorted(act.REASONS):
        text, changed, step = act.describe_reason(code)
        assert text and step and changed, code
        assert code in act.REASON_TEXT, f"{code} fell through to the generic message"
        assert not FORBIDDEN.search(text + " " + step), code
        assert "_" not in code or code not in text, f"{code}: the raw code is not an explanation"
    assert "tree_mismatch" in act.REASONS  # old state files and history rows still validate


def test_support_bundle_and_issue_wording_is_the_same_everywhere():
    bundle_rows = [c for c, (_t, s) in act.REASON_TEXT.items() if "support bundle" in s]
    assert bundle_rows
    for code in bundle_rows:
        assert act.BUNDLE_STEP in act.REASON_TEXT[code][1] or "with the support bundle" in act.REASON_TEXT[code][1], code
    for _c, (t, s) in act.REASON_TEXT.items():
        assert "contact the maintainers" not in (t + s).lower()


def test_every_command_in_a_next_step_exists():
    parser = ocw_cli.build_parser()
    subcommands = set(next(a for a in parser._actions if getattr(a, "choices", None)).choices)
    installer = (REPO / "server" / "install.sh").read_text()
    seen = 0
    for code, (_t, step) in act.REASON_TEXT.items():
        for command in re.findall(r"`([^`]+)`", step):
            seen += 1
            assert command.split()[0] == "sudo", f"{code}: `{command}` needs root and says so"
            argv = command.split()[1:]
            if argv[0] == "ocw-updater":
                assert argv[1] in subcommands, f"{code}: `{command}` is not an ocw-updater command"
            else:
                assert argv[0] == "server/install.sh" and all(a in installer for a in argv[1:]), f"{code}: `{command}`"
            assert any(command == c or command.startswith(c) for c in [x.replace("sudo ", "sudo ", 1) for x in act.NEXT_STEP_COMMANDS]), command
    assert seen >= 10


# -- the command line prints the same words ------------------------------------------------------------------------------
def _cfg(tmp_path):
    return uf.Machine(tmp_path).cfg()


def test_the_refusal_line_prints_what_happened_what_to_do_and_the_code(m, capsys):
    staged(m)
    (m.opt / "staging" / "5.47.0" / "requirements.lock").write_text("# changed\n")
    m.updater().apply(m.request("5.47.0", correlation_id="upg-00000503"))
    st = m.read_state()
    ocw_cli.finish_report(type("A", (), {"json": False})(), m.cfg(), st)
    out = capsys.readouterr().out
    assert "Refused before anything was switched: The prepared files do not match the signed release" in out
    assert "Next: Download the release again" in out and "(reason code release_files_mismatch)" in out


def test_an_earlier_releases_state_still_prints(m, capsys):
    ocw_cli.finish_report(type("A", (), {"json": False})(), m.cfg(), {"result": "failed", "reason_code": "tree_mismatch", "error": "x does not match", "correlation_id": "upg-1"})
    assert "failed before anything was switched: tree_mismatch" in capsys.readouterr().out


def test_status_prints_the_last_runs_words(m, capsys):
    staged(m)
    (m.opt / "staging" / "5.47.0" / "requirements.lock").write_text("# changed\n")
    m.updater().apply(m.request("5.47.0", correlation_id="upg-00000504"))
    assert ocw_cli.main(["status"], m.cfg(), m.host) is not None
    out = capsys.readouterr().out
    assert "[release_files_mismatch]" in out and "Nothing was changed on the server." in out and "Next: Download the release again" in out


def test_a_rejected_request_carries_the_plain_words_too(m):
    up = m.updater()
    act.reject(up, "upg-00000505", "request_replayed", "this approval was already used")
    rej = json.loads(open(os.path.join(m.cfg().rejections, "upg-00000505.json")).read())
    assert rej["reason_text"] == "This approval was already used." and rej["changed"] == act.CHANGED_NONE and "Request the upgrade again" in rej["next_step"]


def test_the_web_pages_list_of_reason_codes_is_exactly_the_updaters_set():
    """frontend/src/utils/upgradeFlow.ts UPDATER_REASON_CODES (which its test iterates for a non-generic sentence) must not drift from REASONS."""
    text = (REPO / "frontend" / "src" / "utils" / "upgradeFlow.ts").read_text(encoding="utf-8")
    block = text[text.index("export const UPDATER_REASON_CODES = ["):]
    block = block[:block.index("] as const")]
    listed = set(re.findall(r"'([a-z_]+)'", block))
    assert listed == act.REASONS, (sorted(listed ^ act.REASONS))
