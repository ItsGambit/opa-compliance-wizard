"""Hardening of the privileged updater against the less-trusted accounts that share its directories (the staging
account and the application account). Real temporary directory trees; ownership itself is asserted on a real host by
tests/integration/updater-vm.sh (these tests do not run as root)."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

import updater_fakes as uf
import ocw_cli
from updater_fakes import act

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def m(tmp_path):
    return uf.Machine(tmp_path)


def cli(m, *argv):
    return ocw_cli.main(list(argv), m.cfg(), m.host)


def staged(m, version="5.47.0", **kw):
    m.build_release(version, **kw)
    m.put_artifacts(version)
    m.host.schema_on_start[version] = 10
    assert m.host.run(["systemctl", "start", f"ocw-stage@{version}.service"])[0] == 0


# --- releases/ is root-only: the tree is moved there BEFORE it is owned and hashed -------------------------------


def test_the_staged_tree_is_moved_into_releases_before_it_is_owned_and_hashed(m):
    staged(m)
    assert (m.opt / "staging" / "5.47.0" / ".staged").exists() and not (m.opt / "releases" / "5.47.0").exists()
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000101")) == "completed"
    in_releases, still_in_staging = m.host.chown_seen
    assert in_releases and not still_in_staging
    assert not (m.opt / "staging" / "5.47.0").exists() and (m.opt / "releases" / "5.47.0" / ".staged").exists()


def test_a_staging_entry_swapped_for_a_link_is_never_followed(m, tmp_path):
    staged(m)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    os.chmod(victim, 0o777)
    os.rename(m.opt / "staging" / "5.47.0", tmp_path / "moved-away")
    os.symlink(victim, m.opt / "staging" / "5.47.0")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000102")) == "failed"
    assert m.read_state()["reason_code"] == "not_staged"
    assert not os.path.lexists(m.opt / "releases" / "5.47.0")
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o777 and (victim / "keep.txt").read_text() == "keep"
    assert os.readlink(m.opt / "current") == "releases/5.46.0"


def test_a_root_owned_leftover_of_an_earlier_attempt_is_replaced_not_trusted(m):
    staged(m)
    left = m.opt / "releases" / "5.47.0"
    (left / "server").mkdir(parents=True)
    (left / "server" / "planted.py").write_text("import os\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000103")) == "completed"
    assert not (m.opt / "releases" / "5.47.0" / "server" / "planted.py").exists()


def test_a_failure_after_the_move_leaves_nothing_the_staging_account_can_reuse(m):
    staged(m)
    (m.opt / "staging" / "5.47.0" / "requirements.lock").write_text("# evil\n")
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000104")) == "failed"
    assert m.read_state()["reason_code"] == "tree_mismatch"
    assert not (m.opt / "staging" / "5.47.0").exists()  # moved: the account cannot touch it any more


def test_prune_removes_stale_staging_directories(m):
    (m.opt / "staging" / "5.40.0").mkdir()
    (m.opt / "staging" / "9.0.0").mkdir()
    m.updater().prune("5.47.0")
    assert not (m.opt / "staging" / "5.40.0").exists() and (m.opt / "staging" / "9.0.0").exists()


def test_status_lists_staged_releases_from_staging(m, capsys):
    staged(m)
    s = ocw_cli.collect_status(m.cfg())
    assert [r["version"] for r in s["staged"]] == ["5.47.0"]


def test_install_sh_makes_releases_root_owned_and_staging_account_owned(tmp_path):
    text = (REPO / "server" / "install.sh").read_text()
    assert 'mkd root:root 0755 "$OPT_DIR/releases"' in text
    assert 'mkd "$UPD_OWNER" 0755 "$OPT_DIR/staging"' in text
    assert 'mkd "$UPD_OWNER" 0755 "$OPT_DIR/releases"' not in text
    unit = (REPO / "server" / "ocw-stage@.service").read_text()
    assert "ReadWritePaths=__OPT_DIR__/staging" in unit and "ReadWritePaths=__OPT_DIR__/releases" not in unit
    assert "StateDirectoryMode=0750" in unit and "CacheDirectoryMode=0750" in unit


# --- an operator's file is handed over through a root-owned directory, never through the staging account's ----------


def test_stage_from_a_file_never_writes_chowns_or_chmods_inside_the_staging_accounts_directories(m, tmp_path, monkeypatch):
    victim = tmp_path / "victim.json"
    victim.write_text("precious")
    evil = tmp_path / "evil"
    evil.mkdir()
    os.symlink(victim, evil / "ocw-5.47.0.tar.gz")
    os.symlink(victim, evil / "ocw-5.47.0.tar.gz.minisig")
    art = m.data / "upgrade" / "artifacts"
    os.symlink(evil, art)
    tar = m.build_release("5.47.0")
    seen = {}

    def fake_stage():
        hand = m.opt / "handoff"
        seen["files"] = sorted(p.name for p in hand.iterdir())
        seen["modes"] = {p.name: stat.S_IMODE(p.stat().st_mode) for p in hand.iterdir()}
        return 0, ""
    m.stage_overrides["5.47.0"] = fake_stage
    touched = []
    real_chown, real_chmod = os.chown, os.chmod
    monkeypatch.setattr(os, "chown", lambda p, *a, **k: touched.append(str(p)) or real_chown(p, *a, **k))
    monkeypatch.setattr(os, "chmod", lambda p, *a, **k: touched.append(str(p)) or real_chmod(p, *a, **k))
    assert cli(m, "stage", str(tar)) == 0
    assert victim.read_text() == "precious"
    assert seen["files"] == ["ocw-5.47.0.tar.gz", "ocw-5.47.0.tar.gz.minisig"] and set(seen["modes"].values()) == {0o640}
    assert not [p for p in touched if str(art) in p or str(evil) in p]
    assert list((m.opt / "handoff").iterdir()) == []  # root cleans up after the stage step


def test_a_planted_file_in_the_handoff_directory_is_replaced_not_followed(m, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.symlink(victim, m.opt / "handoff" / "ocw-5.47.0.tar.gz")
    tar = m.build_release("5.47.0")
    import ocw_cli as c
    c._drop_in_handoff(m.cfg(), str(tar))
    assert victim.read_text() == "precious" and not os.path.islink(m.opt / "handoff" / "ocw-5.47.0.tar.gz")
    assert (m.opt / "handoff" / "ocw-5.47.0.tar.gz").read_bytes() == tar.read_bytes()


def test_the_stage_step_prefers_the_handoff_copy_over_a_stale_one_it_owns(tmp_path, monkeypatch):
    from server.updater import stage as stagemod
    opt = tmp_path / "opt"
    (opt / "handoff").mkdir(parents=True)
    art = tmp_path / "art"
    art.mkdir()
    for n in ("ocw-1.2.3.tar.gz", "ocw-1.2.3.tar.gz.minisig"):
        (art / n).write_text("stale")
        (opt / "handoff" / n).write_text("fresh")
    monkeypatch.setenv("OCW_OPT_DIR", str(opt))
    assert stagemod._adopt_handoff(opt, art, "1.2.3") is True
    assert (art / "ocw-1.2.3.tar.gz").read_text() == "fresh"


def test_venv_paths_are_rewritten_for_the_final_location(tmp_path):
    from server.updater import stage as stagemod
    venv = tmp_path / "staging" / "1.2.3" / ".venv"
    (venv / "bin").mkdir(parents=True)
    old = str(tmp_path / "staging" / "1.2.3")
    (venv / "bin" / "gunicorn").write_text(f"#!{old}/.venv/bin/python\nimport sys\n")
    (venv / "bin" / "gunicorn").chmod(0o755)
    os.symlink("/usr/bin/python3", venv / "bin" / "python")
    stagemod._relocate_venv(venv, old, str(tmp_path / "releases" / "1.2.3"))
    assert (venv / "bin" / "gunicorn").read_text().startswith(f"#!{tmp_path}/releases/1.2.3/.venv/bin/python")
    assert os.access(venv / "bin" / "gunicorn", os.X_OK) and os.path.islink(venv / "bin" / "python")


# --- safe opens: links and pipes in directories another account owns ---------------------------------------------


def test_read_json_does_not_follow_links_or_block_on_pipes(tmp_path):
    real = tmp_path / "real.json"
    real.write_text('{"a": 1}')
    os.symlink(real, tmp_path / "link.json")
    os.mkfifo(tmp_path / "pipe.json")
    assert act.read_json(str(real)) == {"a": 1}
    assert act.read_json(str(tmp_path / "link.json"), "dflt") == "dflt"
    assert act.read_json(str(tmp_path / "pipe.json"), "dflt") == "dflt"
    assert act.read_json(str(tmp_path), "dflt") == "dflt"


# --- trust apply no longer copies into the application's directory -------------------------------------------------


def test_trust_apply_writes_nothing_through_a_link_planted_in_the_application_directory(m, tmp_path, capsys):
    from release_helpers import make_revocation, revocation_payload
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    revdir = m.data / "upgrade" / "revocations"
    revdir.mkdir(parents=True)
    os.symlink(victim, revdir / "1.json")
    k2, sb2 = uf.TestKey(), uf.TestStandby()
    payload = revocation_payload(1, revoke=[m.primary.key_id, m.standby.key_id], add_keys=[k2, sb2])
    rev = make_revocation(tmp_path / "revocation.json", [m.standby], payload)
    assert cli(m, "trust", "apply", str(rev)) == 0
    assert victim.read_text() == "precious"
    assert [p.name for p in revdir.iterdir()] == ["1.json"] and os.path.islink(revdir / "1.json")


# --- revocation: tool output, per-serial source ------------------------------------------------------------------


def _revoke_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("revoke_tool", REPO / "tools" / "revoke.py")
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(REPO / "tools"))
    spec.loader.exec_module(mod)
    return mod


def test_revoke_tool_pins_known_good_releases_by_digest_and_a_bare_revoke_is_allowed():
    from release_helpers import TestKey, TestStandby, key_list
    from server.updater import keys as keylib
    p, sb = TestKey(), TestStandby()
    eff = keylib.effective_from(keylib.validate_key_list(key_list([p, sb])))
    tool = _revoke_tool()
    assert tool.parse_revoke(p.key_id, eff) == p.key_id
    sha = "ab" * 32
    assert tool.parse_revoke(p.key_id, eff, [f"{p.key_id}:5.46.0:{sha}"]) == {"key_id": p.key_id, "known_good": {"5.46.0": sha}}
    for bad in (f"{p.key_id}:5.46.0:XYZ", f"{p.key_id}:nonsense:{sha}"):
        with pytest.raises(Exception):
            tool.parse_revoke(p.key_id, eff, [bad])


def test_a_per_serial_revocation_location_is_polled_next_to_the_fixed_one(monkeypatch):
    from server.updater import service
    monkeypatch.delenv("OPA_REVOCATION_URL", raising=False)
    monkeypatch.delenv("OPA_REVOCATION_URL_BASE", raising=False)
    names = dict(service.revocation_sources(2))
    assert names["release_assets_next"].endswith("/releases/download/revocation-3/revocation.json")
    assert names["release_assets"].endswith("/releases/download/revocation/revocation.json")
    assert "release_assets_next" not in dict(service.revocation_sources())


# --- nginx: skip when absent, and a failing `nginx -t` that fails on the restored site too is not the release's fault ---


def test_a_missing_nginx_site_skips_the_nginx_step_and_the_upgrade_completes(m):
    os.unlink(m.site)
    m.build_release("5.47.0", nginx_changed=True)
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000201")) == "completed"
    assert not m.site.exists() and m.host.reloads == 0
    assert any(e["details"].get("step") == "nginx_skipped" for e in m.audit_actions() if e["action"] == "upgrade.step")


def test_nginx_t_failing_on_the_restored_site_too_is_an_internal_error_and_blames_no_version(m):
    m.host.nginx_t_results = [1, 1]  # the new site fails, and so does the restored original: the test itself cannot run
    m.build_release("5.47.0", nginx_changed=True)
    m.put_artifacts("5.47.0")
    m.host.schema_on_start["5.47.0"] = 10
    assert m.updater().apply(m.request("5.47.0", correlation_id="upg-00000202")) == "rolled_back"
    assert m.read_state()["reason_code"] == "internal_error"
    assert not (act.read_json(m.cfg().failures_path, {}) or {}).get("versions")


def test_the_manifest_flag_is_a_real_comparison_with_the_previous_tag(tmp_path):
    tool = _release_tool()
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "server").mkdir()
    (repo / "server" / "nginx-opa-secrets-wizard.conf").write_text("a\n")
    run("add", "-A")
    run("commit", "-q", "-m", "one")
    run("tag", "v1.0.0")
    same = {"server/nginx-opa-secrets-wizard.conf": (0o644, b"a\n")}
    other = {"server/nginx-opa-secrets-wizard.conf": (0o644, b"b\n")}
    assert tool._nginx_template_changed(repo, same, "1.1.0") is False
    assert tool._nginx_template_changed(repo, other, "1.1.0") is True
    assert tool._nginx_template_changed(repo, other, "1.0.0") is True  # no earlier tag: nothing to compare with


def _release_tool():
    import importlib.util
    import sys
    sys.path.insert(0, str(REPO / "tools"))
    spec = importlib.util.spec_from_file_location("release_tool", REPO / "tools" / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_root_unit_can_run_nginx_t(tmp_path):
    unit = (REPO / "server" / "ocw-upgrade.service").read_text()
    rw = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
    assert " /run" in rw and "/var/log/nginx" in rw
    caps = next(line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet="))
    assert "CAP_NET_BIND_SERVICE" in caps and "CAP_KILL" in caps
    assert "python3 -I -B " in unit
