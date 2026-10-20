"""GET /api/upgrade/bundle (5.47.0): the failed upgrade's redacted support bundle, downloadable by an app admin
who has no shell on the server. Admin-only, read-only, plain names only."""

import hashlib
import json
import os

import pytest

import create_secret_folders as engine
from test_http_authz_matrix import ADMIN, OWNER_A, _call, _who, matrix_server  # noqa: E402,F401

NAME = "ocw-support-5.46.0-to-5.47.0-20261021T023158Z-k4q9.tar.gz"


@pytest.fixture
def bundles(tmp_path, monkeypatch):
    up = tmp_path / "upgrade"
    (up / "bundles").mkdir(parents=True)
    monkeypatch.setenv("OPA_UPGRADE_DIR", str(up))
    return up


def test_admin_downloads_the_bundle_and_it_is_audited(matrix_server, bundles):
    base_url, _serve = matrix_server
    data = os.urandom(5000)
    (bundles / "bundles" / NAME).write_bytes(data)
    r = _call(base_url, "GET", f"/api/upgrade/bundle?name={NAME}", headers=_who(ADMIN, admin=True))
    assert r.status_code == 200 and r.content == data
    assert r.headers["Content-Type"] == "application/gzip" and NAME in r.headers["Content-Disposition"]
    assert r.headers["Cache-Control"] == "no-store" and r.headers["X-Content-Type-Options"] == "nosniff"
    row = [e for e in engine.read_audit_log(limit=20) if e["action"] == "upgrade.bundle_downloaded"][0]
    assert row["details"]["bundle"] == NAME and row["details"]["sha256"] == hashlib.sha256(data).hexdigest()


def test_non_admin_and_unknown_files_are_refused(matrix_server, bundles):
    base_url, _serve = matrix_server
    (bundles / "bundles" / NAME).write_bytes(b"x")
    assert _call(base_url, "GET", f"/api/upgrade/bundle?name={NAME}", headers=_who(OWNER_A)).status_code == 403
    adm = _who(ADMIN, admin=True)
    for bad in ("../state.json", "..%2Fstate.json", "ocw-support-x.tar.gz/../../etc/passwd", "evil.tar.gz", "", f"{NAME}%00", "a/b.tar.gz"):
        assert _call(base_url, "GET", f"/api/upgrade/bundle?name={bad}", headers=adm).status_code in (400, 404), bad
    assert _call(base_url, "GET", "/api/upgrade/bundle?name=ocw-support-nope.tar.gz", headers=adm).status_code == 404


def test_links_and_oversize_files_are_not_served(matrix_server, bundles, tmp_path):
    base_url, _serve = matrix_server
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    os.symlink(secret, bundles / "bundles" / "ocw-support-link.tar.gz")
    (bundles / "bundles" / "ocw-support-big.tar.gz").write_bytes(b"0" * (7 * 1024 * 1024))
    adm = _who(ADMIN, admin=True)
    assert _call(base_url, "GET", "/api/upgrade/bundle?name=ocw-support-link.tar.gz", headers=adm).status_code == 404
    assert _call(base_url, "GET", "/api/upgrade/bundle?name=ocw-support-big.tar.gz", headers=adm).status_code == 404


def test_status_carries_the_updaters_run_without_paths(matrix_server, bundles):
    base_url, _serve = matrix_server
    assert _call(base_url, "GET", "/api/upgrade/status", headers=_who(ADMIN, admin=True)).json()["upgrade_run"] is None
    (bundles / "state.json").write_text(json.dumps({"correlation_id": "upg-12345678", "result": "rolled_back", "reason_code": "health_healthz",
                                                    "version_from": "5.46.0", "version_to": "5.47.0", "manifest": {"files": {}},
                                                    "backup": {"path": "/var/lib/secret/place"}, "bundle": {"name": NAME, "size": 5, "sha256": "ab"}}))
    run = _call(base_url, "GET", "/api/upgrade/status", headers=_who(ADMIN, admin=True)).json()["upgrade_run"]
    assert run["result"] == "rolled_back" and run["bundle"]["name"] == NAME
    assert "backup" not in run and "manifest" not in run
