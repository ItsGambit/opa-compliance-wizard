"""5.51.0: on Windows the archive inherits its folder's permissions (os.chmod cannot make it owner-only), so the app says in one line
when the data folder is one other users of the computer can read. Paths are checked with Windows rules on any host."""
import pytest

import audit_store
from test_http_authz_matrix import matrix_server  # noqa: F401

ENV = {"PUBLIC": "C:\\Users\\Public", "ProgramData": "C:\\ProgramData"}


@pytest.mark.parametrize("path", [
    "C:\\Users\\Public\\opa", "c:\\users\\public", "C:\\ProgramData", "C:\\ProgramData\\opa\\data", "D:\\", "D:", "\\\\fileserver\\share\\opa",
    "C:\\Users\\Public\\..\\Public\\opa",
])
def test_a_folder_other_users_may_read_gets_one_line_naming_the_fix(path):
    notice = audit_store.shared_location_notice(path, "nt", ENV)
    assert notice and "other users of this computer may read" in notice and "OPA_DATA_DIR" in notice


@pytest.mark.parametrize("path", ["C:\\Users\\someone\\Documents\\opa", "C:\\Users\\someone\\AppData\\Local\\opa", "D:\\data\\opa", "C:\\Users\\PublicRelations\\opa"])
def test_a_folder_inside_a_profile_or_a_data_folder_gets_no_notice(path):
    assert audit_store.shared_location_notice(path, "nt", ENV) is None


def test_other_systems_get_no_notice_and_the_ProgramData_variable_is_honoured():
    assert audit_store.shared_location_notice("/var/lib/opa", "posix", ENV) is None
    assert audit_store.shared_location_notice("D:\\Shared\\opa", "nt", {"ProgramData": "D:\\Shared"})


def test_the_start_up_check_logs_a_warning_and_whoami_carries_the_notice(monkeypatch, tmp_path):
    import create_secret_folders as engine
    lines = []
    monkeypatch.setattr(engine, "log", lambda level, msg: lines.append((level, msg)))
    monkeypatch.setattr(audit_store, "shared_location_notice", lambda *a, **k: "The archive is in a location other users of this computer may read: X.")
    assert audit_store._warn_if_shared_location() and lines and lines[0][0] == "WARN"
    monkeypatch.setattr(audit_store, "shared_location_notice", lambda *a, **k: None)
    assert audit_store._warn_if_shared_location() is None


def test_whoami_says_nothing_on_this_host(matrix_server):
    from test_http_authz_matrix import _call, _who, OWNER_A
    base_url, _serve = matrix_server
    body = _call(base_url, "GET", "/api/whoami", headers=_who(OWNER_A)).json()
    assert body["data_location_notice"] is None
