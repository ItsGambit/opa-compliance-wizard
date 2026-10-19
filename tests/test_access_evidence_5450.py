"""5.45.0: the Access Explorer's access-evidence layer (archive first, live
top-up), server-account events, and the model fixes behind it. Names, ids
and projects are all placeholders."""
from datetime import datetime, timedelta, timezone

import pytest

import audit_store
import create_secret_folders as engine
from test_review_batch4_engine import ModelClient

ENV = "33333333-3333-3333-3333-333333333333"
OTHER_ENV = "44444444-4444-4444-4444-444444444444"
ACTOR = "00uUSER"
NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
REVEAL = "pam.service_account.password.reveal"
CHECKOUT = "pam.resource.checkout"


def _ts(days_ago=0.0, hours_ago=0.0):
    return (NOW - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(uuid, published, event_type=REVEAL, target_id="acct-1", actor=ACTOR, debug=None, targets=None, outcome="SUCCESS"):
    return {
        "uuid": uuid, "eventType": event_type, "published": published,
        "actor": {"id": actor, "alternateId": "user@example.com"}, "outcome": {"result": outcome},
        "debugContext": {"debugData": dict({"requestId": "req-" + uuid}, **(debug or {}))},
        "target": targets if targets is not None else [
            {"id": target_id, "type": "Service Account", "displayName": "example-account"},
            {"id": "team-1", "type": "Team", "displayName": "Example Team"}],
    }


class FakeOkta:
    def __init__(self, events=(), complete=True, error=None):
        self.events, self.complete, self.error, self.calls = list(events), complete, error, []

    def get_system_log(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.events, self.complete


def _archive(env, events, scope="curated", completed=True, watermark=None):
    """Writes events and a sync_state row the way a finished sync leaves them."""
    audit_store.run_migrations()
    conn = audit_store._get_connection()
    rows = [audit_store._normalize_live_event(e) for e in events]
    audit_store._insert_rows(conn, env, rows, "all")
    newest = max([e["published"] for e in events] + [watermark or ""])
    audit_store._upsert_sync_state(
        conn, env, last_synced_at=watermark or newest, ingestion_scope=scope,
        last_sync_completed_at=_ts(0, 1) if completed else None)


def _lookup(client, requests, env=ENV, use_archive=True):
    return engine.find_access_evidence(client, ACTOR, requests, environment_id=env, use_archive=use_archive, now=NOW)


SAAS = [{"resource_kind": "individual_managed_saas_app_account", "resource_id": "acct-1"}]


def test_archive_and_live_agree_and_the_same_event_counts_once(tmp_audit_store, tmp_environments_file):
    ev = _event("e1", _ts(2))
    _archive(ENV, [ev, _event("e0", _ts(5))], watermark=_ts(0, 2))
    out = _lookup(FakeOkta([ev]), SAAS)
    info = out["results"]["acct-1"]
    assert info["source"] == "archive+live" and info["uses"] == 2
    assert [e["source"] for e in info["events"]] == ["both", "archive"]
    assert info["events"][0]["event_type"] == REVEAL and info["events"][0]["request_id"] == "req-e1"
    assert info["newer_than_sync"] is False and info["complete"] is True
    assert info["event_types"] == [REVEAL, CHECKOUT] and info["archive_note"] is None
    assert out["coverage"]["archive"]["last_synced_at"] == _ts(0, 2)
    assert "uuid" not in info["events"][0]


def test_archive_only_when_the_live_top_up_fails(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("e1", _ts(3))])
    info = _lookup(FakeOkta(error=engine.OktaApiError(500, "logs", "boom")), SAAS)["results"]["acct-1"]
    assert info["source"] == "archive" and info["uses"] == 1
    assert info["live_error"] and info["complete"] is False  # newest events could not be checked


def test_live_only_when_the_environment_has_no_archive(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    info = _lookup(FakeOkta([_event("l1", _ts(1))]), SAAS)["results"]["acct-1"]
    assert info["source"] == "live" and info["archive_note"] == "no_archive"
    assert info["uses"] == 1 and info["window_days"] == 90


def test_live_only_without_an_environment_or_permission(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("e1", _ts(3))])
    no_env = _lookup(FakeOkta(), SAAS, env=None)["results"]["acct-1"]
    assert no_env["source"] == "live" and no_env["uses"] == 0
    denied = _lookup(FakeOkta(), SAAS, use_archive=False)["results"]["acct-1"]
    assert denied["source"] == "live" and denied["archive_note"] == "not_permitted" and denied["uses"] == 0


def test_a_live_event_newer_than_the_last_sync_is_shown_and_flagged(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("e1", _ts(3))], watermark=_ts(1))
    fresh = _event("fresh", _ts(0, 3))
    client = FakeOkta([fresh])
    info = _lookup(client, SAAS)["results"]["acct-1"]
    assert info["uses"] == 2 and info["newer_than_sync"] is True
    assert info["events"][0]["request_id"] == "req-fresh" and info["events"][0]["source"] == "live"
    # The live walk starts just before the archive's watermark, not 90 days back.
    assert client.calls[0]["since"] == (NOW - timedelta(days=1, hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_the_archive_reaches_back_further_than_the_live_window(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("old", _ts(200)), _event("new", _ts(2))], watermark=_ts(0, 1))
    info = _lookup(FakeOkta(), SAAS)["results"]["acct-1"]
    assert info["uses"] == 2 and info["events"][-1]["request_id"] == "req-old"
    assert info["window_days"] >= 199  # the window the answer is based on, not a fixed 90


def test_a_stale_archive_that_leaves_a_gap_never_claims_never_used(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("old", _ts(200))], watermark=_ts(120))
    client = FakeOkta()
    info = _lookup(client, SAAS)["results"]["acct-1"]
    assert info["archive_note"] == "stale_gap" and info["complete"] is False
    assert info["window_days"] == 90  # only the live window is vouched for
    assert info["uses"] == 1  # the old event is still real evidence
    assert client.calls[0]["since"] == _ts(90)


def test_an_event_type_the_archive_does_not_store_falls_back_to_live(tmp_audit_store, tmp_environments_file, monkeypatch):
    monkeypatch.setitem(engine.RESOURCE_ACCESS_EVENT_TYPES, "example_kind", {
        "event_types": ["pam.example.not_curated"], "extract_ids": engine._target_ids})
    _archive(ENV, [_event("e1", _ts(3))], scope="curated")
    live = _event("l1", _ts(1), event_type="pam.example.not_curated")
    info = _lookup(FakeOkta([live]), [{"resource_kind": "example_kind", "resource_id": "acct-1"}])["results"]["acct-1"]
    assert info["archive_note"] == "type_not_stored" and info["source"] == "live" and info["uses"] == 1
    # With scope "all" the same type IS stored.
    _archive(ENV, [_event("e2", _ts(3), event_type="pam.example.not_curated")], scope="all")
    again = _lookup(FakeOkta(), [{"resource_kind": "example_kind", "resource_id": "acct-1"}])["results"]["acct-1"]
    assert again["archive_note"] is None and again["uses"] == 1


def test_every_event_type_the_lookups_need_is_curated():
    needed = {t for m in engine.RESOURCE_ACCESS_EVENT_TYPES.values() for t in m["event_types"]}
    assert needed <= set(audit_store.COMPLIANCE_EVENT_TYPES)


def test_name_fallback_and_ambiguity_work_from_the_archive(tmp_audit_store, tmp_environments_file):
    db = {"serviceAccountType": "DATABASE_ACCOUNT"}
    _archive(ENV, [_event("d1", _ts(2), target_id="log-id", debug=db)])
    kind = "individual_database_account"
    unique = [{"resource_kind": kind, "resource_id": "a1", "account_name": "example-account", "name_unique": True},
              {"resource_kind": kind, "resource_id": "a2", "account_name": "other", "name_unique": True}]
    res = _lookup(FakeOkta(), unique)["results"]
    assert res["a1"]["uses"] == 1 and res["a1"]["events"][0]["matched_by"] == "name"
    assert res["a2"]["uses"] == 0 and "ambiguous" not in res["a2"]
    shared = [{"resource_kind": kind, "resource_id": "a1", "account_name": "example-account", "name_unique": False}]
    res = _lookup(FakeOkta(), shared)["results"]
    assert res["a1"]["uses"] == 0 and res["a1"]["ambiguous"] is True


def test_events_that_match_no_requested_resource_are_not_reported(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("x1", _ts(2), target_id="not-in-the-model")])
    out = _lookup(FakeOkta([_event("x2", _ts(1), target_id="also-unknown")]), SAAS)
    assert out["results"]["acct-1"]["uses"] == 0 and out["results"]["acct-1"]["events"] == []
    assert list(out["results"]) == ["acct-1"]


def test_only_this_users_events_in_this_environment_are_read(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("mine", _ts(2)), _event("theirs", _ts(1), actor="00uSOMEONEELSE")])
    _archive(OTHER_ENV, [_event("elsewhere", _ts(1))])
    info = _lookup(FakeOkta(), SAAS)["results"]["acct-1"]
    assert [e["request_id"] for e in info["events"]] == ["req-mine"]


def test_one_live_walk_per_distinct_event_type_set(tmp_audit_store, tmp_environments_file):
    audit_store.run_migrations()
    requests = [
        {"resource_kind": "individual_managed_saas_app_account", "resource_id": "a1"},
        {"resource_kind": "individual_unmanaged_saas_app_account", "resource_id": "a2"},
        {"resource_kind": "individual_okta_account", "resource_id": "a3"},
        {"resource_kind": "secret", "resource_id": "s1"},
    ]
    client = FakeOkta()
    _lookup(client, requests, env=None)
    assert len(client.calls) == 2  # one for reveal+checkout, one for secret reveals


def test_selector_families_are_not_capped_per_family(tmp_audit_store, tmp_environments_file):
    db = {"serviceAccountType": "DATABASE_ACCOUNT"}
    events = [_event(f"d{i}", _ts(0, i + 1), debug=db, targets=[
        {"id": f"id-{i}", "type": "Service Account", "displayName": f"example-db-{i}"}]) for i in range(60)]
    events.append(_event("rare", _ts(80), debug=db, targets=[
        {"id": "id-rare", "type": "Service Account", "displayName": "rarely-used"}]))
    info = _lookup(FakeOkta(events), [{"resource_kind": "database_account", "resource_id": "database_accounts"}],
                   env=None)["results"]["database_accounts"]
    assert info["uses"] == 61
    assert "rarely-used" in {e["account_name"] for e in info["events"]}


# ── server accounts ─────────────────────────────────────────────────────────
SERVER = "srv-1"
SA_KIND = "individual_server_account"


def _server_targets(account="example-user", server=SERVER):
    out = [{"id": "sa-1", "type": "Server Account", "displayName": account}]
    if server:
        out.append({"id": server, "type": "Server", "displayName": "example-host"})
    return out


def _sa_request(**extra):
    return [dict({"resource_kind": SA_KIND, "resource_id": "key-1", "server_id": SERVER, "account_name": "example-user",
                  "name_unique": True}, **extra)]


def test_server_account_reveal_checkout_and_credential_events(tmp_audit_store, tmp_environments_file):
    events = [
        _event("r1", _ts(1), event_type="pam.server_account.password.reveal", targets=_server_targets()),
        _event("c1", _ts(2), event_type=CHECKOUT, debug={"resourceType": "SERVER_ACCOUNT"}, targets=_server_targets(server=None)),
        _event("g1", _ts(3), event_type="pam.gateway_creds.issue", debug={"nextHopServerIds": SERVER}, targets=[]),
        _event("u1", _ts(4), event_type="pam.user_creds.issue", debug={"servers": f"other,{SERVER}"}, targets=[]),
        # Not this account / server: dropped.
        _event("r2", _ts(1), event_type="pam.server_account.password.reveal", targets=_server_targets(account="someone-else")),
        _event("r3", _ts(1), event_type="pam.server_account.password.reveal", targets=_server_targets(server="srv-2")),
        _event("c2", _ts(1), event_type=CHECKOUT, debug={"resourceType": "PAM_DATABASE_ACCOUNT"}, targets=_server_targets(server=None)),
    ]
    _archive(ENV, events)
    info = _lookup(FakeOkta(), _sa_request())["results"]["key-1"]
    assert [(e["request_id"], e.get("matched_by")) for e in info["events"]] == [
        ("req-r1", "server_account"), ("req-c1", "name"), ("req-g1", "server"), ("req-u1", "server")]
    assert info["uses"] == 4 and set(info["event_types"]) >= {"pam.server_account.password.reveal", "pam.user_creds.issue"}


def test_server_account_checkout_by_a_shared_name_is_ambiguous_not_guessed(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("c1", _ts(2), event_type=CHECKOUT, debug={"resourceType": "SERVER_ACCOUNT"},
                          targets=_server_targets(server=None))])
    info = _lookup(FakeOkta(), _sa_request(name_unique=False))["results"]["key-1"]
    assert info["uses"] == 0 and info["ambiguous"] is True


def test_two_accounts_on_one_server_are_looked_up_separately(tmp_audit_store, tmp_environments_file):
    _archive(ENV, [_event("r1", _ts(1), event_type="pam.server_account.password.reveal", targets=_server_targets("root"))])
    requests = [
        {"resource_kind": SA_KIND, "resource_id": "k-root", "server_id": SERVER, "account_name": "root", "name_unique": True},
        {"resource_kind": SA_KIND, "resource_id": "k-app", "server_id": SERVER, "account_name": "app", "name_unique": True},
    ]
    res = _lookup(FakeOkta(), requests)["results"]
    assert res["k-root"]["uses"] == 1 and res["k-app"]["uses"] == 0


# ── input validation ────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [
    "not a list",
    [["x"]],
    [{"resource_kind": "secret", "resource_id": "a/../b"}],
    [{"resource_kind": "secret", "resource_id": ""}],
    [{"resource_kind": "bad kind!", "resource_id": "ok"}],
    [{"resource_kind": "secret", "resource_id": "ok", "account_name": 5}],
    [{"resource_kind": "secret", "resource_id": "ok", "name_unique": "yes"}],
    [{"resource_kind": "secret", "resource_id": "ok", "server_id": "x y"}],
])
def test_requests_are_validated(bad):
    with pytest.raises(ValueError):
        engine.validate_access_requests(bad)


def test_valid_requests_pass_through_only_known_fields():
    clean = engine.validate_access_requests([{"resource_kind": "secret", "resource_id": "s-1", "extra": "dropped"}])
    assert clean == [{"resource_kind": "secret", "resource_id": "s-1"}]


def test_a_bad_actor_id_is_refused_before_anything_is_read():
    with pytest.raises(ValueError):
        engine.find_access_evidence(None, 'x" or "1" eq "1', SAAS)


# ── model fixes ─────────────────────────────────────────────────────────────
def test_a_user_whose_groups_cannot_be_read_is_flagged_not_shown_as_having_none():
    class Flaky(ModelClient):
        def list_user_groups(self, name):
            if name == "u2":
                raise engine.OpaApiError(500, "groups", "boom")
            return [{"id": "g"}]

    model = engine.build_access_model(Flaky())
    by_name = {u["name"]: u for u in model["users"]}
    assert by_name["u2"]["groups_error"] is True and by_name["u2"]["groups"] == []
    assert "groups_error" not in by_name["u1"]
    assert any(w["section"] == "user groups" for w in model["warnings"])


class ServerModelClient(ModelClient):
    def list_project_servers(self, rg, proj):
        return [{"id": "srv-1", "hostname": "example-host", "labels": {}}]

    def list_security_policies(self):
        def rule(selector_type, selector, resource_type="server_based_resource"):
            return {"name": "r", "resource_type": resource_type, "privileges": [], "conditions": [],
                    "resource_selector": {"selectors": [{"selector_type": selector_type, "selector": selector}]}}
        return [{
            "id": "pol", "name": "P", "rules": [
                rule("individual_server_account", {"server": {"id": "srv-1", "name": "example-host"}, "username": "root"}),
                rule("individual_server_account", {"server": {"id": "srv-1", "name": "example-host"}, "username": "app"}),
                rule("individual_server_account", {"server": {"id": "gone", "name": "old-host"}, "username": "app"}),
                rule("secret_folder", {"secret_folder": {"id": "no-such-folder", "name": "Gone"}}, "secret_based_resource"),
                rule("secret_folder", {"secret_folder": {"id": "f1", "name": "Known"}}, "secret_based_resource"),
            ]}]


def test_server_account_rows_keep_the_username_and_say_server_slash_account():
    model = engine.build_access_model(ServerModelClient())
    res = [r for rule in model["policies"][0]["rules"] for r in rule["resolutions"]]
    root = next(r for r in res if r.get("account_name") == "root")
    assert root["name"] == "example-host / root" and root["server_id"] == "srv-1" and root["name_unique"] is True
    app = [r for r in res if r.get("account_name") == "app"]
    assert len(app) == 2 and all(r["name_unique"] is False for r in app)  # "app" exists on two servers


def test_missing_objects_and_unresolved_folders_are_marked():
    model = engine.build_access_model(ServerModelClient())
    res = {r["id"]: r for rule in model["policies"][0]["rules"] for r in rule["resolutions"]}
    assert res["gone"]["missing"] is True and "missing" not in res["srv-1"]
    assert res["no-such-folder"]["missing"] is True and "child_secrets" not in res["no-such-folder"]  # unresolved, not empty
    assert res["f1"]["child_secrets"] == [] and "missing" not in res["f1"]  # found and empty


def test_relationship_granted_folder_gets_its_secrets():
    class Rel(ModelClient):
        def get_assignment(self, assignment_id):
            return {"id": assignment_id, "name": assignment_id,
                    "relationship_assignments": [{"relationship": {"id": "rel", "name": "R"}, "principal": {"id": "g1", "name": "G1"}}],
                    "resource_assignments": {"secret_or_folder_assignments": [{"id": "f1", "name": "F", "type": "secret_folder"}]}}
    model = engine.build_access_model(Rel())
    folder = next(r for p in model["policies"] for rule in p["rules"] for r in rule["resolutions"]
                  if r.get("resource_kind") == "relationship_assignment:secret_folder")
    assert folder["child_secrets"] == []


def test_active_directory_description_lists_every_branch():
    text = engine.describe_dynamic_selector("active_directory_based_resource", "active_directory", {
        "individual_accounts": {"by_domain": ["example.test"]},
        "shared_accounts": {"specific_accounts": [{"account_name": "shared-1"}], "by_domain": ["other.test"]},
        "servers": {"selectors": [{"selector": {"labels": {"env": "prod"}}}]},
    })
    for part in ("example.test", "shared-1", "other.test", "env=prod"):
        assert part in text


def test_a_server_scoped_active_directory_selector_is_named_with_its_scope_in_words():
    # 5.45.1: a server scope no longer stops the accounts being named
    accounts = [{"id": "ad1", "account_name": "svc", "domain": {"name": "example.test"}, "resource_group_id": "rg1"}]
    selector = {"individual_accounts": {"by_domain": ["example.test"]},
                "servers": {"selectors": [{"selector": {"labels": {"env": "prod"}}}]}}
    rule = {"resource_type": "active_directory_based_resource",
            "resource_selector": {"selectors": [{"selector_type": "active_directory", "selector": selector}]}}
    out = engine._resolve_rule(rule, {"selector_accounts": {"active_directory": accounts}}, "rg1")
    assert len(out) == 1 and out[0]["kind"] == "resolved" and out[0]["name"] == "svc"
    assert out[0]["scope_text"] == "Only on servers labeled env=prod"
