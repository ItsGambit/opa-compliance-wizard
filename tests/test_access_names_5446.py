"""5.44.6: last used by exact account name when the System Log id differs from
the OPA account id; Active Directory shared accounts named from the rule;
server_label selectors resolved to named servers. Names, ids and projects are
all placeholders."""
import pytest

import create_secret_folders as engine

SEL_RG = "rg-1"


class FakeOktaClient:
    def __init__(self, events):
        self._events = events

    def get_system_log(self, **_kwargs):
        return self._events, True


def _event(name, event_type, debug, target_id="log-id-unrelated"):
    return {
        "uuid": "e-" + name, "eventType": event_type, "published": "2026-10-03T00:00:00.000Z",
        "actor": {"id": "00uActor"}, "outcome": {"result": "SUCCESS"},
        "debugContext": {"debugData": dict(debug)},
        "target": [{"id": target_id, "type": "Service Account", "displayName": name},
                   {"id": "team-1", "type": "Team", "displayName": "Example Team"}],
    }


def _lookup(events, requests):
    return engine.find_last_access_for_user(FakeOktaClient(events), "00uUSER", requests)


REVEAL = "pam.service_account.password.reveal"
DB = {"serviceAccountType": "DATABASE_ACCOUNT"}
KIND = "individual_database_account"
DB_REQ = [
    {"resource_kind": KIND, "resource_id": "a1", "account_name": "svc_app", "name_unique": True},
    {"resource_kind": KIND, "resource_id": "a2", "account_name": "audit", "name_unique": True},
]


@pytest.mark.parametrize("event_type,debug", [
    (REVEAL, DB),
    ("pam.resource.checkout", {"resourceType": "PAM_DATABASE_ACCOUNT"}),
])
def test_database_last_used_falls_back_to_the_exact_account_name_when_the_ids_differ(event_type, debug):
    res = _lookup([_event("svc_app", event_type, debug)], DB_REQ)
    assert len(res["a1"]["events"]) == 1 and res["a1"]["events"][0]["matched_by"] == "name"
    assert res["a2"]["events"] == [] and "ambiguous" not in res["a2"]


def test_name_fallback_is_exact_and_family_bound():
    events = [
        _event("SVC_APP", REVEAL, DB),                                  # case differs
        _event("svc_app_2", REVEAL, DB),                                # longer name
        _event("svc", REVEAL, DB),                                      # substring
        _event("svc_app", REVEAL, {"serviceAccountType": "PAM_AD_ACCOUNT"}),   # other family
        _event("svc_app", REVEAL, {}),                                  # no family evidence
    ]
    res = _lookup(events, DB_REQ)
    assert res["a1"]["events"] == [] and res["a1"]["complete"] is True and "ambiguous" not in res["a1"]


def test_name_is_not_used_without_the_request_carrying_it():
    res = _lookup([_event("svc_app", REVEAL, DB)], [{"resource_kind": KIND, "resource_id": "a1"}])
    assert res["a1"]["events"] == []


def test_id_match_still_works_and_is_not_marked_as_a_name_match():
    res = _lookup([_event("svc_app", REVEAL, DB, target_id="a1")], DB_REQ)
    assert len(res["a1"]["events"]) == 1 and "matched_by" not in res["a1"]["events"][0]


def test_a_shared_name_is_ambiguous_not_guessed_and_not_never_used():
    req = [
        {"resource_kind": KIND, "resource_id": "a1", "account_name": "svc_app", "name_unique": False},
        {"resource_kind": KIND, "resource_id": "a3", "account_name": "svc_app", "name_unique": False},
    ]
    res = _lookup([_event("svc_app", REVEAL, DB)], req)
    assert res["a1"]["events"] == [] and res["a1"]["ambiguous"] is True
    assert res["a3"]["events"] == [] and res["a3"]["ambiguous"] is True
    # an id match for one of them is attributed by id; the other is not flagged
    res = _lookup([_event("svc_app", REVEAL, DB, target_id="a1")], req)
    assert len(res["a1"]["events"]) == 1 and res["a3"]["events"] == [] and "ambiguous" not in res["a3"]


def test_active_directory_last_used_falls_back_to_the_account_name():
    req = [{"resource_kind": "individual_active_directory_account", "resource_id": "d1", "account_name": "svc_one", "name_unique": True}]
    assert len(_lookup([_event("svc_one", REVEAL, {"serviceAccountType": "PAM_AD_ACCOUNT"})], req)["d1"]["events"]) == 1
    assert _lookup([_event("svc_one", REVEAL, DB)], req)["d1"]["events"] == []


def _dbacct(aid, name, conn="c1"):
    return {"id": aid, "account_name": name, "database_connection": {"id": conn, "name": "example-conn-" + conn},
            "project_id": "p1", "project_name": "Example Project", "resource_group_id": SEL_RG}


def _dbsel(conns, *conds):
    return {"database_connections": [{"id": c, "name": "n"} for c in conns],
            "database_accounts": [{"account_name_format": f, "value": v} for f, v in conds]}


def test_resolved_rows_carry_the_name_and_whether_it_is_unique():
    accts = [_dbacct("a1", "svc_app"), _dbacct("a3", "audit"), _dbacct("a5", "svc_app", conn="c2")]
    rows = engine._resolve_account_selector("database", _dbsel(["c1", "c2"], ("EQUALS", "svc_app")), accts, SEL_RG)
    assert [(r["id"], r["account_name"], r["name_unique"]) for r in rows] == [("a1", "svc_app", False), ("a5", "svc_app", False)]
    rows = engine._resolve_account_selector("database", _dbsel(["c1"], ("EQUALS", "audit")), accts, SEL_RG)
    assert rows[0]["name_unique"] is True


AD_ACCOUNTS = [
    {"id": "d1", "account_name": "svc_one", "sam_account_name": "svc_one", "domain": {"name": "example.test"},
     "resource_group_id": SEL_RG, "project_id": "p1", "project_name": "Example Project"},
    {"id": "d2", "account_name": "shared_admin", "sam_account_name": "shared_admin", "domain": {"name": "example.test"},
     "resource_group_id": SEL_RG},
]


def _ad_rule(selector):
    return {"resource_type": "active_directory_based_resource",
            "resource_selector": {"selectors": [{"selector_type": "active_directory", "selector": selector}]}}


def test_ad_shared_accounts_named_in_the_rule_become_named_rows_and_the_rest_stays_a_selector():
    out = engine._resolve_rule(_ad_rule({"shared_accounts": {
        "specific_accounts": [{"account_name": "shared_admin"}, {"shared_account": {"id": "x", "name": "shared_other"}}],
        "by_domain": ["example.test"]}}), {"selector_accounts": {"active_directory": AD_ACCOUNTS}}, SEL_RG)
    assert [(r["kind"], r.get("name")) for r in out[:2]] == [("resolved", "shared_admin"), ("resolved", "shared_other")]
    assert out[0]["id"] == "d2" and out[0]["name_unique"] is True and out[1]["id"] == "shared:shared_other"
    assert [r["kind"] for r in out] == ["resolved", "resolved", "condition"]
    # the unnamed remainder is described without repeating the named accounts
    assert out[2]["description"] == "Shared AD accounts in domain(s): example.test"


def test_ad_individual_and_shared_parts_are_both_kept():
    selectors = {"selector_accounts": {"active_directory": AD_ACCOUNTS}}
    shared = {"specific_accounts": [{"account_name": "shared_admin"}]}
    cond = {"by_condition": {"account_name_format": "STARTS_WITH", "value": "svc"}}
    out = engine._resolve_rule(_ad_rule({"individual_accounts": cond, "shared_accounts": shared}), selectors, SEL_RG)
    assert sorted(r["name"] for r in out) == ["shared_admin", "svc_one"] and all(r["kind"] == "resolved" for r in out)
    # an account matched both ways appears once
    out = engine._resolve_rule(_ad_rule({"individual_accounts": {"by_domain": ["example.test"]}, "shared_accounts": shared}), selectors, SEL_RG)
    assert sorted(r["name"] for r in out) == ["shared_admin", "svc_one"]


def test_ad_selector_with_nothing_certain_stays_exactly_as_before():
    sel = {"shared_accounts": {"by_domain": ["example.test"]}}
    out = engine._resolve_rule(_ad_rule(sel), {"selector_accounts": {"active_directory": AD_ACCOUNTS}}, SEL_RG)
    assert [r["kind"] for r in out] == ["condition"] and out[0]["description"] == "Shared AD accounts in domain(s): example.test"


def _server(sid, host, labels, state="ACTIVE", rg=SEL_RG):
    return {"id": sid, "hostname": host, "labels": labels, "state": state, "deleted_at": None,
            "project_id": "p1", "project_name": "Example Project", "resource_group_id": rg}


SERVERS = [
    _server("s1", "example-web-01", {"env": "prod", "tier": "web"}),
    _server("s2", "example-db-01", {"env": "prod", "tier": "db"}),
    _server("s3", "example-dev-01", {"env": "dev"}),
]


def _label_sel(**labels):
    return {"server_selector": {"labels": labels}, "account_selector_type": "none", "account_selector": {"_type": "none"}}


def _server_rule(selector):
    return {"resource_type": "server_based_resource",
            "resource_selector": {"selectors": [{"selector_type": "server_label", "selector": selector}]}}


def test_server_label_selector_resolves_to_named_servers():
    got = engine._resolve_server_selector(_label_sel(env="prod"), SERVERS, SEL_RG)
    assert [(r["name"], r["id"], r["resource_kind"]) for r in got] == [
        ("example-db-01", "s2", "individual_server"), ("example-web-01", "s1", "individual_server")]
    assert got[0]["project_name"] == "Example Project" and "Servers labeled env=prod" in got[0]["via_selector"]
    out = engine._resolve_rule(_server_rule(_label_sel(env="prod")), {"selector_accounts": {"server_label": SERVERS}}, SEL_RG)
    assert [r["kind"] for r in out] == ["resolved", "resolved"]


def test_server_label_selector_stays_a_selector_when_not_certain():
    def resolve(sel, servers=SERVERS, rg=SEL_RG):
        return engine._resolve_server_selector(sel, servers, rg)
    assert resolve(_label_sel(env="prod")) is not None
    assert resolve(_label_sel(env="staging")) is None                       # nothing matches
    assert resolve(_label_sel(env="prod"), servers=None) is None            # list incomplete
    assert resolve(_label_sel(env="prod"), rg=None) is None
    assert resolve(_label_sel(env="prod"), rg="rg-2") is None               # resource group changes the result
    assert resolve(_label_sel(**{"system.cloud_provider": "aws"})) is None  # a system label with no source on the server
    assert resolve({"server_selector": {"labels": {}}}) is None
    assert resolve({"server_selector": {}}) is None
    assert resolve(_label_sel(env="Prod")) is None                          # only matches if case is ignored
    assert resolve(_label_sel(env="prod", tier="web")) is None              # all-labels vs any-label readings differ
    inactive = _server("s4", "example-old-01", {"env": "prod"}, state="INACTIVE")
    assert resolve(_label_sel(env="prod"), servers=SERVERS + [inactive]) is None   # state changes the result
    unlabeled = {"id": "s5", "hostname": "example-x", "resource_group_id": SEL_RG}
    assert resolve(_label_sel(env="prod"), servers=SERVERS + [unlabeled]) is None  # a server without readable labels
    assert [r["id"] for r in resolve(_label_sel(tier="web"))] == ["s1"]
    # without the server list the selector row stays exactly as before
    out = engine._resolve_rule(_server_rule(_label_sel(env="prod")), {}, SEL_RG)
    assert [r["kind"] for r in out] == ["condition"]
