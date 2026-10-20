"""5.45.1: selector rows named wherever it is certain, and a machine-readable
reason on every selector row that stays one. All names/ids are placeholders."""
import pytest

import create_secret_folders as engine

RG = "rg-1"


def _server(sid, host, os_text="Ubuntu 24.04", os_type="linux", labels=None, rg=RG, **extra):
    return {"id": sid, "hostname": host, "os": os_text, "os_type": os_type, "labels": labels if labels is not None else {},
            "state": "ACTIVE", "deleted_at": None, "project_id": "p1", "project_name": "Example Project",
            "resource_group_id": rg, **extra}


SERVERS = [
    _server("s1", "srv-example-1"),
    _server("s2", "srv-example-2", os_text="Windows Server 2022", os_type="windows"),
    _server("s3", "srv-example-3", labels={"env": "prod"}),
]


def _sel(**labels):
    return {"server_selector": {"labels": labels}}


def _outcome(sel, servers=SERVERS, rg=RG):
    return engine._server_outcome(sel, servers, rg)


def _names(out):
    return [r["name"] for r in out["rows"]] if out["rows"] else None


# ---- servers -------------------------------------------------------------

def test_system_hostname_resolves_by_exact_hostname():
    out = _outcome(_sel(**{"system.hostname": "srv-example-1"}))
    assert _names(out) == ["srv-example-1"] and out["rows"][0]["server_os"] == "Ubuntu 24.04" and not out["inferred"]


def test_system_hostname_case_difference_is_a_disagreement_not_a_guess():
    out = _outcome(_sel(**{"system.hostname": "SRV-EXAMPLE-1"}))
    assert out["rows"] is None and out["reason"]["code"] == "readings_disagree" and out["candidates"] == ["srv-example-1"]


def test_system_hostname_alternative_names_are_only_used_when_every_reading_agrees():
    servers = SERVERS + [_server("s4", "srv-example-4", canonical_name="alias.example.test")]
    out = _outcome(_sel(**{"system.hostname": "alias.example.test"}), servers)
    assert out["rows"] is None and out["reason"]["code"] == "readings_disagree" and out["candidates"] == ["srv-example-4"]
    assert _names(_outcome(_sel(**{"system.hostname": "srv-example-4"}), servers)) == ["srv-example-4"]


def test_system_os_type_resolves_by_exact_equality():
    assert _names(_outcome(_sel(**{"system.os_type": "windows"}))) == ["srv-example-2"]
    assert _names(_outcome(_sel(**{"system.os_type": "linux"}))) == ["srv-example-1", "srv-example-3"]
    assert _outcome(_sel(**{"system.os_type": "Linux"}))["reason"]["code"] == "readings_disagree"


def test_system_os_raw_equality_is_certain():
    out = _outcome(_sel(**{"system.os": "Windows Server 2022"}))
    assert _names(out) == ["srv-example-2"] and not out["inferred"] and "inferred" not in out["rows"][0]


def test_system_os_normalised_match_resolves_but_is_marked_inferred():
    out = _outcome(_sel(**{"system.os": "ubuntu_24.04"}))
    assert _names(out) == ["srv-example-1", "srv-example-3"] and out["inferred"] is True
    assert all(r["inferred"] and "inferred" in r["match_note"] for r in out["rows"])


def test_system_os_raw_and_normalised_readings_that_differ_are_refused():
    servers = SERVERS + [_server("s4", "srv-example-4", os_text="ubuntu_24.04"), _server("s5", "srv-example-5", os_text="UBUNTU 24.04")]
    out = _outcome(_sel(**{"system.os": "ubuntu_24.04"}), servers)
    assert out["rows"] is None and out["reason"]["code"] == "readings_disagree"


def test_combined_labels_need_the_and_and_or_readings_to_agree():
    assert _names(_outcome(_sel(**{"system.os_type": "linux", "env": "prod"}))) is None   # AND finds one, OR finds two
    out = _outcome(_sel(**{"system.os_type": "linux", "env": "prod"}))
    assert out["reason"]["code"] == "readings_disagree" and out["candidates"] == ["srv-example-1", "srv-example-3"]
    both = [_server("s1", "srv-example-1", labels={"env": "prod"})]
    assert _names(_outcome(_sel(**{"system.os_type": "linux", "env": "prod"}), both)) == ["srv-example-1"]


def test_custom_labels_keep_their_rules_and_do_not_need_system_fields():
    assert _names(_outcome(_sel(env="prod"))) == ["srv-example-3"]


@pytest.mark.parametrize("sel,servers,rg,code", [
    (_sel(env="prod"), None, RG, "servers_unavailable"),
    (_sel(env="prod"), SERVERS, None, "no_resource_group"),
    ({"server_selector": {"labels": {}}}, SERVERS, RG, "unsupported_selector"),
    (_sel(**{"system.cloud_provider": "aws"}), SERVERS, RG, "system_label_unsupported"),
    (_sel(env="staging"), SERVERS, RG, "no_server_matched"),
    (_sel(env="prod"), SERVERS, "rg-2", "resource_group_scope"),
    (_sel(**{"system.os": "x"}), [{"id": "s9", "hostname": "srv-example-9"}], RG, "server_field_unreadable"),
    (_sel(env="prod"), SERVERS + [{"id": "s9", "hostname": "srv-example-9", "resource_group_id": RG}], RG, "server_field_unreadable"),
    (_sel(env="Prod"), SERVERS, RG, "readings_disagree"),
])
def test_every_server_fallback_names_its_reason(sel, servers, rg, code):
    out = _outcome(sel, servers, rg)
    assert out["rows"] is None and out["reason"]["code"] == code and out["reason"]["text"]


def test_server_resolve_rule_attaches_reason_and_candidates_to_the_selector_row():
    rule = {"resource_type": "server_based_resource", "resource_selector": {"selectors": [
        {"selector_type": "server_label", "selector": _sel(**{"system.hostname": "SRV-EXAMPLE-1"})}]}}
    out = engine._resolve_rule(rule, {"selector_accounts": {"server_label": SERVERS}}, RG)
    assert out[0]["kind"] == "condition" and out[0]["unresolved_reason"]["code"] == "readings_disagree"
    assert out[0]["candidates"] == ["srv-example-1"]


# ---- Active Directory ----------------------------------------------------

def _ad(aid, name, domain="example.test", **extra):
    base = {"id": aid, "account_name": name, "sam_account_name": name, "domain": {"name": domain} if domain else None,
            "project_id": "p1", "project_name": "Example Project", "resource_group_id": RG}
    base.update(extra)
    return base


ACCOUNTS = [_ad("d1", "a1_svc"), _ad("d2", "b2_svc"), _ad("d3", "a1_other", domain="other.test")]


def _rule(selector):
    return {"resource_type": "active_directory_based_resource",
            "resource_selector": {"selectors": [{"selector_type": "active_directory", "selector": selector}]}}


def _idx(accounts=ACCOUNTS, servers=SERVERS):
    return {"selector_accounts": {"active_directory": accounts, "server_label": servers}}


def test_by_domain_is_named_even_when_another_account_has_no_domain():
    accounts = ACCOUNTS + [_ad("d4", "local_acct", domain=None)]
    out = engine._resolve_rule(_rule({"individual_accounts": {"by_domain": ["example.test"]}}), _idx(accounts), RG)
    assert [(r["kind"], r["name"], r["sub_label"]) for r in out] == [("resolved", "a1_svc", "example.test"), ("resolved", "b2_svc", "example.test")]


@pytest.mark.parametrize("shape", [
    {"domain": "example.test"},
    {"domain": {"domain": "example.test"}},
    {"domain": None, "domain_name": "example.test"},
    {"domain": None, "dns_name": "example.test"},
])
def test_by_domain_reads_every_spelling_of_the_domain(shape):
    accounts = [_ad("d1", "a1_svc", **shape)]
    accounts[0].update(shape)
    out = engine._resolve_rule(_rule({"individual_accounts": {"by_domain": ["example.test"]}}), _idx(accounts), RG)
    assert [r["name"] for r in out] == ["a1_svc"]


def test_an_account_with_an_empty_domain_that_may_belong_blocks_naming_with_a_reason():
    accounts = ACCOUNTS + [_ad("d4", "hidden", domain=None, upn="hidden@example.test")]
    out = engine._resolve_rule(_rule({"individual_accounts": {"by_domain": ["example.test"]}}), _idx(accounts), RG)
    assert out[0]["kind"] == "condition" and out[0]["unresolved_reason"]["code"] == "domain_unreadable"
    assert out[0]["candidates"] == ["hidden"]


def test_server_scope_does_not_stop_naming_and_lists_the_servers():
    sel = {"individual_accounts": {"by_domain": ["example.test"]},
           "servers": {"selectors": [{"selector_type": "server_label", "selector": {"labels": {"system.os_type": "windows"}}}]}}
    out = engine._resolve_rule(_rule(sel), _idx(), RG)
    assert [r["name"] for r in out] == ["a1_svc", "b2_svc"]
    assert out[0]["scope_text"] == "Only on servers labeled system.os_type=windows" and out[0]["scope_servers"] == ["srv-example-2"]
    assert "scope_reason" not in out[0]


def test_unresolvable_server_scope_still_names_accounts_and_says_why():
    sel = {"individual_accounts": {"by_domain": ["example.test"]},
           "servers": {"selectors": [{"selector_type": "server_label", "selector": {"labels": {"system.cloud_provider": "aws"}}}]}}
    out = engine._resolve_rule(_rule(sel), _idx(), RG)
    assert out[0]["kind"] == "resolved" and "scope_servers" not in out[0]
    assert out[0]["scope_reason"]["code"] == "system_label_unsupported"


def test_individual_server_scope_and_ssh_servers_scope():
    sel = {"individual_accounts": {"by_domain": ["example.test"]},
           "servers": {"selectors": [{"selector_type": "individual_server", "selector": {"server": {"id": "s1"}}}]},
           "ssh_servers": {"selectors": [{"selector_type": "individual_server", "selector": {"server": {"id": "s2"}}}]}}
    out = engine._resolve_rule(_rule(sel), _idx(), RG)
    assert out[0]["scope_servers"] == ["srv-example-1", "srv-example-2"]
    assert out[0]["scope_text"] == "Only on servers srv-example-1; or SSH servers srv-example-2"


def test_condition_and_domain_together_are_named_only_when_and_equals_or():
    cond = {"account_name_format": "STARTS_WITH", "value": "a1"}
    sel = {"individual_accounts": {"by_condition": cond, "by_domain": ["example.test"]}}
    out = engine._resolve_rule(_rule(sel), _idx(), RG)
    # AND finds a1_svc, OR finds a1_svc, b2_svc, a1_other: not the same
    assert len(out) == 1 and out[0]["kind"] == "condition"
    assert out[0]["unresolved_reason"]["code"] == "readings_disagree"
    assert out[0]["candidates"] == ["a1_other", "a1_svc", "b2_svc"]
    same = [_ad("d1", "a1_svc"), _ad("d3", "zz", domain="other.test")]
    same_sel = {"individual_accounts": {"by_condition": {"account_name_format": "EQUALS", "value": "a1_svc"}, "by_domain": ["example.test"]}}
    out = engine._resolve_rule(_rule(same_sel), _idx(same), RG)
    assert [r["name"] for r in out] == ["a1_svc"]


def test_shared_account_named_twice_gives_one_row_however_the_rule_spells_it():
    accounts = ACCOUNTS + [_ad("d5", "shared_admin")]
    plain = {"shared_accounts": {"specific_accounts": [{"account_name": "shared_admin"}]}}
    scoped = {"shared_accounts": {"specific_accounts": [{"account_name": "shared_admin@example.test"}]},
              "servers": {"selectors": [{"selector_type": "server_label", "selector": {"labels": {"system.os_type": "windows"}}}]}}
    rule = {"resource_type": "active_directory_based_resource", "resource_selector": {"selectors": [
        {"selector_type": "active_directory", "selector": plain}, {"selector_type": "active_directory", "selector": scoped}]}}
    out = engine._resolve_rule(rule, _idx(accounts), RG)
    assert [(r["kind"], r["id"], r["name"], r.get("scope_text")) for r in out] == [
        ("resolved", "d5", "shared_admin", None), ("resolved", "d5", "shared_admin", "Only on servers labeled system.os_type=windows")]
    assert out[1]["sub_label"] == "example.test"
    # a shared account the list does not know is still named, once, and no selector row repeats it
    ghost = {"shared_accounts": {"specific_accounts": [{"account_name": "ghost@example.test"}]}}
    out = engine._resolve_rule(_rule(ghost), _idx(accounts), RG)
    assert [(r["kind"], r["name"]) for r in out] == [("resolved", "ghost@example.test")]


@pytest.mark.parametrize("selector,accounts,rg,code", [
    ({"individual_accounts": {"by_domain": ["example.test"]}}, None, RG, "accounts_unavailable"),
    ({"individual_accounts": {"by_domain": ["example.test"]}}, ACCOUNTS, None, "no_resource_group"),
    ({"individual_accounts": {"by_domain": []}, "shared_accounts": {}}, ACCOUNTS, RG, "unsupported_selector"),
    ({"individual_accounts": {"by_condition": {"account_name_format": "REGEX", "value": "x"}}}, ACCOUNTS, RG, "unsupported_name_format"),
    ({"individual_accounts": {"by_condition": {"account_name_format": "CONTAINS", "value": ""}}}, ACCOUNTS, RG, "unsupported_name_format"),
    ({"individual_accounts": {"by_condition": {"account_name_format": "CONTAINS", "value": "a"}}}, [{"id": "x", "account_name": None, "resource_group_id": RG}], RG, "name_field_unreadable"),
    ({"individual_accounts": {"by_domain": ["nowhere.test"]}}, ACCOUNTS, RG, "no_account_matched"),
    ({"individual_accounts": {"by_domain": ["example.test"]}}, ACCOUNTS[:1] + [_ad("d9", "z", resource_group_id="rg-2")], RG, "resource_group_scope"),
    ({"individual_accounts": {"by_condition": {"account_name_format": "CONTAINS", "value": "A1"}}}, ACCOUNTS, RG, "readings_disagree"),
    ({"shared_accounts": {"by_domain": ["example.test"]}}, ACCOUNTS, RG, "shared_selection_unsupported"),
    ({}, ACCOUNTS, RG, "unsupported_selector"),
])
def test_every_ad_fallback_names_its_reason(selector, accounts, rg, code):
    out = engine._resolve_rule(_rule(selector), _idx(accounts), rg)
    assert out[-1]["kind"] == "condition"
    assert out[-1]["unresolved_reason"]["code"] == code and out[-1]["unresolved_reason"]["text"]


def test_other_selector_kinds_and_empty_rules_carry_a_reason_too():
    rule = {"resource_type": "database_based_resource", "resource_selector": {"selectors": [
        {"selector_type": "database", "selector": {"database_connections": [{"id": "c1"}], "database_accounts": [{"account_name_format": "CONTAINS", "value": "x"}]}},
        {"selector_type": "something_new", "selector": {}}]}}
    out = engine._resolve_rule(rule, {"selector_accounts": {"database": []}}, RG)
    assert [r["unresolved_reason"]["code"] for r in out] == ["no_account_matched", "unsupported_selector_kind"]
    assert engine._resolve_rule({"resource_type": "secret_based_resource"}, {}, RG)[0]["unresolved_reason"]["code"] == "no_selector"


def test_several_reasons_are_joined_and_every_code_is_known():
    sel = {"individual_accounts": {"by_domain": ["nowhere.test"]}, "shared_accounts": {"by_domain": ["example.test"]}}
    out = engine._resolve_rule(_rule(sel), _idx(), RG)
    reason = out[0]["unresolved_reason"]
    assert reason["codes"] == ["no_account_matched", "shared_selection_unsupported"] and reason["code"] == "no_account_matched"
    assert set(reason["codes"]) <= set(engine.UNRESOLVED_CODES)


def test_version_header_and_constant_agree():
    head = open(engine.__file__, encoding="utf-8").read(4000)
    assert f"# Version     : {engine.SCRIPT_VERSION}" in head
