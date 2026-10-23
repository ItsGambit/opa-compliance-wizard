"""5.53.0: the control catalogue (server/control_catalogue.json) and its loader stay consistent with the report definitions."""
import json
import os
import re

import audit_store

CATALOGUE = audit_store.CONTROL_CATALOGUE_PATH

# Every SOC 2 (2017 Trust Services Criteria) common criterion id that exists, so a typo cannot slip in.
SOC2_COMMON_CRITERIA = {
    "CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5",
    "CC2.1", "CC2.2", "CC2.3",
    "CC3.1", "CC3.2", "CC3.3", "CC3.4",
    "CC4.1", "CC4.2",
    "CC5.1", "CC5.2", "CC5.3",
    "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7", "CC6.8",
    "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5",
    "CC8.1",
    "CC9.1", "CC9.2",
}
KNOWN_FRAMEWORK_IDS = {"soc2": SOC2_COMMON_CRITERIA}
STATUSES = {"proposed", "auditor-reviewed"}


def _load():
    with open(CATALOGUE, encoding="utf-8") as fh:
        return json.load(fh)


def test_file_is_valid_json_and_stable_sorted():
    with open(CATALOGUE, encoding="utf-8") as fh:
        text = fh.read()
    data = json.loads(text)
    assert text == json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_header_fields():
    data = _load()
    assert data["format"] == 1
    assert isinstance(data["version"], str) and re.fullmatch(r"\d+\.\d+\.\d+-\d+", data["version"])
    assert set(data["frameworks"]) <= set(KNOWN_FRAMEWORK_IDS)
    assert all(f["name"] for f in data["frameworks"].values())


def test_every_report_has_an_entry_and_every_entry_names_a_real_report():
    assert set(_load()["reports"]) == set(audit_store.COMPLIANCE_REPORTS)
    assert len(audit_store.COMPLIANCE_REPORTS) == 18


def test_controls_are_known_and_statuses_valid():
    data = _load()
    for key, entry in data["reports"].items():
        assert entry["controls"], key
        seen = set()
        for c in entry["controls"]:
            assert set(c) == {"framework", "id", "status"}, key
            assert c["framework"] in data["frameworks"], key
            assert c["id"] in KNOWN_FRAMEWORK_IDS[c["framework"]], (key, c["id"])
            assert c["status"] in STATUSES, key
            assert (c["framework"], c["id"]) not in seen, key
            seen.add((c["framework"], c["id"]))
        assert entry["methodology"].strip(), key
        assert isinstance(entry["known_limits"], list) and all(isinstance(x, str) and x.strip() for x in entry["known_limits"]), key


def test_nothing_is_auditor_reviewed_in_5_53_0():
    for key, entry in _load()["reports"].items():
        assert {c["status"] for c in entry["controls"]} == {"proposed"}, key
        assert "Proposed mapping" in entry["methodology"], key


def test_methodology_gives_a_rationale_per_mapping():
    for key, entry in _load()["reports"].items():
        for c in entry["controls"]:
            assert c["id"] in entry["methodology"], (key, c["id"])


def test_list_reports_carries_controls_status_and_derived_grouping():
    reports = {r["key"]: r for r in audit_store.list_reports()}
    assert set(reports) == set(audit_store.COMPLIANCE_REPORTS)
    for key, r in reports.items():
        assert r["controls"] and r["mapping_status"] == "proposed"
        assert r["control"] == r["controls"][0]["id"].split(".")[0]
        assert r["control"] in ("CC6", "CC7", "CC8")
    # Owner decision: these two moved from change management to access controls.
    for key in ("api_token_lifecycle", "credential_rotation"):
        assert reports[key]["control"] == "CC6"
        assert [c["id"] for c in reports[key]["controls"]] == ["CC6.1"]
    assert reports["policy_modifications"]["control"] == "CC8"
    assert reports["pam_policy_modifications"]["control"] == "CC8"


def test_catalogue_ships_in_the_release():
    # tools/release.py builds the tarball with `git archive`; the file must be tracked and not export-ignored.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert os.path.isfile(os.path.join(root, "server", "control_catalogue.json"))
    attrs = os.path.join(root, ".gitattributes")
    if os.path.isfile(attrs):
        with open(attrs, encoding="utf-8") as fh:
            assert "export-ignore" not in fh.read()
