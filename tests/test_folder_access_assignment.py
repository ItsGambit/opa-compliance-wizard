"""Covers create_secret_folders.upsert_folder_rule_in_policy (UI-01,
external review, 2026-10-05): "Assign access" used to replace a folder's
existing rule wholesale from a form that starts blank -- silently
dropping an MFA condition, any OTHER condition type the form has no UI
for at all, and -- the worst case -- every OTHER folder a shared rule's
selector also named, since the replacement rule's selector only ever
lists the one folder being assigned.

Fixes:
- upsert_folder_rule_in_policy raises MultiTargetRuleError when the
  matched rule's selector names more than one folder -- there is no safe
  single-folder-form replacement for a shared rule.
- Any non-mfa condition on the matched rule is always carried over
  (the form has no field for those at all); the mfa condition is exactly
  what the caller's `mfa` argument says, since the frontend now prefills
  that checkbox from the existing rule instead of defaulting to off.
"""
import pytest

import create_secret_folders as engine

FOLDER_A = "folder-a-id"
FOLDER_B = "folder-b-id"


def _policy_with_rule(selectors, conditions=None, privileges=None):
    return {
        "name": "P",
        "rules": [
            {
                "name": "existing-rule",
                "resource_type": "secret_based_resource",
                "resource_selector": {"_type": "secret_based_resource", "selectors": selectors},
                "privileges": privileges or [{"privilege_type": "secret", "privilege_value": {"_type": "secret", "list": True}}],
                "conditions": conditions or [],
            }
        ],
    }


def _folder_selector(folder_id, name="Folder"):
    return {"selector_type": "secret_folder", "selector": {"_type": "secret_folder", "secret_folder": {"id": folder_id, "name": name}}}


def test_replacing_a_single_target_rule_works_normally():
    policy = _policy_with_rule([_folder_selector(FOLDER_A)])
    engine.upsert_folder_rule_in_policy(policy, FOLDER_A, "Folder A", "new-name", {"list": True})
    assert len(policy["rules"]) == 1
    assert policy["rules"][0]["name"] == "new-name"


def test_multi_target_rule_raises_instead_of_silently_dropping_other_folders():
    """The exact scenario the review describes: a rule covers folders A
    and B. Assigning access to A alone must refuse, not silently narrow
    the rule to A and drop B's access."""
    policy = _policy_with_rule([_folder_selector(FOLDER_A), _folder_selector(FOLDER_B)])
    with pytest.raises(engine.MultiTargetRuleError):
        engine.upsert_folder_rule_in_policy(policy, FOLDER_A, "Folder A", "new-name", {"list": True})
    # Nothing was mutated -- the raise happens before any rule is touched.
    assert len(policy["rules"]) == 1
    assert len(policy["rules"][0]["resource_selector"]["selectors"]) == 2


def test_non_mfa_condition_on_the_matched_rule_is_always_preserved():
    """The form has no field for a gateway/access-request condition at
    all -- there's nothing the caller could have meant to replace it
    with, so it must survive every replace unconditionally."""
    gateway_condition = {"condition_type": "gateway", "condition_value": {"_type": "gateway", "gateway_id": "gw-1"}}
    policy = _policy_with_rule([_folder_selector(FOLDER_A)], conditions=[gateway_condition])

    engine.upsert_folder_rule_in_policy(policy, FOLDER_A, "Folder A", "new-name", {"list": True}, mfa=None)

    assert gateway_condition in policy["rules"][0]["conditions"]


def test_mfa_true_adds_an_mfa_condition():
    policy = _policy_with_rule([_folder_selector(FOLDER_A)])
    engine.upsert_folder_rule_in_policy(
        policy, FOLDER_A, "Folder A", "new-name", {"list": True},
        mfa={"reauth_seconds": 1800, "acr_values": "urn:okta:loa:2fa:any"},
    )
    conditions = policy["rules"][0]["conditions"]
    assert len(conditions) == 1
    assert conditions[0]["condition_type"] == "mfa"


def test_mfa_false_clears_an_existing_mfa_condition_but_keeps_others():
    """A real user choice (the dialog's "Require MFA" checkbox, now
    prefilled from the existing rule -- unchecking it is an intentional
    "turn it off," not an accidental drop) -- confirmed it does NOT touch
    a non-mfa condition on the same rule."""
    mfa_condition = {"condition_type": "mfa", "condition_value": {"_type": "mfa", "re_auth_frequency_in_seconds": 0, "acr_values": "x"}}
    gateway_condition = {"condition_type": "gateway", "condition_value": {"_type": "gateway", "gateway_id": "gw-1"}}
    policy = _policy_with_rule([_folder_selector(FOLDER_A)], conditions=[mfa_condition, gateway_condition])

    engine.upsert_folder_rule_in_policy(policy, FOLDER_A, "Folder A", "new-name", {"list": True}, mfa=None)

    conditions = policy["rules"][0]["conditions"]
    assert gateway_condition in conditions
    assert all(c["condition_type"] != "mfa" for c in conditions)


def test_creating_a_new_rule_in_an_empty_policy_is_unaffected():
    policy = {"name": "P", "rules": []}
    engine.upsert_folder_rule_in_policy(policy, FOLDER_A, "Folder A", "new-rule", {"list": True})
    assert len(policy["rules"]) == 1
    assert policy["rules"][0]["conditions"] == []


def test_appending_a_rule_for_an_unrelated_folder_does_not_touch_the_existing_one():
    gateway_condition = {"condition_type": "gateway", "condition_value": {"_type": "gateway", "gateway_id": "gw-1"}}
    policy = _policy_with_rule([_folder_selector(FOLDER_A)], conditions=[gateway_condition])

    engine.upsert_folder_rule_in_policy(policy, FOLDER_B, "Folder B", "second-rule", {"list": True})

    assert len(policy["rules"]) == 2
    assert policy["rules"][0]["conditions"] == [gateway_condition]  # original untouched
    assert policy["rules"][1]["conditions"] == []  # new rule, nothing to preserve
