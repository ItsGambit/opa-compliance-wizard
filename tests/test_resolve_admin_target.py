"""Covers environment_storage_name + _resolve_admin_target -- the
admin-override lookup that must disambiguate two different owners' same-
named environments by environment_id, not by a potentially-ambiguous
by-name scan. See docs/fast-follow-redesign.md's Phase 7 for why this is
one of the functions named as having the most direct history of silent
breakage (the original F1/F2/F3 cross-tenant bugs, external review,
2026-09-30)."""
import pytest

import create_secret_folders as engine


def test_environment_storage_name_namespaces_by_owner():
    assert engine.environment_storage_name(None, "dev") == "__local__::dev"
    assert engine.environment_storage_name("00uOWNERB", "dev") == "00uOWNERB::dev"


def test_resolve_admin_target_prefers_explicit_environment_id():
    data = {
        "environments": {
            "__local__::dev": {"owner": None, "base_domain": "a.example.com"},
            "00uOWNERB::dev": {"owner": "00uOWNERB", "base_domain": "b.example.com"},
        }
    }
    storage_name, meta = engine._resolve_admin_target(data, "dev", "00uOWNERB::dev")
    assert storage_name == "00uOWNERB::dev"
    assert meta["base_domain"] == "b.example.com"

    storage_name, meta = engine._resolve_admin_target(data, "dev", "__local__::dev")
    assert storage_name == "__local__::dev"
    assert meta["base_domain"] == "a.example.com"


def test_resolve_admin_target_raises_on_unknown_environment_id():
    data = {"environments": {"__local__::dev": {"owner": None}}}
    with pytest.raises(KeyError):
        engine._resolve_admin_target(data, "dev", "nonexistent::dev")


def test_resolve_admin_target_falls_back_to_ambiguous_scan_without_id():
    """Legacy path only -- deliberately NOT asserting WHICH of the two
    same-named environments wins, since _find_environment_by_name's
    first-match-wins dict iteration order is explicitly documented as
    non-deterministic across owners. New code should always pass
    environment_id; this test only proves the fallback resolves to SOME
    real entry rather than raising, matching backward-compat intent."""
    data = {
        "environments": {
            "__local__::dev": {"owner": None},
            "00uOWNERB::dev": {"owner": "00uOWNERB"},
        }
    }
    storage_name, meta = engine._resolve_admin_target(data, "dev", None)
    assert storage_name in ("__local__::dev", "00uOWNERB::dev")
    assert meta is not None


def test_resolve_admin_target_raises_when_name_not_found_at_all():
    data = {"environments": {}}
    with pytest.raises(KeyError):
        engine._resolve_admin_target(data, "dev", None)
