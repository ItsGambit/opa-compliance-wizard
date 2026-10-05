"""Covers server/gate_config.py (5.38.0): choosing the Okta authorization server
and giving each auth gate instance its own session key, so a second gate can
serve a second Okta org on the same server without sharing sessions."""
from pathlib import Path

import pytest

from server.gate_config import DEFAULT_SESSION_KEY_PATH, access_control_path, okta_endpoints, session_key_path


def test_default_authorization_server_is_unchanged():
    e = okta_endpoints("https://example.oktapreview.com")
    assert e["issuer"] == "https://example.oktapreview.com/oauth2/default"
    assert e["authorize"] == "https://example.oktapreview.com/oauth2/default/v1/authorize"
    assert e["token"] == "https://example.oktapreview.com/oauth2/default/v1/token"
    assert e["jwks"] == "https://example.oktapreview.com/oauth2/default/v1/keys"
    assert e["logout"] == "https://example.oktapreview.com/oauth2/default/v1/logout"


def test_org_authorization_server_uses_the_org_url_as_issuer():
    e = okta_endpoints("https://login.example.com", "org")
    assert e["issuer"] == "https://login.example.com"
    assert e["authorize"] == "https://login.example.com/oauth2/v1/authorize"
    assert e["jwks"] == "https://login.example.com/oauth2/v1/keys"
    assert e["logout"] == "https://login.example.com/oauth2/v1/logout"


def test_custom_authorization_server_by_id():
    e = okta_endpoints("https://login.example.com", "aus123abc")
    assert e["issuer"] == "https://login.example.com/oauth2/aus123abc"
    assert e["token"] == "https://login.example.com/oauth2/aus123abc/v1/token"


@pytest.mark.parametrize("bad", ["", "../keys", "default/v1", "a b", "x" * 65])
def test_rejects_malformed_authorization_server(bad):
    with pytest.raises(RuntimeError):
        okta_endpoints("https://login.example.com", bad)


def test_session_key_path_defaults_to_the_existing_file():
    assert session_key_path({}) == Path(DEFAULT_SESSION_KEY_PATH)
    assert session_key_path({"OPA_SESSION_KEY_PATH": ""}) == Path(DEFAULT_SESSION_KEY_PATH)


def test_session_key_path_is_configurable_per_gate():
    assert session_key_path({"OPA_SESSION_KEY_PATH": "/etc/opa-gate-second.key"}) == Path("/etc/opa-gate-second.key")


def test_session_key_path_must_be_absolute():
    with pytest.raises(RuntimeError):
        session_key_path({"OPA_SESSION_KEY_PATH": "relative.key"})


DEFAULT_AC = Path("/home/app/opa/access_control.json")


def test_access_control_path_defaults_to_the_app_file():
    assert access_control_path({}, DEFAULT_AC) == DEFAULT_AC
    assert access_control_path({"OPA_ACCESS_CONTROL_PATH": ""}, DEFAULT_AC) == DEFAULT_AC


def test_access_control_path_is_configurable_per_gate():
    env = {"OPA_ACCESS_CONTROL_PATH": "/etc/opa-auth-gate-second/access_control.json"}
    assert access_control_path(env, DEFAULT_AC) == Path("/etc/opa-auth-gate-second/access_control.json")


def test_access_control_path_must_be_absolute():
    with pytest.raises(RuntimeError):
        access_control_path({"OPA_ACCESS_CONTROL_PATH": "access_control.json"}, DEFAULT_AC)
