"""Covers server/nginx_second_site.py (5.38.1), using the repo's real nginx template as the
"main site": the additional gate's site must keep every protection of the main site and only
change where it listens, its hostname, TLS handling, and which gate the sign-in routes use."""
import re
from pathlib import Path

import pytest

from server.nginx_second_site import build, server_blocks

TEMPLATE = (Path(__file__).resolve().parent.parent / "server" / "nginx-opa-secrets-wizard.conf").read_text()
MAIN = TEMPLATE.replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", "s3cr3t-live-value")


@pytest.fixture
def site():
    return build(MAIN, 8768, "127.0.0.1:8080", "opa.example.com", "second")


def test_single_server_block_listening_on_loopback(site):
    assert len(server_blocks(site)) == 1
    assert re.findall(r"listen\s+[^;]+;", site) == ["listen 127.0.0.1:8080;"]
    assert "server_name opa.example.com;" in site


def test_tls_is_left_to_the_front(site):
    assert not re.search(r"^\s*ssl_", site, re.M)
    assert "X-Forwarded-Proto $scheme" not in site
    assert "X-Forwarded-Proto https" in site


def test_sign_in_routes_use_the_additional_gate(site):
    main_gate_routes = len(re.findall(r"127\.0\.0\.1:8767", MAIN))
    assert main_gate_routes >= 5
    assert "127.0.0.1:8767" not in site
    assert len(re.findall(r"127\.0\.0\.1:8768", site)) == main_gate_routes


def test_backend_auth_rules_and_secret_are_kept(site):
    # GATE-04: the main site's /api/access_control/save location (one of
    # the main site's two proxy_pass-to-8766 routes) is dropped entirely --
    # replaced by a flat deny -- so the additional gate's site proxies to
    # 8766 one route fewer than the main site. See
    # test_access_control_is_denied_entirely below for the actual
    # cross-org privilege-escalation fix this is testing.
    assert site.count("127.0.0.1:8766") == MAIN.count("127.0.0.1:8766") - 1
    assert 'set $nginx_proxy_secret "s3cr3t-live-value";' in site
    https_block = [b for b in server_blocks(MAIN) if re.search(r"listen\s+443", b)][0]
    # auth_request /verify_stepup and the step-up X-Auth-Action-Id plumbing
    # lived ONLY in the now-removed /api/access_control/save block.
    assert site.count("auth_request /verify;") == https_block.count("auth_request /verify;")
    assert site.count("auth_request /verify_stepup;") == 0
    assert https_block.count("auth_request /verify_stepup;") >= 1


# ---------------------------------------------------------------------------
# GATE-04 (external review, 2026-10-05): an additional gate shares the SAME
# backend as the main gate -- serve.py has no notion of which gate
# authenticated a request -- so a user admin in the SECOND org's admin
# group used to be a full admin of the shared backend, including the MAIN
# org's own access_control.json (admin group, user group, restrict_login).
# The dashboard's Access control page only ever edits that one, default
# file, so there's no "this gate's own access control" to redirect writes
# to instead -- the fix is to make the whole route unreachable from an
# additional gate's hostname.
# ---------------------------------------------------------------------------
def test_access_control_is_denied_entirely(site):
    assert "location /api/access_control {" in site
    assert re.search(r"location /api/access_control \{\s*return 403;", site)
    # The main site's own, more specific .../save location must NOT
    # survive -- nginx matches the LONGEST prefix location, so if it did,
    # it would win over the blanket deny for exactly the one route (the
    # write endpoint) that matters most.
    assert "location /api/access_control/save" not in site


@pytest.mark.parametrize("kwargs", [
    {"gate_port": 8767}, {"gate_port": 8766}, {"gate_port": "80; evil"},
    {"listen": "0.0.0.0:8080; include /etc/passwd"}, {"host": "opa.example.com; return 200"},
])
def test_rejects_bad_parameters(kwargs):
    args = {"gate_port": 8768, "listen": "127.0.0.1:8080", "host": "opa.example.com", "name": "x", **kwargs}
    with pytest.raises(ValueError):
        build(MAIN, **args)


def test_requires_exactly_one_https_block():
    with pytest.raises(ValueError):
        build("server { listen 80; }", 8768, "127.0.0.1:8080", "opa.example.com", "x")
