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
    assert site.count("127.0.0.1:8766") == MAIN.count("127.0.0.1:8766")
    assert 'set $nginx_proxy_secret "s3cr3t-live-value";' in site
    https_block = [b for b in server_blocks(MAIN) if re.search(r"listen\s+443", b)][0]
    for rule in ("auth_request /verify;", "auth_request /verify_stepup;", "X-Nginx-Proxy-Secret"):
        assert site.count(rule) == https_block.count(rule)


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
