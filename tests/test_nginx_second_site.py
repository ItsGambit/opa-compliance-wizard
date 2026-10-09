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


# ---------------------------------------------------------------------------
# GATE-15 (5.40.5): comment- and quote-aware block scanning, loopback-only
# listen unless explicitly allowed.
# ---------------------------------------------------------------------------
from server.nginx_second_site import _location_blocks, _structure  # noqa: E402

TRICKY = """# a comment mentioning server { and } braces, and server_name evil;
limit_req_zone $binary_remote_addr zone=z:1m rate=1r/s;  # trailing comment with {
server {
    listen 80;  # } not a closing brace
    return 301 https://$server_name$request_uri;
}
server {
    listen 443 ssl;
    server_name main.example.com;
    set $nginx_proxy_secret "s3cr3t#{not}a;comment";
    add_header X-Test "a } b" always;
    # location /api/access_control/save { return 200; }
    location /api/access_control/save {
        proxy_pass http://127.0.0.1:8767;
    }
    location / {
        proxy_pass http://127.0.0.1:8767/x#frag;
        set $v "${host}";
    }
}
"""


def test_server_blocks_ignore_braces_and_keywords_in_comments_and_strings():
    blocks = server_blocks(TRICKY)
    assert len(blocks) == 2
    assert blocks[0].startswith("server {") and "listen 80;" in blocks[0]
    assert blocks[1].startswith("server {") and blocks[1].rstrip().endswith("}")
    assert 's3cr3t#{not}a;comment' in blocks[1]  # original text kept verbatim


def test_location_blocks_ignore_commented_out_locations():
    https = server_blocks(TRICKY)[1]
    paths = [p for p, _ in _location_blocks(https)]
    assert paths == ["/api/access_control/save", "/"]


def test_structure_keeps_length_and_blanks_only_comments_and_string_bodies():
    s = _structure(TRICKY)
    assert len(s) == len(TRICKY)
    assert "server_name evil" not in s
    assert "s3cr3t" not in s and '"' in s
    assert "http://127.0.0.1:8767/x#frag;" in s  # '#' inside a token is not a comment


def test_build_handles_the_tricky_site_and_keeps_the_secret():
    site = build(TRICKY, 8768, "127.0.0.1:8080", "opa.example.com", "second")
    assert 'set $nginx_proxy_secret "s3cr3t#{not}a;comment";' in site
    assert "location /api/access_control {" in site
    assert len(server_blocks(site)) == 1


@pytest.mark.parametrize("bad", ["server { listen 443 ssl; ", "server { listen 443 ssl; } }"])
def test_unbalanced_braces_are_refused(bad):
    with pytest.raises(ValueError):
        server_blocks(bad)


@pytest.mark.parametrize("listen", ["0.0.0.0:8080", "192.168.1.5:8080", "10.0.0.1:80"])
def test_non_loopback_listen_needs_explicit_opt_in(listen):
    with pytest.raises(ValueError, match="not loopback"):
        build(MAIN, 8768, listen, "opa.example.com", "x")
    site = build(MAIN, 8768, listen, "opa.example.com", "x", allow_public_listen=True)
    assert f"listen {listen};" in site


@pytest.mark.parametrize("listen", ["127.0.0.1:8080", "127.0.0.2:9000"])
def test_loopback_listen_is_accepted(listen):
    assert f"listen {listen};" in build(MAIN, 8768, listen, "opa.example.com", "x")


def test_cli_accepts_only_the_public_listen_flag(tmp_path):
    import subprocess
    import sys

    src = tmp_path / "main"
    src.write_text(MAIN)
    script = Path(__file__).resolve().parent.parent / "server" / "nginx_second_site.py"
    base = [sys.executable, str(script), str(src), str(tmp_path / "out"), "8768"]
    assert subprocess.run(base + ["0.0.0.0:8080", "h.example.com", "x"], capture_output=True).returncode != 0
    assert subprocess.run(base + ["0.0.0.0:8080", "h.example.com", "x", "--allow-public-listen"],
                          capture_output=True).returncode == 0
    assert subprocess.run(base + ["127.0.0.1:8080", "h.example.com", "x", "--bogus"],
                          capture_output=True).returncode != 0


# Opus review follow-ups (5.40.5): directives not at line start, location
# modifiers, and a regex location that could shadow the GATE-04 deny.
def test_listen_and_server_name_on_one_line_are_rewritten():
    one_line = "server { listen 443 ssl; server_name main.example.com; location / { proxy_pass http://127.0.0.1:8767; } }"
    site = build(one_line, 8768, "127.0.0.1:8080", "opa.example.com", "x")
    assert "listen 443" not in site and "listen 127.0.0.1:8080;" in site
    assert "server_name opa.example.com;" in site


def test_commented_listen_is_not_rewritten_but_the_real_one_is():
    text = "server {\n    # listen 443 ssl; (old)\n    listen 443 ssl;\n    server_name m.example.com;\n}\n"
    site = build(text, 8768, "127.0.0.1:8080", "opa.example.com", "x")
    assert "# listen 443 ssl; (old)" in site and "    listen 127.0.0.1:8080;" in site


@pytest.mark.parametrize("modifier", ["^~ ", "= "])
def test_save_location_with_any_modifier_is_removed(modifier):
    text = ("server { listen 443 ssl; server_name m.example.com;\n"
            f"  location {modifier}/api/access_control/save {{ proxy_pass http://127.0.0.1:8766; }}\n"
            "  location / { proxy_pass http://127.0.0.1:8766; } }")
    site = build(text, 8768, "127.0.0.1:8080", "opa.example.com", "x")
    assert "/api/access_control/save" not in _structure(site)


def test_regex_location_touching_access_control_is_refused():
    text = ("server { listen 443 ssl; server_name m.example.com;\n"
            "  location ~ ^/api/access_control/(save|x)$ { proxy_pass http://127.0.0.1:8766; }\n"
            "  location / { proxy_pass http://127.0.0.1:8766; } }")
    with pytest.raises(ValueError, match="shadow"):
        build(text, 8768, "127.0.0.1:8080", "opa.example.com", "x")


def test_location_blocks_see_regex_and_caret_tilde_modifiers():
    block = "server { location ~ \\.js$ { add_header X 1; } location ^~ /a { } location ~* x { } location = /b { } }"
    assert [p for p, _ in _location_blocks(block)] == ["\\.js$", "/a", "x", "/b"]


def test_build_refuses_when_the_listen_rewrite_did_not_happen(monkeypatch):
    """Backstop: if the rewrite ever misses (a future template shape), build()
    refuses instead of emitting a site that still listens on 443."""
    import server.nginx_second_site as nss

    real = nss._replace_directive
    monkeypatch.setattr(nss, "_replace_directive",
                        lambda block, pattern, replacement: block if pattern.startswith("listen") else
                        real(block, pattern, replacement))
    with pytest.raises(ValueError, match="listen directive was not rewritten"):
        build(MAIN, 8768, "127.0.0.1:8080", "opa.example.com", "x")


def test_server_name_variable_is_not_mistaken_for_the_directive():
    text = ("server { listen 443 ssl; server_name m.example.com;\n"
            "  add_header X-Host $server_name always;\n"
            "  location / { proxy_pass http://127.0.0.1:8766; } }")
    site = build(text, 8768, "127.0.0.1:8080", "opa.example.com", "x")
    assert "add_header X-Host $server_name always;" in site
    assert "server_name opa.example.com;" in site


def test_quoted_regex_location_is_seen_and_refused():
    assert [p for p, _ in _location_blocks('server { location ~ "^/x y" { } location / { } }')] == ["^/x y", "/"]
    text = ("server { listen 443 ssl; server_name m.example.com;\n"
            '  location ~ "^/api/access_control" { proxy_pass http://127.0.0.1:8766; }\n'
            "  location / { proxy_pass http://127.0.0.1:8766; } }")
    with pytest.raises(ValueError, match="shadow"):
        build(text, 8768, "127.0.0.1:8080", "opa.example.com", "x")
