"""server/nginx_bake.py: the live site's own values carried into the public
template before deploy.sh applies it (OPS-02 third-party installs, OPS-09)."""

import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import nginx_bake  # noqa: E402

TEMPLATE = (Path(__file__).resolve().parent.parent / "server" / "nginx-opa-secrets-wizard.conf").read_text()
SECRET = "a&b\\1$x"


def _live(template=TEMPLATE, name="opa.example.test", secret=SECRET, crt="/etc/ssl/mine.crt"):
    return (template.replace("REPLACE_WITH_SERVER_NAME", name)
            .replace("REPLACE_WITH_NGINX_PROXY_SECRET_VALUE", secret)
            .replace("/etc/nginx/ssl/opa-secrets-wizard.crt", crt))


def test_the_template_has_no_server_specific_values():
    assert "REPLACE_WITH_SERVER_NAME" in TEMPLATE and "REPLACE_WITH_NGINX_PROXY_SECRET_VALUE" in TEMPLATE
    assert "192.168." not in TEMPLATE


def test_secret_names_and_certificate_paths_come_from_the_live_site():
    live = _live()
    baked, problems = nginx_bake.bake(live, TEMPLATE)
    assert problems == []
    assert baked == live  # same layout: the result IS the live site
    assert f'set $nginx_proxy_secret "{SECRET}";' in baked


def test_template_changes_are_kept_while_the_values_are_carried():
    live = _live(name="a.example b.example")
    newer_template = TEMPLATE.replace("server_tokens off;", "server_tokens off;\n    # a new hardening line")
    baked, problems = nginx_bake.bake(live, newer_template)
    assert problems == []
    assert "# a new hardening line" in baked
    assert baked.count("server_name a.example b.example;") == 2
    assert "ssl_certificate /etc/ssl/mine.crt;" in baked and "REPLACE_WITH" not in baked.replace("# ", "")


@pytest.mark.parametrize("live,needle", [
    (lambda: _live().replace("    server_name opa.example.test;\n", "", 1), "`server_name` appears 1 time"),
    (lambda: _live(secret="REPLACE_WITH_NGINX_PROXY_SECRET_VALUE"), "no real NGINX_PROXY_SECRET"),
    (lambda: _live(secret=""), "no real NGINX_PROXY_SECRET"),
    (lambda: "server { listen 443 ssl; server_name x; }\n", "expected one `set $nginx_proxy_secret`"),
])
def test_a_live_site_with_another_layout_is_refused(live, needle):
    _, problems = nginx_bake.bake(live(), TEMPLATE)
    assert any(needle in p for p in problems), problems


def test_comments_and_the_server_name_variable_are_not_directives():
    pattern = nginx_bake._directive_re("server_name")
    text = "  # server_name commented.example;\n  return 301 https://$server_name$request_uri;\n  server_name real.example;\n"
    assert [m.group(2) for m in pattern.finditer(text)] == ["real.example"]
    assert nginx_bake._directive_re("ssl_certificate").findall("ssl_certificate_key /k;\n") == []


def test_cli_writes_owner_only_and_refuses_without_touching_the_template(tmp_path, capsys):
    live, template = tmp_path / "live", tmp_path / "template"
    live.write_text(_live())
    template.write_text(TEMPLATE)
    template.chmod(0o664)
    assert nginx_bake.main(["x", str(live), str(template)]) == 0
    assert template.read_text() == _live()
    assert stat.S_IMODE(template.stat().st_mode) == 0o600
    template.write_text(TEMPLATE)
    live.write_text("server {}\n")
    assert nginx_bake.main(["x", str(live), str(template)]) == 3
    assert template.read_text() == TEMPLATE
    assert "not applying" in capsys.readouterr().err
    assert list(tmp_path.glob(".nginx-bake-*")) == []


def test_any_placeholder_left_in_the_result_is_refused():
    template = TEMPLATE.replace("server_tokens off;", "server_tokens off;\n    ssl_dhparam REPLACE_WITH_DHPARAM;")
    _, problems = nginx_bake.bake(_live(), template)
    assert any("placeholder would be left" in p for p in problems), problems
    # ...but a placeholder mentioned in a comment is fine
    commented = TEMPLATE.replace("server_tokens off;", "server_tokens off;\n    # e.g. REPLACE_WITH_THING")
    assert nginx_bake.bake(_live(), commented)[1] == []


def test_check_mode_reports_without_writing(tmp_path):
    live, template = tmp_path / "live", tmp_path / "template"
    live.write_text(_live())
    template.write_text(TEMPLATE)
    assert nginx_bake.main(["x", "--check", str(live), str(template)]) == 0
    assert template.read_text() == TEMPLATE
    live.write_text("server {}\n")
    assert nginx_bake.main(["x", "--check", str(live), str(template)]) == 3
