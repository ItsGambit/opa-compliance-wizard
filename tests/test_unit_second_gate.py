"""Covers server/unit_second_gate.py (5.38.2). Regression: 5.38.1's sed edits skipped INDENTED unit
lines, so on a server whose live unit was indented the second gate kept the main EnvironmentFile
(main org, shared session key). Both the repo template and an indented copy must come out right."""
from pathlib import Path

import pytest

from server.unit_second_gate import MAIN_ENV, build

TEMPLATE = (Path(__file__).resolve().parent.parent / "server" / "opa-auth-gate.service").read_text()
INDENTED = "\n".join(("  " + l) if l else l for l in TEMPLATE.splitlines()) + "\n"
ARGS = dict(env_file="/etc/opa-compliance-wizard-second.env", port=8768,
            key_dir="/etc/opa-auth-gate-second", description="OPA auth gate 'second'")


def active(text):
    return [l for l in text.splitlines() if l and not l.startswith(("#", ";"))]


@pytest.mark.parametrize("main", [TEMPLATE, INDENTED], ids=["repo-template", "indented-live-unit"])
def test_points_at_the_new_env_file_only(main):
    lines = active(build(main, **ARGS))
    assert lines.count("EnvironmentFile=/etc/opa-compliance-wizard-second.env") == 1
    assert not any(MAIN_ENV in l for l in lines)


@pytest.mark.parametrize("main", [TEMPLATE, INDENTED], ids=["repo-template", "indented-live-unit"])
def test_port_key_dir_and_description(main):
    lines = active(build(main, **ARGS))
    exec_start = [l for l in lines if l.startswith("ExecStart=")]
    assert len(exec_start) == 1 and exec_start[0].endswith("server/auth_gate.py --port 8768")
    assert "ReadWritePaths=/etc/opa-auth-gate-second" in lines
    assert "Description=OPA auth gate 'second'" in lines
    assert "After=network.target opa-compliance-wizard.service opa-auth-gate.service" in lines


@pytest.mark.parametrize("main", [TEMPLATE, INDENTED], ids=["repo-template", "indented-live-unit"])
def test_keeps_user_and_hardening(main):
    out = active(build(main, **ARGS))
    for key in ("User=", "WorkingDirectory=", "NoNewPrivileges=", "ProtectHome=", "UMask=", "WantedBy="):
        assert sum(l.startswith(key) for l in out) == sum(l.strip().startswith(key) for l in main.splitlines()
                                                          if not l.strip().startswith("#"))
    assert all(l == l.strip() for l in out), "output must be unindented"


def test_collapses_multiple_env_files():
    main = TEMPLATE.replace(f"EnvironmentFile={MAIN_ENV}", f"EnvironmentFile={MAIN_ENV}\nEnvironmentFile=-/etc/extra.env")
    lines = active(build(main, **ARGS))
    assert [l for l in lines if l.startswith("EnvironmentFile=")] == ["EnvironmentFile=/etc/opa-compliance-wizard-second.env"]


@pytest.mark.parametrize("bad", [dict(port=8767), dict(port="80; x"), dict(env_file=MAIN_ENV),
                                 dict(key_dir="relative"), dict(description="a\nExecStartPre=/bin/sh")])
def test_rejects_bad_parameters(bad):
    with pytest.raises(ValueError):
        build(TEMPLATE, **{**ARGS, **bad})


def test_requires_one_gate_exec_start():
    with pytest.raises(ValueError):
        build(TEMPLATE.replace("server/auth_gate.py", "server/other.py"), **ARGS)
