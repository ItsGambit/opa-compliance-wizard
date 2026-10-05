"""Builds the systemd unit for an additional auth gate (server/setup-second-gate.sh, 5.38.2).

Starts from the LIVE main gate unit (/etc/systemd/system/opa-auth-gate.service) and changes exactly:
Description, After, EnvironmentFile (exactly one, the new gate's), the --port of the auth_gate.py
ExecStart, and one extra ReadWritePaths= for the new gate's session-key folder. Everything else
(user, working dir, hardening, keyring paths) is kept.

Handles indented units: systemd accepts leading whitespace, and a hand-installed unit may have it.
5.38.1 used anchored sed patterns that silently skipped indented lines, which left the second gate
on the MAIN env file (same org, same session key). The output is always written unindented and is
validated before it's returned, so that failure mode can't recur silently.

Usage: python3 server/unit_second_gate.py <main unit> <output> <env file> <port> <key dir> <description>
"""
import re
import sys

MAIN_ENV = "/etc/opa-compliance-wizard.env"


def build(main_unit, env_file, port, key_dir, description):
    if not re.fullmatch(r"[0-9]{4,5}", str(port)) or str(port) in ("8766", "8767"):
        raise ValueError(f"bad gate port {port!r}")
    for value in (env_file, key_dir):
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", value) or value == MAIN_ENV:
            raise ValueError(f"bad path {value!r}")
    if "\n" in description:
        raise ValueError("description must be one line")

    out, section, exec_starts, env_written, rw_index = [], None, 0, False, None
    for raw in main_unit.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        key = line.split("=", 1)[0] if "=" in line and not line.startswith(("#", ";")) else None
        if key == "Description":
            line = f"Description={description}"
        elif key == "After" and section == "[Unit]":
            line = "After=network.target opa-compliance-wizard.service opa-auth-gate.service"
        elif key == "EnvironmentFile":
            if env_written:
                continue                      # collapse to exactly one EnvironmentFile
            line, env_written = f"EnvironmentFile={env_file}", True
        elif key == "ExecStart" and "auth_gate.py" in line:
            exec_starts += 1
            if not re.search(r"--port\s+[0-9]+", line):
                raise ValueError("main ExecStart has no --port")
            line = re.sub(r"--port\s+[0-9]+", f"--port {port}", line)
        elif key == "ReadWritePaths" and section == "[Service]":
            rw_index = len(out)
        out.append(line)

    if exec_starts != 1:
        raise ValueError(f"expected exactly one auth_gate.py ExecStart, found {exec_starts}")
    if not env_written:
        raise ValueError("main unit has no EnvironmentFile")
    extra = f"ReadWritePaths={key_dir}"
    if rw_index is None:
        out.insert(next(i for i, l in enumerate(out) if l.startswith("ExecStart=")) + 1, extra)
    else:
        out.insert(rw_index + 1, extra)

    text = "\n".join(out).rstrip("\n") + "\n"
    active = [l for l in text.splitlines() if l and not l.startswith(("#", ";"))]
    assert active.count(f"EnvironmentFile={env_file}") == 1
    assert not any(MAIN_ENV in l for l in active), "the main env file is still referenced"
    assert any(l.startswith("ExecStart=") and f"--port {port}" in l for l in active)
    return text


if __name__ == "__main__":
    src, dst, env_file, port, key_dir, description = sys.argv[1:7]
    out = build(open(src).read(), env_file, port, key_dir, description)
    with open(dst, "w") as f:
        f.write(out)
