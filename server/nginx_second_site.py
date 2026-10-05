"""Builds the nginx site for an additional auth gate (server/setup-second-gate.sh, 5.38.1).

Starts from the LIVE main site (so the real NGINX_PROXY_SECRET line is copied, never typed or
templated), keeps only its HTTPS server block, and:
- listens on the given address (loopback for a Cloudflare Tunnel by default),
- answers to the new hostname,
- drops the ssl_* lines (TLS ends in front of this site, e.g. at Cloudflare) and sends
  X-Forwarded-Proto https accordingly,
- points every route that went to the main gate (127.0.0.1:8767) at the additional gate.
The backend (127.0.0.1:8766), auth_request rules and the proxy secret stay exactly as in the main site.

Usage: python3 server/nginx_second_site.py <main site> <output> <gate port> <listen> <host> <name>
"""
import re
import sys

MAIN_GATE = "127.0.0.1:8767"


def server_blocks(text):
    """Top-level `server { ... }` blocks, in order."""
    blocks, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if depth == 0 and start is None and text.startswith("server", i):
            start = i
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                blocks.append(text[start:i + 1])
                start = None
    return blocks


def _location_blocks(text):
    """Every `location <path-or-pattern> { ... }` block inside `text` (one
    nesting level -- good enough for this project's own flat nginx
    template), as (path, full_block_text) pairs. Brace-depth tracked from
    the block's own opening `{` so a path containing `{`/`}` (never happens
    here, but this stays correct regardless) can't desync the scan."""
    out = []
    for m in re.finditer(r"location\s+(=\s+)?(\S+)\s*\{", text):
        path = m.group(2)
        depth = 0
        i = m.end() - 1  # the matched opening brace
        start = m.start()
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    out.append((path, text[start:j + 1]))
                    break
    return out



# GATE-04 (external review, 2026-10-05): an additional gate shares the SAME
# backend (serve.py has no notion of which gate authenticated a request --
# see gate_config.py's docstring), so without this block, a user admin in
# the SECOND org's admin group is a full admin of the shared backend,
# including the MAIN org's own access_control.json (admin group, user
# group, restrict_login) -- a cross-org privilege escalation if the two
# orgs have different trust levels. The dashboard's Access control page
# only ever edits the one, default access_control.json (see serve.py), so
# there is no "this gate's own access control" for it to edit instead --
# the simplest and safest fix is to make these three routes unreachable
# from an additional gate's hostname entirely.
_ACCESS_CONTROL_BLOCK = (
    "\n    # GATE-04: access_control.json belongs to the MAIN org only --\n"
    "    # see server/nginx_second_site.py's module comment.\n"
    "    location /api/access_control {\n"
    "        return 403;\n"
    "    }\n"
)


def build(main_site, gate_port, listen, host, name):
    https = [b for b in server_blocks(main_site) if re.search(r"listen\s+443", b)]
    if len(https) != 1:
        raise ValueError(f"expected exactly one HTTPS server block in the main site, found {len(https)}")
    if not re.fullmatch(r"[0-9]{4,5}", str(gate_port)) or str(gate_port) in ("8766", "8767"):
        raise ValueError(f"bad gate port {gate_port!r}")
    if not re.fullmatch(r"[0-9.]+:[0-9]{2,5}", listen):
        raise ValueError(f"bad listen address {listen!r}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError(f"bad host {host!r}")
    b = https[0]
    b = re.sub(r"listen\s+443[^;]*;", f"listen {listen};", b)
    b = re.sub(r"server_name\s+[^;]*;", f"server_name {host};", b)
    b = re.sub(r"\n[ \t]*ssl_[a-z_]+\s+[^;]*;", "", b)
    b = b.replace(MAIN_GATE, f"127.0.0.1:{gate_port}")
    b = b.replace("X-Forwarded-Proto $scheme", "X-Forwarded-Proto https")
    if MAIN_GATE in b:
        raise ValueError("a route still points at the main gate")
    # GATE-04: drop the main site's own `location /api/access_control/save
    # { ... }` block entirely -- nginx matches the LONGEST prefix location,
    # so leaving it in place would let it win over the blanket
    # `/api/access_control` deny inserted below for exactly the one route
    # (the write endpoint) that matters most.
    save_blocks = [blk for blk in _location_blocks(b) if blk[0] == "/api/access_control/save"]
    for _, blk_text in save_blocks:
        b = b.replace(blk_text, "", 1)
    # Inserted right before the closing brace of the server block, so it's
    # a sibling of every other `location` block, matched by nginx's normal
    # longest-prefix rule ahead of the catch-all `location /`.
    last_brace = b.rindex("}")
    b = b[:last_brace] + _ACCESS_CONTROL_BLOCK + b[last_brace:]
    if "location /api/access_control {" not in b:
        raise ValueError("access_control block was not inserted")
    if "location /api/access_control/save" in b:
        raise ValueError("the main site's own access_control/save location survived -- it would shadow the deny block")
    header = (f"# OPA auth gate '{name}' on {host}. Generated from sites-available/opa-secrets-wizard by\n"
              "# server/setup-second-gate.sh; server/deploy.sh does not manage this file.\n")
    return header + b + "\n"


if __name__ == "__main__":
    src, dst, port, listen, host, name = sys.argv[1:7]
    out = build(open(src).read(), port, listen, host, name)
    with open(dst, "w") as f:
        f.write(out)
