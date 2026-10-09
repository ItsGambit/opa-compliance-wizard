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
       [--allow-public-listen]

<listen> must be a loopback address (127.x.x.x) unless --allow-public-listen is given (GATE-15): this site
carries the proxy secret path and speaks plain HTTP, so publishing it on a LAN or public address is a choice
the operator has to make explicitly.
"""
import re
import sys

MAIN_GATE = "127.0.0.1:8767"


def _structure(text):
    """`text` with every comment and the inside of every quoted string
    blanked to spaces (newlines kept), same length -- so brace matching and
    directive searches see only real nginx syntax, while callers slice the
    ORIGINAL text by the same indices (GATE-15: a `{`, `}` or the word
    `server` in a comment used to derail the block scan).

    Follows nginx's own tokenizer: `#` starts a comment only at the start
    of a token (so `http://x/#frag` is not one), and a quote opens a string
    only at the start of a token; a backslash escapes the next character
    inside a string."""
    out = list(text)
    i, n = 0, len(text)
    token_start = True
    while i < n:
        ch = text[i]
        if token_start and ch == "#":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if token_start and ch in "\"'":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    if text[i + 1] != "\n":
                        out[i + 1] = " "
                    out[i] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            i += 1  # closing quote (kept)
            token_start = False
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":  # ${variable}: its braces are not blocks
            j = text.find("}", i + 2)
            if j != -1 and "\n" not in text[i:j]:
                for k in range(i + 1, j + 1):
                    out[k] = " "
                i = j + 1
                token_start = False
                continue
        token_start = ch.isspace() or ch in ";{}"
        i += 1
    return "".join(out)


def server_blocks(text):
    """Top-level `server { ... }` blocks, in order (comments and quoted
    strings are ignored for matching; the returned text is the original)."""
    s = _structure(text)
    blocks, depth, start = [], 0, None
    for i, ch in enumerate(s):
        if (depth == 0 and start is None and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_"))
                and re.match(r"server\s*\{", s[i:i + 64])):
            start = i
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced '}' in the nginx site")
            if depth == 0 and start is not None:
                blocks.append(text[start:i + 1])
                start = None
    if depth != 0:
        raise ValueError("unbalanced '{' in the nginx site")
    return blocks


def _location_blocks(text):
    """Every `location <path-or-pattern> { ... }` block inside `text` (one
    nesting level -- good enough for this project's own flat nginx
    template), as (path, full_block_text) pairs. Brace-depth tracked from
    the block's own opening `{` so a path containing `{`/`}` (never happens
    here, but this stays correct regardless) can't desync the scan."""
    out = []
    s = _structure(text)
    # The pattern may be quoted (location ~ "^/x" {): _structure blanks the
    # inside of quotes, so match the quoted token's span on the structure
    # and read the real pattern from the original text.
    for m in re.finditer(r"(?<![A-Za-z0-9_$])location\s+(?:(=|\^~|~\*|~)\s*)?(\"[^\"]*\"|'[^']*'|[^\s{\"']+)\s*\{", s):
        path = text[m.start(2):m.end(2)]
        if len(path) >= 2 and path[0] == path[-1] and path[0] in "\"'":
            path = path[1:-1]
        depth = 0
        i = m.end() - 1  # the matched opening brace
        start = m.start()
        for j in range(i, len(s)):
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
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


def _replace_directive(block, pattern, replacement):
    """Replace every real (not commented-out, not quoted) occurrence of
    `pattern` in `block`, wherever it sits on the line."""
    s = _structure(block)
    spans = [m.span() for m in re.finditer(r"(?<![A-Za-z0-9_$])" + pattern, s)]
    for start, end in reversed(spans):
        block = block[:start] + replacement + block[end:]
    return block


def build(main_site, gate_port, listen, host, name, allow_public_listen=False):
    https = [b for b in server_blocks(main_site) if re.search(r"(?<![A-Za-z0-9_$])listen\s+443", _structure(b))]
    if len(https) != 1:
        raise ValueError(f"expected exactly one HTTPS server block in the main site, found {len(https)}")
    if not re.fullmatch(r"[0-9]{4,5}", str(gate_port)) or str(gate_port) in ("8766", "8767"):
        raise ValueError(f"bad gate port {gate_port!r}")
    if not re.fullmatch(r"[0-9.]+:[0-9]{2,5}", listen):
        raise ValueError(f"bad listen address {listen!r}")
    if not allow_public_listen and not re.fullmatch(r"127(\.[0-9]{1,3}){3}:[0-9]{2,5}", listen):
        raise ValueError(f"listen address {listen!r} is not loopback (127.x.x.x); pass --allow-public-listen "
                         "to publish this plain-HTTP site on another address")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError(f"bad host {host!r}")
    b = https[0]
    b = _replace_directive(b, r"listen\s+443[^;]*;", f"listen {listen};")
    b = _replace_directive(b, r"server_name\s+[^;]*;", f"server_name {host};")
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
    structure = _structure(b)
    if not re.search(rf"(?<![A-Za-z0-9_$])listen {re.escape(listen)};", structure) or re.search(
            r"(?<![A-Za-z0-9_$])listen\s+443", structure):
        raise ValueError("the HTTPS listen directive was not rewritten")
    if not re.search(rf"(?<![A-Za-z0-9_$])server_name {re.escape(host)};", structure):
        raise ValueError("server_name was not rewritten")
    # A regex location could also match /api/access_control/save and win over
    # the prefix deny block (regex locations beat prefix ones in nginx).
    if any("access_control" in path for path, _ in _location_blocks(b)
           if path not in ("/api/access_control",)):
        raise ValueError("another location matching /api/access_control survived -- it could shadow the deny block")
    if "location /api/access_control {" not in structure:
        raise ValueError("access_control block was not inserted")
    if re.search(r"location\s+(=\s*)?/api/access_control/save", structure):
        raise ValueError("the main site's own access_control/save location survived -- it would shadow the deny block")
    header = (f"# OPA auth gate '{name}' on {host}. Generated from sites-available/opa-secrets-wizard by\n"
              "# server/setup-second-gate.sh; server/deploy.sh does not manage this file.\n")
    return header + b + "\n"


if __name__ == "__main__":
    src, dst, port, listen, host, name = sys.argv[1:7]
    extra = sys.argv[7:]
    if extra not in ([], ["--allow-public-listen"]):
        raise SystemExit(f"unexpected arguments: {extra}")
    out = build(open(src).read(), port, listen, host, name, allow_public_listen=bool(extra))
    with open(dst, "w") as f:
        f.write(out)
