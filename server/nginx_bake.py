"""Carries this server's own values from the live nginx site into the
repository's site template, before server/deploy.sh compares the two and
applies the template.

The template in the repository is public, so it can't hold any one server's
values. deploy.sh used to carry forward only NGINX_PROXY_SECRET; the
template's server_name and certificate paths were the maintainer's, so on
anyone else's server a deploy that applied it silently replaced their
server name (OPS-02, third-party installs). Now the proxy secret, every
`server_name`, `ssl_certificate` and `ssl_certificate_key` value is taken
from the live site, in order, and the result is refused -- nothing is
written -- when the live site doesn't have the template's layout (a
different number of those directives) or a placeholder would be left in
the result. The baked copy holds the secret, so it is written owner-only
(OPS-09).

    python server/nginx_bake.py [--check] <live site> <template, rewritten in place>

--check only reports whether the template can be baked (deploy.sh runs it
before changing anything); nothing is written.

Exit status: 0 baked; 3 refused (reason on stderr, template untouched);
2 usage.
"""

import os
import re
import sys
import tempfile

PLACEHOLDER_PREFIX = "REPLACE_WITH_"
_SECRET_RE = re.compile(r'(^[ \t]*set[ \t]+\$nginx_proxy_secret[ \t]+")([^"\n]*)(";)', re.M)
CARRIED_DIRECTIVES = ("server_name", "ssl_certificate", "ssl_certificate_key")


def _directive_re(name):
    # Line-anchored, so comments ("# server_name ...") and the $server_name
    # variable never match; `ssl_certificate` needs whitespace after it, so
    # it never matches `ssl_certificate_key`.
    return re.compile(rf"(^[ \t]*{name}[ \t]+)([^;\n#]*?)([ \t]*;)", re.M)


def _replace_in_order(pattern, text, values):
    matches = list(pattern.finditer(text))
    out, last = [], 0
    for match, value in zip(matches, values):
        out.append(text[last:match.start(2)])
        out.append(value)
        last = match.end(2)
    out.append(text[last:])
    return "".join(out)


def bake(live_text, template_text):
    """Returns (baked_text, problems). `problems` non-empty means the
    result must not be applied."""
    problems = []
    out = template_text

    live_secrets = [m.group(2) for m in _SECRET_RE.finditer(live_text)]
    template_secrets = list(_SECRET_RE.finditer(out))
    if len(live_secrets) != 1 or len(template_secrets) != 1:
        problems.append(f"expected one `set $nginx_proxy_secret` line in each file (live site has "
                        f"{len(live_secrets)}, template has {len(template_secrets)})")
    elif not live_secrets[0] or live_secrets[0].startswith(PLACEHOLDER_PREFIX):
        problems.append("the live site still has no real NGINX_PROXY_SECRET (set the same value as in the "
                        "service's environment file; docs/hosting.md step 4)")
    else:
        out = _replace_in_order(_SECRET_RE, out, live_secrets)

    for name in CARRIED_DIRECTIVES:
        pattern = _directive_re(name)
        live_values = [m.group(2).strip() for m in pattern.finditer(live_text)]
        template_count = len(pattern.findall(out))
        if len(live_values) != template_count:
            problems.append(f"`{name}` appears {len(live_values)} time(s) in the live site but {template_count} "
                            f"time(s) in the template, so its values can't be carried over one for one")
            continue
        out = _replace_in_order(pattern, out, live_values)

    for line in out.splitlines():
        if PLACEHOLDER_PREFIX in line and not line.lstrip().startswith("#"):
            problems.append(f"a placeholder would be left in the applied config: {line.strip()[:80]}")
            break
    return out, problems


def _write_owner_only(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".nginx-bake-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv):
    args = argv[1:]
    check_only = bool(args) and args[0] == "--check"
    if check_only:
        args = args[1:]
    if len(args) != 2:
        print("usage: nginx_bake.py [--check] <live site> <template, rewritten in place>", file=sys.stderr)
        return 2
    live_path, template_path = args
    with open(live_path, encoding="utf-8", newline="") as fh:
        live = fh.read()
    with open(template_path, encoding="utf-8", newline="") as fh:
        template = fh.read()
    baked, problems = bake(live, template)
    if problems:
        print(f"ERROR: not applying the repository's nginx config to {live_path}:", file=sys.stderr)
        for problem in problems:
            print(f"       - {problem}", file=sys.stderr)
        print("       Make the live site follow server/nginx-opa-secrets-wizard.conf (your own server_name,\n"
              "       certificate paths and proxy secret in it), then deploy again.", file=sys.stderr)
        return 3
    if check_only:
        return 0
    _write_owner_only(template_path, baked)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
