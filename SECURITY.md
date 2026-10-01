# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately via
[GitHub Security Advisories](https://github.com/ItsGambit/opa-compliance-wizard/security/advisories/new)
for this repository. This creates a private discussion visible only to
the maintainer until a fix is ready, and lets GitHub coordinate a
disclosure timeline with you if one is needed.

Include, if you can:
- What you found and why it's a security issue (not just "this seems
  wrong")
- Steps to reproduce it
- The version/commit you tested against
- Whether it requires a specific deployment mode (local-only vs. hosted
  behind nginx + Okta login) to be exploitable

## What to expect

This is a community-maintained project with one informal maintainer, not
a company with a dedicated security team or an SLA. A genuine effort will
be made to acknowledge a report promptly and fix a confirmed issue — but
there's no guaranteed response time. If you don't hear back within a
reasonable window, a follow-up is completely fair.

## Current security review status

This project has gone through internal review and multiple
AI-assisted security review passes, with findings independently verified
against the real code before being fixed — see
[CHANGELOG.md](CHANGELOG.md) for the specific fixes shipped this way.
**No independent third-party security audit has been performed.** If
you're evaluating this for a production tenant, especially a hosted
multi-user deployment, factor that in — see the main
[README](README.md)'s "Project status" section for the full framing.

## Supported versions

This project ships one actively-maintained line — only the latest
released version receives fixes. There is no long-term-support branch.
Please update to the latest version before reporting an issue, in case
it's already fixed.
