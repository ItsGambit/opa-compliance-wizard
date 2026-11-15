# What to get before you start

Both install guides ask for the same five things from OPA and Okta. They are owned by administrators, so ask for them first: it is
the slowest part of the whole install.

| Get this | From | Looks like |
|---|---|---|
| **OPA base domain** | OPA administrator | `yourorg.pam.okta.com` (the host of the address you sign in to OPA at, without `https://`) |
| **OPA team name** | OPA administrator | `yourteam-pam` (the name of your OPA team; it appears in OPA's API addresses as `/v1/teams/<team>/...`) |
| **OPA service-user key ID and key secret** | OPA administrator | two long strings; the secret is shown once |
| **Okta URL** | Okta administrator | `https://yourorg.okta.com` (your normal address: not the one with `-admin` in it, no path) |
| **Okta API token** | Okta administrator | one long string; shown once |

**What the tool does with them.** The sync and the reports only **read**. The only part that creates or deletes anything in OPA is
**Folder Builder**, and you will not open it for a first report.

## A message you can send

To the OPA administrator:

> Please create an OPA **service user** for the OPA Compliance Wizard (Directory → Users → Service Users tab), create an API key for
> it, and send me the key ID and key secret, plus our OPA base domain and team name. It only needs to read our OPA setup (resource
> groups, projects, users, groups, policies). It has been tested with a service user in a group that holds the `pam_admin` role.

To the Okta administrator:

> Please create an Okta API token (Security → API → Tokens → Create token) for the OPA Compliance Wizard, and send me the token and our
> Okta URL. It should be created by a dedicated admin account, not a person, so it keeps working when people change jobs. The account
> needs to read the System Log, users and groups.

## Notes for the administrators

**The OPA service user.** It is an OPA account for programs, made at **Directory → Users → Service Users → Create API Key**. What the
tool can see is limited by what that user may do in OPA. The minimum OPA role has not been documented by the project: reports and
the folder tools were tested with a group holding `pam_admin`; each screen says what it could not read.

**The Okta API token.** The token's name does not matter. It has the permissions of the admin who creates it and stops working if
it is not used for 30 days or if that admin is deactivated, so use a dedicated account. The account must be able to read the System Log,
users and groups. The Okta Admins report also needs a Super Administrator or a custom role with `okta.iam.read`
([which Okta role the token needs](features.md#which-okta-role-the-token-needs)). The project has not documented a minimum built-in
role.
