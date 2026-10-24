# Evidence packages: the administrator's guide

An evidence package is one zip file that holds the archived events of an audit period, grouped into report files under
proposed SOC 2 criteria, together with the data an auditor needs to check, offline, that the events match the archive's own hash
chain. This page is for the person who builds one and sends it. What is inside, and how an auditor checks it, is in
[evidence-package-format.md](evidence-package-format.md); the limits are in [SECURITY.md](../SECURITY.md), "Evidence packages".

The tool is an independent project and is not affiliated with Okta. The control groupings are **proposed** by this project; no
auditor has reviewed them. A package shows that events were recorded by the source system and archived here. It does not show
that a control operated effectively.

## Before you start

1. **Build it well before the audit date.** An archive can only hold what it has read. Days the tool was not running, or a sync
   that failed, are gaps, and a gap cannot be filled afterwards for events Okta no longer keeps (the System Log is kept for 90
   days). Check the coverage of the period first (below) and fix a failing sync early. We cannot promise any response time from
   anyone: plan for your auditor's questions to need a second package.
2. **Check the archive.** Open the environment's Overview or Compliance Reports, make sure the last sync succeeded and the
   integrity check is intact. A package is refused if the archive's own chain check does not hold.
3. **Know who can build.** The environment's owner always can. Other people the environment is shared with need two permissions:
   *View archived reports* and *Build evidence packages*. The second is **off by default**: the environment form asks "Who can
   build evidence packages" (environment owner only, or the owner and the people it is shared with), and an administrator can also
   set it under Shared permissions. Changing it later needs MFA on a hosted server, like every other change there.
4. **Remember what a package holds.** Names, email addresses, IP addresses and what people did. It is not encrypted and not
   signed. Decide who will receive it, and how, before you build it.
5. **Free disk space.** The build needs free space on the data volume (see [hosting.md](hosting.md), "Evidence packages on the
   server") and refuses, with the numbers, when there is not enough.

## Building

Open **Compliance Reports** and choose **Build an evidence package…** (or **Build evidence package** on the Overview's evidence
card). The page has six steps; each heading takes keyboard focus when you arrive, and progress is announced to screen readers.

1. **Framework.** SOC 2 (proposed mapping). ISO 27001 and SOX are shown as "Not available yet".
2. **Period.** *Last quarter*, *Last 12 months* or custom dates. All dates are **UTC calendar days, both included**; the end date
   cannot be in the future. Events of the last day are in the package only if they were synced; "Data as of" in the package is the
   last successful sync.
3. **Coverage check.** The tool counts each day of the period: *covered with events*, *covered with zero events* (the archive read
   the day and holds nothing for it), *pruned by retention* (the retention setting removed old events; not a gap), *not covered*
   (a **gap**), *before the archive began* and *after the last successful sync* (not a gap). If there are gap days you must tick
   the box that says the archive has no record of reading those days, so events from them may be missing, and that the package
   will list them as gaps. A period with no coverage at all is refused. The wording of every state is text, not colour.
4. **Control matrix.** What each SOC 2 criterion will hold: its reports and the number of rows. A report that maps to two criteria
   appears under both. Every mapping is labelled proposed.
5. **Build.** On a hosted server the page sends you through your Okta step-up (fresh MFA) and back; the period and the
   acknowledgement are kept. On a computer without a login gate (local mode) there is no MFA: the build starts at once and the
   build log says "local mode, no MFA". Only one package can be built at a time on a server.
6. **Result.** A download button (the package stays on the server for **15 minutes** after it is finished; you can download it
   again inside that time), the package's **sha256** and the **chain head**. Write both down or leave the page open: the build log
   in the Audit Log (`evidence_package.build_finished`) has the same two values, and an auditor's check prints them, so a match shows
   the file is the one recorded in this server's build log.

A build that fails says why on the page (not enough disk, the size limit, the chain check, a permission that was withdrawn) and leaves
nothing on the server.

## What to send

- The zip file, exactly as downloaded. Do not open and re-zip it: the check fails on any change.
- The **verifier's sha256**, authoritative in the signed release (`manifest.json`, `verifier_sha256`), its release notes and the
  signing-key page (not the package), so the auditor can check the checking program before running it. The package also holds a
  copy of the program and its sha256 on the cover sheet; those are conveniences that came from the same place as the package and
  prove nothing about themselves.
- The package's **sha256** and **chain head**, from the page or the build log, by a different route than the file (for example by
  email, with the file shared another way).
- Your own statement of the period, the environment and what you want the auditor to see. The package does not make claims for you.

Send it over a channel you trust and delete your copies when the audit is over. If you need to share it with someone who should see
less, build a package for a shorter period; there is no redaction.

## What auditors usually ask

- *How do I know this is what your system produced?* They run the verifier and compare the zip's sha256 and the chain head with
  yours. State plainly that the package is not signed and the hashes are unkeyed: the verifier detects accidental or partial change
  and checks the exported events against the archive's hash chain as it stood when the package was built. It cannot show who
  produced the events.
- *Is it complete?* Show the coverage statement (`completeness.json`, the cover sheet): gap days you acknowledged, zero-event days,
  pruned days, the archive's start date, the data-as-of time, and which event types had no events in the period.
- *What does "proposed" mean?* The criteria are this project's suggestion, not reviewed by an auditor. Ask them how they map their
  own controls, and use the methodology note of each report (`methodology/`) to explain how rows are chosen and what each report
  cannot show.
- *Why do some cells start with an apostrophe?* They began with `=`, `+`, `-` or `@`; the apostrophe stops a spreadsheet program
  from running them as formulas. `events.ndjson` is the authoritative copy and has no apostrophe.
- *Can we see a sample or the raw events?* `events.ndjson` has every event of the period exactly as stored, one per line.
- *What is not in it?* Anything outside the archive: the tool reads the System Log and the OPA structure; it makes no statement about
  token scopes, and events the archive never read are not there.

## If something goes wrong

| You see | What it means |
|---|---|
| "No coverage" | The archive has no record of reading any day of the period. Pick another period, or run a sync and check the schedule. |
| "Confirm the gaps" | Days were not covered. Read the list; if the gaps are expected (the tool was off), tick the box. If not, fix the sync first. |
| "The archive's own chain check does not hold" | Run the integrity check on the environment (Overview or Compliance Reports) and resolve it. A package of a chain that fails would fail the verifier too. |
| "Not enough free disk space" | Free space on the data volume, or choose a shorter period. |
| "Larger than the limit" | Choose a shorter period (two packages are fine). |
| "Another evidence package is being built" | One at a time on a server. Wait a few minutes. |
| The download says the window ended | Build it again. Packages are deleted after 15 minutes and when the server starts. |
| 403 "Not allowed on this shared environment" | You need *View archived reports* and *Build evidence packages* on this environment; ask its owner or an administrator. |
