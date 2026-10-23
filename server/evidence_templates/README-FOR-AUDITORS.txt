READ THIS FIRST - EVIDENCE PACKAGE FOR AUDITORS

This file is plain text. It explains what is in this package, how to check it
and what the check does and does not show. Nothing in this package asks you to
run a program that came with it: the checking program is a separate file, and
you decide where you trust it from (see "How to check this package").

1. WHAT THIS IS

This package was made by the OPA Compliance Wizard, a tool that copies audit
events from an Okta organization's System Log (which also carries the events of
Okta Privileged Access) into a local archive and reports on them. The tool is
an independent project. It is not affiliated with, endorsed by or supported by
Okta.

The package holds the events of one audit period, grouped into report files,
together with the data needed to check that those events match the archive's
own hash chain as it stood when the package was built.

2. THE FACTS OF THIS PACKAGE

  Environment label ......... @@ENVIRONMENT@@
  Period (UTC dates) ........ @@PERIOD_START@@ to @@PERIOD_END@@, both days included
  Built at (UTC) ............ @@BUILT_AT@@
  Built by .................. @@BUILDER@@
  Application version ....... @@APP_VERSION@@
  Control catalogue version . @@CATALOGUE_VERSION@@
  Data as of (UTC) .......... @@DATA_AS_OF@@
  Archive starts (UTC date) . @@ARCHIVE_START@@
  Events in the period ...... @@EVENT_COUNT@@
  Chain head ................ @@CHAIN_HEAD@@

"Data as of" is the time of the last successful sync of this environment.
Events after that time are not in the package; that is not a gap.

3. COVERAGE: GAP, ZERO-EVENT AND PRUNED DAYS

@@COVERAGE_TEXT@@

The day-by-day list is in completeness.json (coverage, days). It is the
builder's own statement, made by the tool when the package was built. The
checking program prints it and does not check it.

4. WHAT "PROPOSED" MEANS

control-matrix.csv and the files under controls/ group the reports under SOC 2
criteria. Every such grouping is labelled "proposed": it is a suggestion made by
the project that wrote the tool, it has not been reviewed by an auditor, and
you should treat it as a starting point for your own mapping, not as a
conclusion. The methodology/ folder has one plain-text note per report: what
it lists, how rows are chosen, and its known limits.

A row in a report file shows that an event was recorded by the source system
and archived. It does not show that a control operated effectively.

5. WHAT IS IN THE PACKAGE

  README-FOR-AUDITORS.txt     this file
  cover-sheet.html            a one-page summary (static page, no scripts)
  control-matrix.csv          criteria, reports, row counts and status
  controls/<id>/<report>.csv  the report rows, one file per criterion and report
  events.ndjson               every archived event of the period, one per line,
                              exactly as stored; the authoritative copy
  chain/manifests.ndjson      the archive's chain of manifest records
  chain/seals.ndjson          the sealed hashes of the events of the period
  completeness.json           the builder's statement of rows, scope, coverage,
                              pruned days and event types with no events
  what-this-tool-reads.txt    what the tool reads from the source systems
  methodology/<report>.txt    a note per report
  tools/verify_evidence_package.py   a convenience copy of the checking program
  package-manifest.json       the list of every file with its sha256 and size

Some cells in the report files begin with an apostrophe ('). It is added on
purpose when a value begins with =, +, - or @ so that a spreadsheet program
cannot run the value as a formula. The value in events.ndjson has no
apostrophe; events.ndjson is the authoritative copy.

6. HOW TO CHECK THIS PACKAGE

You need Python 3 (3.9 or newer) from your own operating system. No other
software and no network access is needed.

  Step 1. Get the checking program from a source you trust.
          Most trusted first: (a) the sha256 value printed in the release notes
          and on the project's signing-key page, which are outside this
          package; (b) the signed release of the tool; (c) the copy inside this
          package (tools/verify_evidence_package.py) and the value on the cover
          sheet. The copy and the cover-sheet value came from the same place as
          this package, so they prove nothing about themselves. Compute the
          sha256 of the file you will run and compare it with value (a):
            Linux:    sha256sum verify_evidence_package.py
            macOS:    shasum -a 256 verify_evidence_package.py
            Windows:  Get-FileHash verify_evidence_package.py
          If the values differ, do not use that copy.
  Step 2. Run it on the zip file, without unpacking the zip:
            python3 -I verify_evidence_package.py <package file name>.zip
          On Windows: py -I verify_evidence_package.py <package file name>.zip
          Use a Python installation you already trust. Running it from an empty
          folder is a further precaution. The program reads the zip in memory,
          never unpacks a file and never follows a path named inside the zip.
  Step 3. Read the report. It ends with one of:
            RESULT: PASS          exit status 0
            RESULT: FAIL (...)    exit status 1, with the reasons
          Exit status 2 means the file could not be used (not a zip, missing).
          Read the "Not verified" lines of a PASS too: they say how many rows
          the check could not cover.
  Step 4. The program prints the sha256 of the zip file and the chain head.
          Ask the operator of the server for the server-side build log of this
          package and compare both values with it. That log is the only
          independent record of who built the package, when, and with what
          result.

If the result is FAIL, do not rely on the package. Tell the operator and ask
for a new package.

7. WHAT A SUCCESSFUL CHECK DOES NOT SHOW

The check detects accidental or partial change to this package and checks the
exported events against the archive's hash chain as it stood when the package
was built. It does not show:

  - who produced the events, or that the archive was never altered by someone
    who could rewrite it;
  - that events.ndjson holds every event of the period: the completeness
    statement is the builder's own;
  - anything about events that are not sealed in the archive (for example
    events outside the curated set, and rows removed by retention), the rows of
    older-format or snapshot records, and report rows that name no event. The
    program lists their counts by name.

The hashes are unkeyed and the package is not signed. Anyone who can rewrite the
whole package, or the archive it was built from, and recompute every hash can
produce a package that passes the check. The package holds personal data
(people's names, email addresses, IP addresses and what they did) and is not
encrypted: handle it accordingly.

8. FEEDBACK

If something in this package is unclear or wrong, open an issue on the
project's public issue page (the person who sent you the package can give you
the address). Describe the problem in words. Never attach or paste the package
or any of the data in it.
