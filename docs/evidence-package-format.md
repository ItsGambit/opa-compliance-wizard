# Evidence package format v1

For auditors and for anyone who needs to check or re-implement a check of an OPA Compliance Wizard evidence package. The package is one zip file. This page says what is in it, how its hashes are made, how to check it, and what a successful check does and does not show.

The OPA Compliance Wizard is not affiliated with Okta.

## What a successful check shows

A package that verifies shows that:

- every file in the package is exactly the file its `package-manifest.json` lists (sha256 and byte count), and nothing is missing or extra;
- every exported event that the archive sealed hashes to the value sealed for it, and every sealed manifest's content hash recomputes from its sealed entries;
- the chain of manifest records in the package links from its first record to the head recorded at build time, with no record changed, removed, added or reordered inside the package;
- every report row that carries an `event_uuid` names an event that is in `events.ndjson`.

In short: the verifier detects accidental or partial change to the package, and checks the exported events against the archive's hash chain as it stood when the package was built.

## What a successful check does not show

- **Not signed, unkeyed hashes.** Anyone who can rewrite the whole package, or the archive it was built from, and recompute every hash can produce a package that verifies. Nothing in the package proves who built it.
- It does not prove who produced the events, or that the archive was never altered by someone who could rewrite it.
- It does not prove that `events.ndjson` holds every event of the period. The `published` dates in `chain/seals.ndjson` and the list `period_manifest_ids` in `package-manifest.json` are outside every hash, so a builder could misstate them and hide a missing event. The completeness statement (`completeness.json`) is the builder's own statement.
- Only events the archive sealed are checked against a seal. These are not verified, and the verifier lists their counts by name every time:
  - events with no seal in the package (rows the archive does not content-seal, for example events outside the curated set, and rows removed by retention);
  - **legacy v1 manifests**: written before content sealing began, they record identifiers only;
  - **snapshot manifests**: configuration snapshots; their link in the chain is checked, their objects are not in the package;
  - report rows that carry no `event_uuid`;
  - pruned days, which the package builder states in `completeness.json`: a statement the verifier prints and does not check.
- The verifier prints the chain head on its own line. The operator's server-side build log (written when the package was built) is the only independent record of who built it, when, and with what result. The verifier also prints the sha256 of the zip file itself; compare both it and the chain head with that log.

## Getting the verifier and checking it

The verifier is `tools/verify_evidence_package.py`, one file, Python standard library only. Where to get it, most trusted first:

1. **The sha256 in the signed release (`manifest.json`, field `verifier_sha256`), in its release notes and on the signing-key page.** All are outside the package. This is the authoritative value.
2. **The signed release tarball** of the OPA Compliance Wizard contains the verifier. Verify the release as the README describes, then take the file from it.
3. **The value on the package's cover sheet and the copy inside the package** (`tools/verify_evidence_package.py` inside the zip, listed in `package-manifest.json` like every file) are conveniences only. They come from the same place as the package, so they prove nothing about themselves.

Before you rely on a copy, compute its sha256 yourself and compare it with the authoritative value:

```
sha256sum tools/verify_evidence_package.py        # Linux
shasum -a 256 tools/verify_evidence_package.py    # macOS
Get-FileHash tools\verify_evidence_package.py     # Windows PowerShell
```

If the value differs, do not use that copy.

## Running it

```
python3 -I tools/verify_evidence_package.py package.zip      # Linux, macOS
py -I tools\verify_evidence_package.py package.zip           # Windows
```

Use an operating-system Python you already trust. `-I` runs Python in isolated mode: it ignores the current directory, `PYTHONPATH` and the user's site-packages. The installation's own library and its `sitecustomize` still load, so isolated mode does not protect against a Python installation that is itself altered. Running from an empty directory is a further precaution, not a guarantee. The verifier reads the zip in memory, never extracts a file, never follows a path named inside the package, and imports nothing from the application. It refuses entry names that are absolute, contain `..`, a backslash or a colon, are not plain ASCII, repeat (ignoring case), or are not regular files.

Output is a short report and a final line:

- `RESULT: PASS`, exit status 0;
- `RESULT: FAIL (<reasons>)`, exit status 1;
- exit status 2 when the input cannot be used (missing file, not a zip, wrong arguments).

A PASS still lists the "Not verified" counts above; read them.

## Files

Entries are ASCII names built from fixed keys. Order in the zip is as listed; the verifier does not depend on it.

| Path | Content |
|---|---|
| `README-FOR-AUDITORS.txt` | plain text for the reader |
| `cover-sheet.html` | static page, no scripts, no external loads |
| `control-matrix.csv` | `control_id`, `framework`, `mapping_status` (`proposed` or `auditor-reviewed`), `reports`, `rows_in_period`, `status` |
| `controls/<control_id>/<report_key>.csv` | one per control and report; see the `event_uuid` column contract below |
| `events.ndjson` | every event of the period in scope, one per line, oldest first (ties by uuid) |
| `tools/verify_evidence_package.py` | convenience copy of the verifier; listed in `package-manifest.json` like every file; not a trusted source (see above) |
| `chain/manifests.ndjson` | every manifest record of the environment, first to head, in chain order |
| `chain/seals.ndjson` | for each manifest holding an event of the period, its sealed entries |
| `completeness.json` | the builder's statement of rows, scope, counts, coverage and pruned days (`pruned_basis` says what the pruned days rest on: records the server wrote when it pruned, or, for older prunes, the server's audit log or the current retention setting; a builder without administrator rights sees only prune times and counts there, not who ran them) |
| `what-this-tool-reads.txt` | static statement of what the tool reads |
| `methodology/<report_key>.txt` | method notes per report |
| `package-manifest.json` | the file list and package facts, below |

`package-manifest.json`:

```
{"format": 1,
 "files": [{"path": "...", "sha256": "<64 lowercase hex>", "bytes": 123}, ...],
 "built_at": "...", "app_version": "...", "environment_label_ascii": "...",
 "period": {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD"},
 "data_as_of": "...", "chain_head": "<64 hex> or null", "catalogue_version": "...",
 "curated_event_types": ["<event type the archive seals>", ...],
 "period_manifest_ids": [<id of every manifest that holds an event of the period>, ...]}
```

`files` lists every entry except `package-manifest.json` itself, exactly once each. `curated_event_types` is the sorted list of event types the archive content-seals. `period_manifest_ids` lists, in ascending order, every manifest in the chain that holds an event of the period, including legacy and older-format ones.

### events.ndjson

Ordered by canonical `published` time ascending, ties by `uuid` ascending (the verifier fails otherwise). The canonical form is `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC, derived from the event's `published` text by the archive's rule (space or `T`, 0 to 9 fractional digits, `Z`, an offset or no zone meaning UTC); the verifier carries the same function. An event whose `published` does not canonicalise fails. One line per event, UTF-8, each line is the event's stored `raw_json` byte for byte, terminated by a single `\n` (including the last line). Each event is a JSON object with a string `uuid`. A uuid appears once.

### chain/manifests.ndjson

One JSON object per line, ascending `manifest_id`:

`manifest_id` (integer), `environment_id`, `source`, `since` (or null), `until` (or null), `row_count` (integer), `batch_hash`, `prev_manifest_hash` (null for the first record), `created_at`, `content_hash` (null for legacy), `entry_hash` (null for legacy), and `entries_json` (true for an older-format manifest whose entries live in a single cell; informational, outside every hash, and ignored by the verifier: such a manifest is checked like any other sealed one).

A manifest whose `source` starts with `snapshot:` is a snapshot manifest.

### chain/seals.ndjson

One object per line: `{"manifest_id": 7, "entries": ["<event uuid>:<content hash>", ...], "published": ["<published time of each entry's event>", ...]}`. `entries` are all of the manifest's curated rows (sorted); `published` is parallel to `entries` (same length and order), written in the archive's canonical form (`YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC). It is outside every hash; the verifier uses it only to decide whether a sealed event that is missing from `events.ndjson` fell inside the period, so it is a statement by the builder, not something the archive sealed. A seal line is present for every manifest in `period_manifest_ids` that is sealed (v2) and not a snapshot, including an older-format (`entries_json`) manifest. Lines for legacy and snapshot manifests are ignored and counted as not verified. When an event is present in `events.ndjson`, its seal's `published` must equal the event's canonical `published` time.

### The `event_uuid` column contract for report CSVs

Every file under `controls/` has a header row containing a column named exactly `event_uuid`. For each data row, `event_uuid` is either the uuid of the System Log event the row was built from, which must be in `events.ndjson`, or empty when the row is not derived from a single event (the verifier counts these and reports them as not verified). A leading apostrophe added by formula neutralisation is accepted and ignored. Only the uuid ties a row to an event: the other cells of a row are not compared with the event, and the `reports` column of the matrix is not cross-checked. Files are read as UTF-8 (a byte order mark is accepted) with standard CSV quoting.

In `control-matrix.csv`, `rows_in_period` for a control must equal the number of data rows in the CSV files under `controls/<control_id>/`, and every control that has report files must be in the matrix.

## The three hash formulas

All hashes are SHA-256, written as 64 lowercase hex digits. Strings are UTF-8.

1. **Event content hash.** `sha256(raw_json as UTF-8 bytes)`. In the package, the bytes of an `events.ndjson` line without its trailing `\n`.
2. **Manifest content hash.** `sha256("\n".join(sorted("<uuid>:<event content hash>" for each curated row of the manifest)))`. Sorting is by the full string, by code point. An empty manifest hashes the empty string (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
3. **Manifest entry hash (the chain link).** `sha256("\n".join([prev_hash or "", environment_id, source, since or "", until or "", str(row_count), created_at, batch_hash, content_hash]))`, where `prev_hash` is the previous record's `entry_hash` (or, if the previous record is a legacy one, its `batch_hash`), and absent values are empty strings.

`batch_hash` is `sha256("\n".join(sorted(uuids of every row of the batch)))`; it is carried in the record and is part of formula 3, and the verifier does not recompute it (it covers rows, including non-curated ones, that the package does not hold).

Golden values (the test suite asserts them against both the application and the verifier):

| Input | Result |
|---|---|
| raw_json `{"uuid":"evt-1","eventType":"user.session.start","published":"2026-01-02T03:04:05.000Z"}` | `a37dfdb0ca8b86f92b3322a15a37d1c777dbd798d31e9701257cc95a0641d650` |
| raw_json `{"uuid":"evt-2","eventType":"user.session.start","published":"2026-01-02T03:04:06.000Z","note":"café"}` with the real character e-acute (UTF-8) | `cabc4b097a719c13fd5cf69695cc4fa5f198830dd6c7e8cf95205e5172352a8b` |
| manifest content hash of the two events above | `89a18423836d2fb441ae349b0595e19653eccf647cff22640e8dc02a62a20364` |
| entry hash: prev empty, environment `11111111-1111-1111-1111-111111111111`, source `sync`, since `2026-01-01T00:00:00.000Z`, until empty, row_count 3, created_at `2026-01-02T03:05:00.000Z`, batch_hash `8d3f182a04c6d2bcb51a2e6f0201039af53aa777c6aa18236b3c6eae53083b44`, content hash as above | `8a53dc4a39059e81e9d06559cc857a74a25a449ddd000084762147e606afb2d6` |

## Verification steps

1. Open the zip without extracting. Refuse any unsafe or repeated entry name, any encrypted entry and any entry that is not a regular file.
2. Read `package-manifest.json`: `format` is 1 and the required keys are present. Its `files` must name exactly the other entries; each entry's byte count and sha256 must match; every required file must be present.
3. Walk `chain/manifests.ndjson` in order. Ids ascend; the first record's `prev_manifest_hash` is null; each record's `prev_manifest_hash` equals the previous record's link (its `entry_hash`, or `batch_hash` for a legacy record); a legacy record after a sealed one is a downgrade and fails; each sealed record's `entry_hash` recomputes by formula 3. The last link must equal `chain_head` in `package-manifest.json`.
4. Every id in `period_manifest_ids` must be in the chain. For each ordinary sealed manifest among them there must be a seal line; the entries recompute to the record's `content_hash` by formula 2, and there are no more of them than `row_count`.
5. For each line of `events.ndjson`: it is in order (published, then uuid); if the event's uuid is in a seal, its content hash (formula 1) must equal the sealed value. An event whose `eventType` is in `curated_event_types` and that has no seal fails, unless a legacy (pre-sealing) manifest is among the period's manifests (it might hold that event; the event is then counted as not verified, and the report prints the legacy manifest ids and how many events were tolerated). Other events with no seal are counted as not verified.
6. Every event's canonical `published` date lies inside `period` (a date pair `YYYY-MM-DD`, start not after end). Every sealed entry of a period manifest whose published date is inside the period must be in `events.ndjson`; one that is absent fails (a curated event is missing).
7. For each `controls/**/*.csv` row with an `event_uuid`, that uuid is in `events.ndjson`; the matrix row counts match the report files.
8. Print the report (package text is shown as printable ASCII only, at most 120 characters per value), the zip's sha256 and the chain head on their own labelled lines, and the final `RESULT:` line. Lines longer than 16 MiB (256 MiB for a seals line), a `completeness.json` over 64 MiB and zip entries that are not stored or deflated fail.

## Limits and memory

The verifier holds the uuids of the sealed entries and of the exported events in memory (about 250 bytes per event). The verifier needs about 650 MB of memory per million events (streaming it is planned for 5.54.0). Files are streamed and hashed in chunks.

## Versioning

`format` is 1. A change to any formula or field above is a new format number; a verifier refuses a format it does not know.
