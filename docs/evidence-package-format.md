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
- It does not prove that `events.ndjson` holds every event of the period. The completeness statement (`completeness.json`) is the builder's own statement.
- Only events the archive sealed are checked against a seal. These are not verified, and the verifier lists their counts by name every time:
  - events with no seal in the package (rows the archive does not content-seal, for example events outside the curated set, and rows removed by retention);
  - **legacy v1 manifests**: written before content sealing began, they record identifiers only;
  - **`entries_json` manifests**: an older sealing format that a package does not carry seals for;
  - **snapshot manifests**: configuration snapshots; their link in the chain is checked, their objects are not in the package;
  - report rows that carry no `event_uuid`;
  - pruned days, which the package builder states in `completeness.json`: a statement the verifier prints and does not check.
- The operator's server-side build log (written when the package was built) is the independent record of who built it, when, and with what result. Compare the package's sha256 and chain head with that log.

## Getting the verifier and checking it

The verifier is `tools/verify_evidence_package.py`, one file, Python standard library only. It ships inside the signed release of the OPA Compliance Wizard, and a convenience copy is placed in every package. Its sha256 is printed in the release notes, on the signing-key page and on the package's cover sheet. Before you rely on a copy, compute its sha256 yourself and compare:

```
sha256sum tools/verify_evidence_package.py        # Linux
shasum -a 256 tools/verify_evidence_package.py    # macOS
Get-FileHash tools\verify_evidence_package.py     # Windows PowerShell
```

If the value differs from the one published with the release, do not use that copy. A copy found only inside the package proves nothing about itself.

## Running it

```
python3 -I tools/verify_evidence_package.py package.zip
```

`-I` runs Python in isolated mode, so nothing from the current directory or the environment is loaded. The verifier reads the zip in memory, never extracts a file, never follows a path named inside the package, and imports nothing from the application. It refuses entry names that are absolute, contain `..`, a backslash or a colon, are not plain ASCII, repeat (ignoring case), or are not regular files.

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
| `chain/manifests.ndjson` | every manifest record of the environment, first to head, in chain order |
| `chain/seals.ndjson` | for each manifest holding an event of the period, its sealed entries |
| `completeness.json` | the builder's statement of rows, scope, counts, coverage and pruned days |
| `what-this-tool-reads.txt` | static statement of what the tool reads |
| `methodology/<report_key>.txt` | method notes per report |
| `package-manifest.json` | the file list and package facts, below |

`package-manifest.json`:

```
{"format": 1,
 "files": [{"path": "...", "sha256": "<64 lowercase hex>", "bytes": 123}, ...],
 "built_at": "...", "app_version": "...", "environment_label_ascii": "...",
 "period": {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD"},
 "data_as_of": "...", "chain_head": "<64 hex> or null", "catalogue_version": "..."}
```

`files` lists every entry except `package-manifest.json` itself, exactly once each.

### events.ndjson

One line per event, UTF-8, each line is the event's stored `raw_json` byte for byte, terminated by a single `\n` (including the last line). Each event is a JSON object with a string `uuid`. A uuid appears once.

### chain/manifests.ndjson

One JSON object per line, ascending `manifest_id`:

`manifest_id` (integer), `environment_id`, `source`, `since` (or null), `until` (or null), `row_count` (integer), `batch_hash`, `prev_manifest_hash` (null for the first record), `created_at`, `content_hash` (null for legacy), `entry_hash` (null for legacy), and `entries_json` (true for an older-format manifest whose entries live in a single cell).

A manifest whose `source` starts with `snapshot:` is a snapshot manifest.

### chain/seals.ndjson

One object per line: `{"manifest_id": 7, "entries": ["<event uuid>:<content hash>", ...]}`. The entries are the manifest's curated rows. A seal line is present for each ordinary sealed manifest holding at least one event of the period. Lines for legacy, snapshot and `entries_json` manifests are ignored and counted as not verified.

### The `event_uuid` column contract for report CSVs

Every file under `controls/` has a header row containing a column named exactly `event_uuid`. For each data row, `event_uuid` is either the uuid of the System Log event the row was built from, which must be in `events.ndjson`, or empty when the row is not derived from a single event (the verifier counts these and reports them as not verified). A leading apostrophe added by formula neutralisation is accepted and ignored. Files are read as UTF-8 (a byte order mark is accepted) with standard CSV quoting.

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
4. For each seal line of an ordinary sealed manifest: the entries recompute to the record's `content_hash` by formula 2, and there are no more of them than `row_count`.
5. For each line of `events.ndjson`: if the event's uuid is in a seal, its content hash (formula 1) must equal the sealed value. Events with no seal are counted as not verified.
6. For each `controls/**/*.csv` row with an `event_uuid`, that uuid is in `events.ndjson`.
7. Print the report and the final `RESULT:` line.

## Limits and memory

The verifier holds the uuids of the sealed entries and of the exported events in memory (about 250 bytes per event). A package of a million events needs a few hundred megabytes. Files are streamed and hashed in chunks.

## Versioning

`format` is 1. A change to any formula or field above is a new format number; a verifier refuses a format it does not know.
