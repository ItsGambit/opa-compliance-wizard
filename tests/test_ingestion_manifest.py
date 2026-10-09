"""Covers Phase 6's hash-chained ingestion batch manifest
(ingestion_manifests table, _record_ingestion_manifest,
verify_ingestion_chain) -- one manifest row per sync_okta_events()/
import_from_csv() CALL (not per internal day-chunk), chained via
prev_manifest_hash to the previous row for the SAME environment_id.

Uses audit_store.run_migrations() (schema only), matching
test_sync_watermark.py's established pattern -- no need for
tmp_environments_file here since nothing in this file calls init_db()
(which would also run migrate_legacy_environments_json())."""
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import audit_store
import create_secret_folders as engine

ENV_A = "11111111-1111-1111-1111-111111111111"
ENV_B = "22222222-2222-2222-2222-222222222222"


class FakeOktaClient:
    """Same pattern as test_sync_watermark.py's -- scripted
    (events, complete) tuples, one per get_system_log call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get_system_log(self, since, until, limit, sort_order, max_pages):
        self.calls.append((since, until))
        if self._responses:
            return self._responses.pop(0)
        return [], True


def _event(uuid, published):
    return {
        "uuid": uuid,
        "eventType": "user.session.start",
        "published": published,
        "actor": {"id": "00uActor", "displayName": "Someone"},
        "outcome": {"result": "SUCCESS"},
        "target": [],
    }


def test_sync_records_one_manifest_per_call_not_per_day_chunk(tmp_audit_store):
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    okta_client = FakeOktaClient([
        ([_event("evt-1", since)], True),
        ([_event("evt-2", since)], True),
        ([_event("evt-3", since)], True),
    ])

    result = audit_store.sync_okta_events(okta_client, ENV_A, "all", since=since)
    assert result["complete"] is True
    assert result["chunks"] >= 3  # multiple day-chunks fetched...

    manifests = audit_store._get_connection().execute(
        "SELECT * FROM ingestion_manifests WHERE environment_id = ?", (ENV_A,)
    ).fetchall()
    assert len(manifests) == 1  # ...but exactly ONE manifest row for the whole call
    assert manifests[0]["row_count"] == 3
    assert manifests[0]["source"] == "sync"
    assert manifests[0]["prev_manifest_hash"] is None  # first manifest for this environment_id


def test_second_sync_chains_to_first_manifests_hash(tmp_audit_store, monkeypatch):
    """Legacy (v1) linking, as written before 5.40.4: prev -> batch_hash."""
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", False)
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    first_client = FakeOktaClient([([_event("evt-1", since)], True)])
    audit_store.sync_okta_events(first_client, ENV_A, "all", since=since)

    second_client = FakeOktaClient([([_event("evt-2", since)], True)])
    audit_store.sync_okta_events(second_client, ENV_A, "all", since=since)

    rows = audit_store._get_connection().execute(
        "SELECT id, batch_hash, prev_manifest_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id",
        (ENV_A,),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["prev_manifest_hash"] is None
    assert rows[1]["prev_manifest_hash"] == rows[0]["batch_hash"]


def test_second_sync_chains_to_first_manifests_entry_hash_by_default(tmp_audit_store):
    """Default (v2, 5.40.4+) linking: prev -> the previous row's entry_hash."""
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), ENV_A, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-2", since)], True)]), ENV_A, "all", since=since)
    rows = audit_store._get_connection().execute(
        "SELECT entry_hash, prev_manifest_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id",
        (ENV_A,),
    ).fetchall()
    assert len(rows) == 2 and rows[0]["prev_manifest_hash"] is None
    assert rows[0]["entry_hash"] and rows[1]["prev_manifest_hash"] == rows[0]["entry_hash"]


def test_zero_new_rows_batch_still_recorded_not_skipped(tmp_audit_store):
    """A sync that finds nothing new (every uuid already seen) must
    still produce a manifest row -- "nothing new happened" is itself a
    chained, verifiable fact, not a silent gap."""
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    okta_client = FakeOktaClient([([], True)])  # no events at all this run
    result = audit_store.sync_okta_events(okta_client, ENV_A, "all", since=since)
    assert result["inserted"] == 0

    manifests = audit_store._get_connection().execute(
        "SELECT * FROM ingestion_manifests WHERE environment_id = ?", (ENV_A,)
    ).fetchall()
    assert len(manifests) == 1
    assert manifests[0]["row_count"] == 0


def test_incomplete_chunk_sync_still_records_a_manifest_for_rows_already_inserted(tmp_audit_store):
    """An interrupted sync (hit max_pages mid-run) still produced real
    inserted rows across however many chunks completed first -- those
    must be in the chain too, not lost because the sync didn't finish
    cleanly. Note: the incomplete day's OWN partial results are still
    inserted (get_system_log's "not complete" flag means more events may
    exist on that day beyond what was fetched, not that what WAS fetched
    is unusable) -- so both day 1's and day 2's rows count."""
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    okta_client = FakeOktaClient([
        ([_event("evt-1", since)], True),   # day 1: complete, 1 new row
        ([_event("evt-2", since)], False),  # day 2: INCOMPLETE -- stops here, but its 1 row still inserted
    ])

    result = audit_store.sync_okta_events(okta_client, ENV_A, "all", since=since)
    assert result["complete"] is False
    assert result["inserted"] == 2

    manifests = audit_store._get_connection().execute(
        "SELECT * FROM ingestion_manifests WHERE environment_id = ?", (ENV_A,)
    ).fetchall()
    assert len(manifests) == 1
    assert manifests[0]["row_count"] == 2  # both days' rows, even though the overall sync didn't complete


def test_csv_import_records_a_manifest(tmp_audit_store, tmp_path):
    audit_store.run_migrations()
    csv_path = tmp_path / "export.csv"
    csv_path.write_text(
        "event_type,timestamp,uuid,actor.id,actor.display_name,outcome.result\n"
        "user.session.start,2026-01-01T00:00:00.000Z,csv-evt-1,00uActor,Someone,SUCCESS\n",
        encoding="utf-8",
    )

    result = audit_store.import_from_csv(str(csv_path), ENV_A, "all")
    assert result["inserted"] == 1

    manifests = audit_store._get_connection().execute(
        "SELECT * FROM ingestion_manifests WHERE environment_id = ?", (ENV_A,)
    ).fetchall()
    assert len(manifests) == 1
    assert manifests[0]["source"] == "csv_import"
    assert manifests[0]["since"] is None
    assert manifests[0]["until"] is None


def test_chains_are_independent_per_environment_id(tmp_audit_store):
    """Two different environments' chains must never cross-reference
    each other's hashes, even if ingested in the same test/process."""
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    audit_store.sync_okta_events(FakeOktaClient([([_event("a-evt-1", since)], True)]), ENV_A, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("b-evt-1", since)], True)]), ENV_B, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("a-evt-2", since)], True)]), ENV_A, "all", since=since)

    conn = audit_store._get_connection()
    env_a_rows = conn.execute(
        "SELECT prev_manifest_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id", (ENV_A,)
    ).fetchall()
    env_b_rows = conn.execute(
        "SELECT prev_manifest_hash FROM ingestion_manifests WHERE environment_id = ? ORDER BY id", (ENV_B,)
    ).fetchall()
    assert len(env_a_rows) == 2
    assert len(env_b_rows) == 1
    assert env_a_rows[0]["prev_manifest_hash"] is None  # ENV_A's first row, not chained to ENV_B's row in between


def test_verify_ingestion_chain_valid_on_an_untampered_chain(tmp_audit_store):
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), ENV_A, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-2", since)], True)]), ENV_A, "all", since=since)

    result = audit_store.verify_ingestion_chain(ENV_A)
    # 5.40.2 (DATA-04) added reason/head_hash/legacy_manifests/deep/... to
    # the result; the three original keys keep their exact meaning.
    assert {k: result[k] for k in ("valid", "manifest_count", "broken_at")} == {"valid": True, "manifest_count": 2, "broken_at": None}
    assert result["head_hash"] is not None


def test_verify_ingestion_chain_valid_and_empty_with_no_manifests(tmp_audit_store):
    audit_store.run_migrations()
    result = audit_store.verify_ingestion_chain(ENV_A)
    assert {k: result[k] for k in ("valid", "manifest_count", "broken_at")} == {"valid": True, "manifest_count": 0, "broken_at": None}
    assert result["head_hash"] is None


@pytest.mark.parametrize("chain_v2", [False, True], ids=["v1-legacy", "v2-default"])
def test_verify_ingestion_chain_detects_a_tampered_hash(tmp_audit_store, monkeypatch, chain_v2):
    """Directly corrupts a stored batch_hash (simulating tampering with
    the archive after the fact) and confirms verify_ingestion_chain
    actually detects it -- proves the mechanism catches tampering, not
    just that it runs without error."""
    monkeypatch.setattr(audit_store, "EVIDENCE_CHAIN_V2", chain_v2)
    audit_store.run_migrations()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), ENV_A, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-2", since)], True)]), ENV_A, "all", since=since)
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-3", since)], True)]), ENV_A, "all", since=since)

    conn = audit_store._get_connection()
    middle_id = conn.execute(
        "SELECT id FROM ingestion_manifests WHERE environment_id = ? ORDER BY id LIMIT 1 OFFSET 1", (ENV_A,)
    ).fetchone()["id"]
    conn.execute("UPDATE ingestion_manifests SET batch_hash = 'tampered' WHERE id = ?", (middle_id,))
    conn.commit()

    result = audit_store.verify_ingestion_chain(ENV_A)
    assert result["valid"] is False
    third_id = conn.execute(
        "SELECT id FROM ingestion_manifests WHERE environment_id = ? ORDER BY id LIMIT 1 OFFSET 2", (ENV_A,)
    ).fetchone()["id"]
    # v1: the THIRD row's prev_manifest_hash no longer matches the tampered
    # second row's batch_hash. v2: the second row's own entry_hash (which
    # seals batch_hash) no longer recomputes, so the break is found a row
    # earlier, at the edited row itself.
    assert result["broken_at"] == (middle_id if chain_v2 else third_id)


# ---------------------------------------------------------------------------
# HTTP route round-trip -- same live_server pattern as
# test_two_owner_collision.py, kept local to this file rather than
# shared, matching that file's own precedent.
# ---------------------------------------------------------------------------
@pytest.fixture
def live_server(tmp_audit_store, tmp_environments_file, fake_keyring, tmp_audit_log, monkeypatch):
    import server.serve as serve

    monkeypatch.setattr(serve, "NGINX_PROXY_SECRET", "test-proxy-secret")
    audit_store.run_migrations()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server_instance = serve.StrictBindHTTPServer(("127.0.0.1", port), serve.Handler)
    thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    for _ in range(50):
        try:
            requests.get(base_url + "/api/environments", timeout=0.5,
                         headers={"X-Nginx-Proxy-Secret": "test-proxy-secret"})
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)

    yield base_url
    server_instance.shutdown()
    server_instance.server_close()


def test_http_integrity_route_returns_valid_chain(live_server, tmp_environments_file, fake_keyring):
    _, env_id = engine.upsert_environment(
        "dev", {"base_domain": "a.example.com", "team_name": "team-a", "key_id": "key-a", "key_secret": "secret-a"},
        owner=engine.LOCAL_OWNER_KEY,
    )
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    audit_store.sync_okta_events(FakeOktaClient([([_event("evt-1", since)], True)]), env_id, "all", since=since)

    resp = requests.get(
        f"{live_server}/api/environments/dev/integrity",
        headers={"X-Nginx-Proxy-Secret": "test-proxy-secret"},
        timeout=5,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert {k: body[k] for k in ("valid", "manifest_count", "broken_at")} == {"valid": True, "manifest_count": 1, "broken_at": None}
    assert body["deep"] is False


def test_http_integrity_route_404s_for_unknown_environment(live_server):
    resp = requests.get(
        f"{live_server}/api/environments/doesnotexist/integrity",
        headers={"X-Nginx-Proxy-Secret": "test-proxy-secret"},
        timeout=5,
    )
    assert resp.status_code == 404
