"""Covers Phase 3's pending_admin_actions table -- the server-held
record binding a step-up MFA approval to the EXACT payload reviewed,
closing the gap where a step-up cookie (previously valid for ANY
payload submitted within its 120s TTL) could be used to apply a
DIFFERENT access_control.json change than the one the admin actually
looked at.

Uses audit_store.run_migrations() (schema only), matching every other
test file's established pattern -- no need for tmp_environments_file
here since nothing in this file calls init_db()."""
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import audit_store
import create_secret_folders as engine

ACTOR_A = "00uActorA"
ACTOR_B = "00uActorB"


def test_create_then_consume_round_trip_returns_the_exact_payload(tmp_audit_store):
    audit_store.run_migrations()
    payload = {"admin_group_id": "00gAdmin", "user_group_id": None, "restrict_login": True}

    action_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)
    consumed = audit_store.consume_pending_admin_action(action_id, ACTOR_A)

    assert consumed == payload


def test_action_id_is_unguessable_and_unique(tmp_audit_store):
    audit_store.run_migrations()
    payload = {"admin_group_id": None, "user_group_id": None, "restrict_login": False}

    id_1 = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)
    id_2 = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)

    assert id_1 != id_2
    assert len(id_1) > 20  # secrets.token_urlsafe(32) -- not a short/sequential id


def test_second_consume_attempt_fails_already_consumed(tmp_audit_store):
    """The actual regression this phase exists to prevent: a step-up
    cookie, once used to apply a change, must never be replayable to
    apply it (or anything else) a second time."""
    audit_store.run_migrations()
    payload = {"admin_group_id": "00gAdmin", "user_group_id": None, "restrict_login": True}
    action_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)

    audit_store.consume_pending_admin_action(action_id, ACTOR_A)

    with pytest.raises(audit_store.PendingActionError) as exc_info:
        audit_store.consume_pending_admin_action(action_id, ACTOR_A)
    assert exc_info.value.reason == "already_consumed"


def test_consume_fails_not_found_for_unknown_action_id(tmp_audit_store):
    audit_store.run_migrations()
    with pytest.raises(audit_store.PendingActionError) as exc_info:
        audit_store.consume_pending_admin_action("nonexistent-action-id", ACTOR_A)
    assert exc_info.value.reason == "not_found"


def test_consume_fails_actor_mismatch_for_a_different_subs_action(tmp_audit_store):
    """A step-up cookie's sub must match the pending action's actor_sub --
    otherwise a step-up cookie belonging to one admin could be used to
    apply a DIFFERENT admin's prepared (and reviewed) change."""
    audit_store.run_migrations()
    payload = {"admin_group_id": "00gAdmin", "user_group_id": None, "restrict_login": True}
    action_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)

    with pytest.raises(audit_store.PendingActionError) as exc_info:
        audit_store.consume_pending_admin_action(action_id, ACTOR_B)
    assert exc_info.value.reason == "actor_mismatch"

    # Confirmed NOT consumed by the failed attempt -- the real actor can still use it.
    consumed = audit_store.consume_pending_admin_action(action_id, ACTOR_A)
    assert consumed == payload


def test_consume_fails_expired_after_ttl_elapses(tmp_audit_store):
    audit_store.run_migrations()
    payload = {"admin_group_id": None, "user_group_id": "00gUser", "restrict_login": False}
    # ttl_seconds=-1 -- expires_at is already in the past the instant it's created,
    # simulating "the admin took too long to complete the Okta redirect."
    action_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=-1)

    with pytest.raises(audit_store.PendingActionError) as exc_info:
        audit_store.consume_pending_admin_action(action_id, ACTOR_A)
    assert exc_info.value.reason == "expired"


def test_payload_hash_is_stable_for_the_same_payload_regardless_of_key_order(tmp_audit_store):
    audit_store.run_migrations()
    payload_a = {"admin_group_id": "00gX", "user_group_id": "00gY", "restrict_login": True}
    payload_b = {"restrict_login": True, "user_group_id": "00gY", "admin_group_id": "00gX"}

    id_a = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload_a, ttl_seconds=900)
    id_b = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload_b, ttl_seconds=900)

    conn = audit_store._get_connection()
    hash_a = conn.execute("SELECT payload_hash FROM pending_admin_actions WHERE action_id = ?", (id_a,)).fetchone()["payload_hash"]
    hash_b = conn.execute("SELECT payload_hash FROM pending_admin_actions WHERE action_id = ?", (id_b,)).fetchone()["payload_hash"]
    assert hash_a == hash_b  # canonical (sorted-keys) hashing is key-order-independent


def test_cleanup_removes_expired_unconsumed_rows_but_not_live_ones(tmp_audit_store):
    audit_store.run_migrations()
    payload = {"admin_group_id": None, "user_group_id": None, "restrict_login": False}
    expired_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=-1)
    live_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)

    audit_store._cleanup_expired_pending_admin_actions()

    conn = audit_store._get_connection()
    remaining_ids = {row["action_id"] for row in conn.execute("SELECT action_id FROM pending_admin_actions")}
    assert expired_id not in remaining_ids
    assert live_id in remaining_ids


def test_cleanup_does_not_remove_an_expired_but_already_consumed_row(tmp_audit_store):
    """An expired-and-consumed row is historical record of a real,
    already-applied change -- the cleanup sweep only targets ABANDONED
    (never-consumed) actions, not every row past its expiry."""
    audit_store.run_migrations()
    payload = {"admin_group_id": None, "user_group_id": None, "restrict_login": False}
    action_id = audit_store.create_pending_admin_action(ACTOR_A, "access_control.update", payload, ttl_seconds=900)
    audit_store.consume_pending_admin_action(action_id, ACTOR_A)

    conn = audit_store._get_connection()
    # Force the row into the past (simulating time passing after consumption).
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conn.execute("UPDATE pending_admin_actions SET expires_at = ? WHERE action_id = ?", (past, action_id))
    conn.commit()

    audit_store._cleanup_expired_pending_admin_actions()

    remaining_ids = {row["action_id"] for row in conn.execute("SELECT action_id FROM pending_admin_actions")}
    assert action_id in remaining_ids


# ---------------------------------------------------------------------------
# HTTP route round-trip -- /prepare -> /save consuming EXACTLY the prepared
# payload, even when the request body sent to /save differs. This is the
# actual regression this phase exists to prevent: before Phase 3, /save
# trusted its own request body for the settings, so a step-up cookie
# (proving only "fresh MFA happened," never "for THIS payload") could be
# replayed with ANY body within its TTL. Same live_server pattern as
# test_two_owner_collision.py/test_ingestion_manifest.py, kept local to
# this file per those files' own precedent.
# ---------------------------------------------------------------------------
@pytest.fixture
def tmp_access_control_file(tmp_path, monkeypatch):
    path = tmp_path / "access_control.json"
    monkeypatch.setattr(engine, "_access_control_file_path", lambda: str(path))
    return path


@pytest.fixture
def live_server(tmp_audit_store, tmp_environments_file, tmp_access_control_file, fake_keyring, tmp_audit_log, monkeypatch):
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


def _admin_headers(action_id=None):
    headers = {
        "X-Nginx-Proxy-Secret": "test-proxy-secret",
        "X-Auth-Is-Admin": "true",
        "X-Auth-Sub": "00uADMIN",
    }
    if action_id is not None:
        headers["X-Auth-Action-Id"] = action_id
    return headers


def test_prepare_then_save_applies_exactly_the_prepared_payload_not_the_save_body(live_server):
    reviewed = {"admin_group_id": "00gReviewed", "user_group_id": None, "restrict_login": True}

    prepare_resp = requests.post(
        f"{live_server}/api/access_control/prepare", json=reviewed, headers=_admin_headers(), timeout=5,
    )
    assert prepare_resp.status_code == 200, prepare_resp.text
    action_id = prepare_resp.json()["action_id"]

    # Sends a DIFFERENT payload in /save's own request body -- Phase 3's
    # whole point is that this must be ignored; the action_id is what
    # actually determines what gets applied.
    tampered_body = {"admin_group_id": "00gAttacker", "user_group_id": "00gAttacker", "restrict_login": False}
    save_resp = requests.post(
        f"{live_server}/api/access_control/save", json=tampered_body, headers=_admin_headers(action_id), timeout=5,
    )
    assert save_resp.status_code == 200, save_resp.text
    assert save_resp.json() == reviewed  # the REVIEWED payload won, not the tampered save-body

    get_resp = requests.get(f"{live_server}/api/access_control", headers=_admin_headers(), timeout=5)
    assert get_resp.json() == reviewed


def test_save_without_an_action_id_is_rejected(live_server):
    resp = requests.post(
        f"{live_server}/api/access_control/save", json={}, headers=_admin_headers(), timeout=5,
    )
    assert resp.status_code == 409
    assert resp.json()["reason"] == "not_found"


def test_replaying_the_same_action_id_a_second_time_is_rejected(live_server):
    """The real replay scenario this phase closes: a step-up cookie
    (carrying one action_id) must not authorize two separate saves."""
    reviewed = {"admin_group_id": "00gReviewed", "user_group_id": None, "restrict_login": True}
    prepare_resp = requests.post(
        f"{live_server}/api/access_control/prepare", json=reviewed, headers=_admin_headers(), timeout=5,
    )
    action_id = prepare_resp.json()["action_id"]

    first = requests.post(
        f"{live_server}/api/access_control/save", json={}, headers=_admin_headers(action_id), timeout=5,
    )
    assert first.status_code == 200

    second = requests.post(
        f"{live_server}/api/access_control/save", json={}, headers=_admin_headers(action_id), timeout=5,
    )
    assert second.status_code == 409
    assert second.json()["reason"] == "already_consumed"
