"""The combined Refresh (5.51.0): one job per environment with three independently reported parts.

This module holds the parts that need no server state: the vocabulary (parts, states, deadlines), the job record with its
lock, the per-part outcome wording, and the summary line. server/serve.py conducts the existing OPA-scan, System Log sync and
Okta-capture jobs and records what happened here. Every message names what happened, whether anything changed and what to do;
none carries a URL, a name or an e-mail address."""
import threading
import time
import uuid
from datetime import datetime, timezone

PARTS = ("opa", "okta", "log")  # display order; "opa" and "log"/"okta" run in two lanes
PART_LABELS = {"opa": "OPA scan", "okta": "Okta scan", "log": "System Log"}
OKTA_SUBS = ("admins", "principal_status", "inventory", "mfa_aggregates")
OKTA_SUB_LABELS = {
    "admins": "Okta admin roles", "principal_status": "Okta status of OPA users", "inventory": "Inventory counts",
    "mfa_aggregates": "Sign-in and MFA figures",
}
TRIGGERS = ("manual", "scheduled", "explorer")

# Wall-clock budget of each part, from the part's own start. On expiry the part is timed_out and asked to stop at its next
# checkpoint; the job does not wait for it beyond KILL_GRACE_SECS more.
PART_DEADLINES_SECS = {"opa": 45 * 60, "log": 90 * 60, "okta": 30 * 60}
KILL_GRACE_SECS = 60

PENDING, RUNNING = "pending", "running"
TERMINAL_STATES = ("ok", "refused", "error", "skipped", "cancelled", "timed_out", "partial")
ACTIVE_STATES = (PENDING, RUNNING)
COMPLETED_STATES = ("ok",)


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def normalize_parts(parts):
    """The requested parts, de-duplicated and in display order; ValueError (with a message for the caller) on anything
    that is not a non-empty list of known part names."""
    if parts is None:
        return list(PARTS)
    if not isinstance(parts, list) or not parts or len(parts) > len(PARTS) or not all(isinstance(p, str) for p in parts):
        raise ValueError(f"parts must be a non-empty list drawn from {list(PARTS)}")
    unknown = [p for p in parts if p not in PARTS]
    if unknown:
        raise ValueError(f"unknown part {unknown[0][:40]!r}; parts must be drawn from {list(PARTS)}")
    return [p for p in PARTS if p in parts]


def capabilities_for(part):
    """The shared-environment capabilities a part needs (the same ones its single-purpose button needs today)."""
    return {"opa": ("live_read",), "log": ("sync_now",), "okta": ("live_read", "sync_now")}[part]


def format_time(iso):
    """'21 Oct 2026, 02:20 UTC' from a stored timestamp; the input unchanged when it does not parse."""
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return str(iso)
    return f"{dt.day} {dt.strftime('%b %Y, %H:%M')} UTC"


class RefreshJob:
    """The record of one refresh. All reads and writes of its fields go through the lock; status() returns a plain copy."""

    def __init__(self, environment_id, parts, trigger, options=None):
        self.environment_id = environment_id
        self.job_id = uuid.uuid4().hex[:12]
        self.parts = list(parts)
        self.trigger = trigger
        self.options = dict(options or {})
        self.lock = threading.Lock()
        self.started_at = utc_now_iso()
        self.started_mono = time.monotonic()
        self.finished_at = None
        self.status = "running"
        self.cancel_requested = False
        self.cancelled_by = None
        self.cancel_events = {p: threading.Event() for p in PARTS}  # one per part: a deadline stops one part, a cancel stops all
        self.model_ready = threading.Event()  # set when the opa part is terminal (or was not requested)
        self.part_data = {p: {"state": PENDING if p in self.parts else "not_requested"} for p in PARTS}
        self.sub_data = {s: {"state": PENDING} for s in OKTA_SUBS}
        self.summary = None
        self.fresh_model = None  # the redacted model this refresh's OPA part read (the Okta part's counts use it)
        if "opa" not in self.parts:
            self.model_ready.set()

    # -- part bookkeeping ------------------------------------------------------------------------------------------
    def begin(self, part):
        with self.lock:
            data = self.part_data[part]
            if data["state"] in TERMINAL_STATES:
                return False
            data.update(state=RUNNING, started_at=utc_now_iso(), _started_mono=time.monotonic())
            return True

    def finish(self, part, state, message=None, **extra):
        """Records a part's terminal state once. Returns False (and changes nothing) if it already ended, e.g. the supervisor
        timed it out before the worker came back."""
        if state not in TERMINAL_STATES:
            raise ValueError(f"not a terminal state: {state}")
        with self.lock:
            data = self.part_data[part]
            if data["state"] in TERMINAL_STATES:
                return False
            data.update(state=state, finished_at=utc_now_iso(), **extra)
            if message is not None:
                data["message"] = message
            if part == "opa":
                self.model_ready.set()
            return True

    def part_state(self, part):
        with self.lock:
            return self.part_data[part]["state"]

    def set_sub(self, sub, state, message=None, **extra):
        with self.lock:
            self.sub_data[sub] = {"state": state, **({"message": message} if message else {}), **extra}

    def annotate(self, part, **fields):
        with self.lock:
            self.part_data[part].update(fields)

    def running_parts(self):
        with self.lock:
            return [p for p in self.parts if self.part_data[p]["state"] == RUNNING]

    def overdue(self, deadlines=None):
        """Parts that have been running longer than their deadline."""
        deadlines = deadlines or PART_DEADLINES_SECS
        now = time.monotonic()
        with self.lock:
            return [p for p in self.parts
                    if self.part_data[p]["state"] == RUNNING and now - self.part_data[p].get("_started_mono", now) > deadlines[p]]

    def all_terminal(self):
        with self.lock:
            return all(self.part_data[p]["state"] in TERMINAL_STATES for p in self.parts)

    def request_cancel(self, by=None):
        with self.lock:
            first = not self.cancel_requested
            self.cancel_requested = True
            if first:
                self.cancelled_by = by
        for event in self.cancel_events.values():
            event.set()
        return first

    def is_cancelled(self):
        return self.cancel_requested

    def conclude(self):
        with self.lock:
            self.status = "done"
            self.finished_at = utc_now_iso()
            self.summary = summary_line({p: self.part_data[p] for p in self.parts})

    # -- reading -----------------------------------------------------------------------------------------------------
    def outcome(self):
        with self.lock:
            return {p: self.part_data[p]["state"] for p in self.parts}

    def status_view(self, steps=None):
        """The JSON-able record for GET .../refresh/status. `steps` maps a part to its live step list (the OPA scan's and the
        sync's progress events live in their own dicts while they run)."""
        steps = steps or {}
        with self.lock:
            parts_out = {}
            for p in PARTS:
                data = {k: v for k, v in self.part_data[p].items() if not k.startswith("_")}
                if p in steps and "steps" not in data:
                    data["steps"] = steps[p]
                if p == "okta":
                    data["sub"] = {s: dict(v) for s, v in self.sub_data.items()}
                parts_out[p] = data
            return {
                "status": self.status, "job_id": self.job_id, "trigger": self.trigger, "started_at": self.started_at,
                "finished_at": self.finished_at, "parts_requested": list(self.parts), "parts": parts_out,
                "cancel_requested": self.cancel_requested, "summary": self.summary,
            }


def idle_view():
    return {"status": "idle", "job_id": None, "trigger": None, "started_at": None, "finished_at": None, "parts_requested": [],
            "parts": {p: {"state": "not_requested"} for p in PARTS}, "cancel_requested": False, "summary": None}


def summary_line(parts):
    """'2 of 3 parts completed; Okta scan refused' from {part: data}."""
    requested = [p for p in PARTS if p in parts]
    done = [p for p in requested if parts[p]["state"] == "ok"]
    if len(requested) == 1:
        state = parts[requested[0]]["state"]
        return f"{PART_LABELS[requested[0]]} completed." if state == "ok" else f"{PART_LABELS[requested[0]]} {_state_words(state)}."
    line = f"{len(done)} of {len(requested)} parts completed"
    others = [f"{PART_LABELS[p]} {_state_words(parts[p]['state'])}" for p in requested if parts[p]["state"] != "ok"]
    return line + ("; " + ", ".join(others) if others else "") + "."


def _state_words(state):
    return {"refused": "refused", "error": "failed", "skipped": "was skipped", "cancelled": "was stopped",
            "timed_out": "timed out", "partial": "stopped early", "pending": "did not run", "running": "is still running"}.get(state, state)


# -- the wording of each outcome (spec section 3.5) ---------------------------------------------------------------------
OPA_STEP_NOUNS = {
    "resource_groups": "resource groups", "groups": "groups", "users": "users", "workload_roles": "workload roles",
    "clients": "enrolled clients", "devices": "Okta-managed devices", "projects": "projects",
    "index_resources": "folders, secrets and resources", "user_groups": "user group memberships",
    "policies": "security policies", "resolve": "policy resolution",
}


def _previous(previous_built_at):
    return (f"The previous scan from {format_time(previous_built_at)} is kept." if previous_built_at
            else "No earlier scan exists, so nothing is shown yet.")


def opa_success_message(counts, warnings, stored, snapshot=None):
    bits = [f"{counts[k]} {k}" for k in ("users", "groups", "policies", "projects", "servers") if k in counts]
    text = "Scanned " + ", ".join(bits) + "." if bits else "Scan finished."
    if warnings:
        text += (f" Completed with {warnings} section{'s' if warnings != 1 else ''} the key cannot read "
                 "(shown empty, listed on the Access Explorer).")
    if stored == "memory_only":
        text += " Kept in memory only: the scan is larger than 96 MB, so it was not stored and will be read again after a restart."
    state = (snapshot or {}).get("state")
    if state == "sealed":
        text += f" Today's OPA access state ({snapshot.get('items')} records) was sealed into the evidence chain."
    elif state == "error":
        text += " Today's OPA access state could not be sealed; the scan itself is kept and the next refresh tries again."
    return text


def opa_failure(kind, status, failed_step, previous_built_at, error_class, key_path=None):
    """(state, message) for a failed OPA scan. kind: refused (401/403 on a section the model cannot do without), redaction,
    cancelled or error (the network, a 5xx, anything else)."""
    keep = _previous(previous_built_at)
    if kind == "refused":
        section = OPA_STEP_NOUNS.get(failed_step, "a required section")
        return "refused", (f"OPA refused the service key for {section} (HTTP {status}). {keep} "
                           "Check the key in Environments; the key needs read access to the team.")
    if kind == "redaction":
        where = f" at {key_path}" if key_path else ""
        return "error", (f"The scan was not stored: a value shaped like a credential was found{where}. Nothing was written. "
                         "Report this to the maintainers with the key path.")
    if kind == "cancelled":
        return "cancelled", f"Stopped before the scan finished. {keep}"
    return "error", (f"OPA did not answer as expected ({error_class}). {keep} "
                     "Try again; if it keeps failing, check the OPA host and the server's network.")


def log_failure(kind, status, previous_message=None):
    """(state, message) for the System Log part."""
    if kind == "refused":
        return "refused", (f"Okta refused the System Log read (HTTP {status}). Events stored before the refusal are kept. "
                           "The token needs permission to read the System Log.")
    if kind == "cancelled":
        return "cancelled", "Stopped on request. Events fetched before the stop are saved; the next run continues from there."
    if kind == "partial":
        return "partial", previous_message or "Stopped early; progress is saved and the next run continues."
    return "error", ("System Log sync stopped" + (f": {previous_message.rstrip('. ')}" if previous_message else "") +
                     ". Events fetched before the stop are saved; the next run continues from there. "
                     "Select \"Refresh\" to retry, or check the sync settings.")


def timed_out_message(part, minutes, previous_kept=True):
    return (f"Stopped after {minutes} minutes." + (" The previous data is kept." if previous_kept else "") +
            " Try again; if it keeps timing out, check the network between this server and the service.")


def cancelled_message(by_admin=True):
    return "Stopped by an administrator; previous data kept." if by_admin else "Stopped; previous data kept."
