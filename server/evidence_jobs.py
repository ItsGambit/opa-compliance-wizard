"""Evidence package jobs (5.53.0, WP4): the state of builds and where finished packages live.

No HTTP, no permissions, no building here: server/serve.py checks who may do what, starts the worker thread and
logs; evidence_package.py builds. This module owns

  * the job table (one build at a time server-wide, which also means one per environment),
  * the binding of a job to the person who started it (caller sub + gate issuer + login-session fingerprint + job id),
  * the packages folder ($DATA_DIR/packages/<job id>/, folder 0700, file 0600) and its clean-up:
    everything left from an earlier run is deleted at start-up, a finished package is deleted when its download window
    (15 minutes after it was built) ends, and a failed build leaves nothing behind.

A job id is random (192 bits) and is validated against a fixed pattern before it is ever joined to a path.
"""
import hmac
import os
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone

DOWNLOAD_WINDOW_SECONDS = 15 * 60
TOMBSTONE_SECONDS = 24 * 60 * 60      # an expired or failed job is remembered this long so the answer is "expired", not "unknown"
PACKAGE_FILE = "evidence-package.zip"
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$", re.ASCII)
ERROR_MAX_CHARS = 400


class Busy(Exception):
    """Another build is running. `reason` is `build_running_environment` or `build_running_server`."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Registry:
    def __init__(self, packages_dir_fn, window_seconds=DOWNLOAD_WINDOW_SECONDS, clock=time.monotonic, wall=None):
        self._dir_fn = packages_dir_fn
        self.window_seconds = window_seconds
        self._clock = clock
        self._wall = wall or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._jobs = {}
        self._timers = set()
        self.startup_skipped = None

    # -- folder ------------------------------------------------------------------------------
    def packages_dir(self):
        return self._dir_fn()

    def _ensure_dir(self, path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass

    def job_dir(self, job_id):
        if not JOB_ID_RE.match(job_id or ""):
            raise ValueError("not a job id")
        return os.path.join(self.packages_dir(), job_id)

    def package_path(self, job_id):
        return os.path.join(self.job_dir(job_id), PACKAGE_FILE)

    def cleanup_startup(self):
        """Deletes everything under the packages folder: no job survives a restart (the table is in memory, and a package
        whose window is unknown is not kept). Returns the number of entries removed."""
        base = self.packages_dir()
        removed = 0
        if os.path.islink(base):
            # Never follow a link: if the folder itself was replaced by one, nothing behind it is ours to delete.
            self.startup_skipped = "the packages folder is a symbolic link"
            return 0
        if os.path.isdir(base):
            for name in os.listdir(base):
                full = os.path.join(base, name)
                try:
                    if os.path.isdir(full) and not os.path.islink(full):
                        shutil.rmtree(full)
                    else:
                        os.remove(full)
                    removed += 1
                except OSError:
                    pass
        return removed

    def _remove_dir(self, job_id):
        try:
            shutil.rmtree(self.job_dir(job_id), ignore_errors=True)
        except ValueError:
            pass

    # -- lifecycle -----------------------------------------------------------------------------
    def reset(self):
        """Forgets every job and cancels the timers (tests; a clean start)."""
        with self._lock:
            self._jobs.clear()
            timers, self._timers = self._timers, set()
        for t in timers:
            t.cancel()

    def running(self):
        with self._lock:
            return any(j["status"] == "running" for j in self._jobs.values())

    def waiting_until(self):
        """The ISO time (UTC) the latest finished package's download window ends, or None when no package is still in its window.
        The upgrade preflight uses it: a restart deletes packages."""
        with self._lock:
            gone = self._expire_locked()
            ends = [j["expires_at"] for j in self._jobs.values() if j["status"] == "done"]
        for g in gone:
            self._remove_dir(g)
        return max(ends) if ends else None

    def start(self, spec):
        """Registers a new job (status running) and creates its folder. `spec`: environment_id, environment_name, period
        (start/end dates as strings), gaps_acknowledged, owner (sub or ""), issuer, fingerprint, mode. Raises Busy."""
        with self._lock:
            self._expire_locked()
            for j in self._jobs.values():
                if j["status"] != "running":
                    continue
                if j["environment_id"] == spec["environment_id"]:
                    raise Busy("build_running_environment", "A package is already being built for this environment. Wait for it to finish.")
                raise Busy("build_running_server", "Another evidence package is being built on this server. Try again in a few minutes.")
            job_id = secrets.token_urlsafe(24)
            now = self._clock()
            job = {
                "job_id": job_id, "status": "running", "stage": "Starting", "progress": 0.0,
                "environment_id": spec["environment_id"], "environment_name": spec["environment_name"],
                "period": dict(spec["period"]), "gaps_acknowledged": bool(spec["gaps_acknowledged"]),
                "owner": spec.get("owner") or "", "issuer": spec.get("issuer") or "", "fingerprint": spec.get("fingerprint") or "",
                "mode": spec.get("mode", "hosted"),
                "started_at": _iso(self._wall()), "started_mono": now, "finished_at": None, "finished_mono": None,
                "expires_at": None, "expires_mono": None, "error": None, "reason": None, "result": None, "filename": None,
            }
            self._jobs[job_id] = job
        try:
            self._ensure_dir(self.packages_dir())
            self._ensure_dir(self.job_dir(job_id))
        except OSError:
            with self._lock:
                self._jobs.pop(job_id, None)
            raise
        return job_id

    def progress(self, job_id, stage, fraction):
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job["status"] == "running":
                job["stage"] = str(stage)[:80]
                job["progress"] = max(0.0, min(1.0, float(fraction)))

    def finish(self, job_id, result, filename):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            now = self._clock()
            job.update({
                "status": "done", "stage": "Done", "progress": 1.0, "result": dict(result), "filename": filename,
                "finished_at": _iso(self._wall()), "finished_mono": now,
                "expires_mono": now + self.window_seconds,
                "expires_at": _iso(self._wall() + timedelta(seconds=self.window_seconds)),
            })
        timer = threading.Timer(self.window_seconds + 1, self.sweep)
        timer.daemon = True
        with self._lock:
            self._timers.add(timer)
        timer.start()

    def fail(self, job_id, reason, message):
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.update({
                "status": "error", "stage": "Failed", "reason": reason, "error": str(message)[:ERROR_MAX_CHARS],
                "finished_at": _iso(self._wall()), "finished_mono": self._clock(),
            })
        self._remove_dir(job_id)

    def _expire_locked(self):
        """Marks done jobs whose window ended as expired and forgets old tombstones. Returns the ids whose folder to delete."""
        now = self._clock()
        gone = []
        for job_id, job in list(self._jobs.items()):
            if job["status"] == "done" and now >= job["expires_mono"]:
                job["status"] = "expired"
                job["stage"] = "Expired"
                gone.append(job_id)
            elif job["status"] in ("expired", "error") and job["finished_mono"] is not None and now - job["finished_mono"] > TOMBSTONE_SECONDS + self.window_seconds:
                self._jobs.pop(job_id, None)
        return gone

    def sweep(self):
        """Ends the download window of every finished package whose time is up: the file and its folder are deleted."""
        with self._lock:
            gone = self._expire_locked()
        for job_id in gone:
            self._remove_dir(job_id)
        return len(gone)

    # -- reads -----------------------------------------------------------------------------------
    def _bound(self, job, owner, issuer, fingerprint):
        # Every part must match; a missing session fingerprint (hosted, no cookie) matches nothing.
        if not fingerprint:
            return False
        a = f"{job['owner']}\x00{job['issuer']}\x00{job['fingerprint']}".encode("utf-8")
        b = f"{owner or ''}\x00{issuer or ''}\x00{fingerprint}".encode("utf-8")
        return hmac.compare_digest(a, b)

    def get(self, job_id, owner, issuer, fingerprint):
        """A copy of the job when it exists and belongs to this caller, else None (the caller answers 404 for both)."""
        if not JOB_ID_RE.match(job_id or ""):
            return None
        with self._lock:
            gone = self._expire_locked()
            job = self._jobs.get(job_id)
            snapshot = dict(job) if job and self._bound(job, owner, issuer, fingerprint) else None
        for g in gone:
            self._remove_dir(g)
        return snapshot

    def public(self, job):
        """The job as the status route shows it: no owner, issuer, fingerprint or path."""
        now = self._clock()
        out = {
            "job_id": job["job_id"], "status": job["status"], "stage": job["stage"], "progress": round(job["progress"], 3),
            "environment": job["environment_name"], "period": job["period"], "gaps_acknowledged": job["gaps_acknowledged"],
            "started_at": job["started_at"], "finished_at": job["finished_at"], "expires_at": job["expires_at"],
            "seconds_left": max(0, int(job["expires_mono"] - now)) if job["status"] == "done" else None,
            "error": job["error"], "reason": job["reason"], "window_seconds": self.window_seconds,
        }
        if job["status"] == "done" and job["result"]:
            r = job["result"]
            out["result"] = {k: r.get(k) for k in ("sha256", "bytes", "chain_head", "events", "report_rows", "coverage_pct", "gap_days",
                                                   "zero_days", "pruned_days", "built_at", "seconds", "data_as_of", "verifier_sha256")}
            out["result"]["filename"] = job["filename"]
        return out

    def open_for_download(self, job_id, owner, issuer, fingerprint):
        """('ok', job, path) | ('notfound', None, None) | ('expired', job, None) | ('notready', job, None). The job copy is the
        caller's own."""
        job = self.get(job_id, owner, issuer, fingerprint)
        if job is None:
            return "notfound", None, None
        if job["status"] == "expired":
            return "expired", job, None
        if job["status"] != "done":
            return "notready", job, None
        path = self.package_path(job_id)
        if not os.path.isfile(path):
            return "expired", job, None
        return "ok", job, path
