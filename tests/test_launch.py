"""launch.py: the desktop launcher (LNCH-01..04, LNCH-06)."""

import os
import signal
import socket
import subprocess
import sys

import pytest

import launch


@pytest.fixture
def no_prompt(monkeypatch):
    answers = []
    monkeypatch.setattr(launch, "_confirm", lambda prompt: answers.pop(0) if answers else False)
    return answers


# --- LNCH-02 ------------------------------------------------------------------


@pytest.mark.parametrize("version,ok", [((20, 18, 9), False), ((20, 19, 0), True), ((21, 7, 0), False),
                                        ((22, 11, 0), False), ((22, 12, 0), True), ((24, 1, 0), True), (None, False)])
def test_node_version_rule(version, ok):
    assert launch._node_version_ok(version) is ok


def test_a_too_old_node_after_install_says_so_instead_of_looping(monkeypatch, capsys):
    monkeypatch.setattr(launch, "_get_node_version", lambda: ("/usr/bin/node", (18, 19, 0)))
    monkeypatch.setattr(launch, "_offer_install_or_upgrade", lambda *a: True)
    assert launch.check_node() is False
    out = capsys.readouterr().out
    assert "v18.19.0 is installed but still too old" in out and "nodejs.org" in out
    assert "isn't visible in this session" not in out


def test_node_not_on_path_after_install_keeps_the_new_terminal_hint(monkeypatch, capsys):
    monkeypatch.setattr(launch, "_get_node_version", lambda: (None, None))
    monkeypatch.setattr(launch, "_offer_install_or_upgrade", lambda *a: True)
    assert launch.check_node() is False
    assert "isn't visible in this session" in capsys.readouterr().out


def test_pacman_never_refreshes_without_upgrading():
    for component in launch._INSTALL_COMMANDS.values():
        for argv in component["pacman"]:
            assert not any(a.startswith("-S") and "y" in a for a in argv), argv
            assert "--needed" in argv


def test_missing_node_is_not_fatal_when_a_build_exists(monkeypatch, tmp_path):
    index = tmp_path / "index.html"
    index.write_text("x")
    monkeypatch.setattr(launch, "FRONTEND_DIST_INDEX", index)
    monkeypatch.setattr(launch, "check_python", lambda: True)
    monkeypatch.setattr(launch, "check_node", lambda: False)
    monkeypatch.setattr(launch, "ensure_python_deps", lambda: None)
    assert launch.check_prerequisites() == (True, False)
    index.unlink()
    assert launch.check_prerequisites() == (False, False)


def _no_keyring(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "keyring":
            raise ImportError("no keyring")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)


def test_keyring_goes_into_a_project_venv_and_the_launcher_restarts_in_it(monkeypatch, tmp_path, no_prompt):
    _no_keyring(monkeypatch)
    venv = tmp_path / ".venv"
    monkeypatch.setattr(launch, "VENV_DIR", venv)
    ran, relaunched = [], []

    def fake_run(argv, **kwargs):
        ran.append([str(a) for a in argv])
        if argv[1:3] == ["-m", "venv"]:
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").write_text("")
            (venv / "Scripts").mkdir()
            (venv / "Scripts" / "python.exe").write_text("")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(launch.subprocess, "run", fake_run)
    monkeypatch.setattr(launch, "_keyring_importable", lambda python: True)
    monkeypatch.setattr(launch, "_relaunch_with", lambda python: relaunched.append(python))
    no_prompt.append(True)
    launch.ensure_python_deps()
    assert ran[0][1:3] == ["-m", "venv"]
    assert ran[1][0] == str(launch._venv_python()) and ran[1][1:4] == ["-m", "pip", "install"]
    assert relaunched == [launch._venv_python()]


def test_a_failed_pip_install_is_reported_not_ignored(monkeypatch, tmp_path, no_prompt, capsys):
    _no_keyring(monkeypatch)
    venv = tmp_path / ".venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("")
    (venv / "Scripts").mkdir()
    (venv / "Scripts" / "python.exe").write_text("")
    monkeypatch.setattr(launch, "VENV_DIR", venv)
    monkeypatch.setattr(launch.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1))
    monkeypatch.setattr(launch, "_relaunch_with", lambda python: pytest.fail("must not relaunch"))
    no_prompt.append(True)
    launch.ensure_python_deps()
    assert "pip exited with code 1" in capsys.readouterr().out


def test_venv_creation_failure_names_the_missing_package(monkeypatch, tmp_path, no_prompt, capsys):
    _no_keyring(monkeypatch)
    monkeypatch.setattr(launch, "VENV_DIR", tmp_path / ".venv")
    monkeypatch.setattr(launch.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1))
    no_prompt.append(True)
    launch.ensure_python_deps()
    assert "python3-venv" in capsys.readouterr().out


def test_an_existing_venv_is_used_when_this_python_lacks_keyring(monkeypatch, tmp_path):
    _no_keyring(monkeypatch)
    venv = tmp_path / ".venv"
    monkeypatch.setattr(launch, "VENV_DIR", venv)
    py = launch._venv_python()
    py.parent.mkdir(parents=True)
    py.write_text("")
    monkeypatch.delenv(launch._REEXEC_MARKER, raising=False)
    monkeypatch.setattr(launch, "_keyring_importable", lambda python: True)
    relaunched = []
    monkeypatch.setattr(launch, "_relaunch_with", lambda python: relaunched.append(python))
    launch.use_project_venv_if_present()
    assert relaunched == [py]
    # already running inside .venv (whose python is a symlink to the base
    # interpreter, so paths can't tell): no relaunch
    monkeypatch.setattr(launch.sys, "prefix", str(venv))
    launch.use_project_venv_if_present()
    assert relaunched == [py]
    monkeypatch.setattr(launch.sys, "prefix", "/usr")
    # never loops: after one relaunch the marker stops it
    monkeypatch.setenv(launch._REEXEC_MARKER, "1")
    launch.use_project_venv_if_present()
    assert relaunched == [py]


# --- LNCH-03 ------------------------------------------------------------------


@pytest.fixture
def frontend(tmp_path, monkeypatch):
    fe = tmp_path / "frontend"
    (fe / "src").mkdir(parents=True)
    (fe / "src" / "main.tsx").write_text("x")
    (fe / "package.json").write_text("{}")
    monkeypatch.setattr(launch, "FRONTEND_DIR", fe)
    monkeypatch.setattr(launch, "FRONTEND_DIST_INDEX", fe / "dist" / "index.html")
    monkeypatch.setattr(launch.shutil, "which", lambda name: f"/usr/bin/{name}")
    return fe


def _touch_dist(fe, newer=True):
    dist = fe / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("built")
    src_time = (fe / "src" / "main.tsx").stat().st_mtime
    t = src_time + 10 if newer else src_time - 10
    os.utime(dist / "index.html", (t, t))


def test_an_up_to_date_build_is_not_rebuilt(frontend, monkeypatch):
    _touch_dist(frontend, newer=True)
    monkeypatch.setattr(launch.subprocess, "run", lambda *a, **k: pytest.fail("no build expected"))
    launch.build_frontend()


def test_a_changed_source_is_rebuilt(frontend, monkeypatch):
    _touch_dist(frontend, newer=False)
    ran = []
    monkeypatch.setattr(launch.subprocess, "run", lambda argv, **k: ran.append(argv) or subprocess.CompletedProcess(argv, 0))
    launch.build_frontend()
    assert ran == [["/usr/bin/npm", "run", "build"]]


def test_a_failed_build_with_nothing_to_serve_stops(frontend, monkeypatch, capsys):
    monkeypatch.setattr(launch.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 1))
    asked = []
    monkeypatch.setattr(launch, "_confirm", lambda prompt: asked.append(prompt) or False)
    with pytest.raises(SystemExit) as exc:
        launch.build_frontend()
    assert exc.value.code == 1
    assert "no previous build to serve" in capsys.readouterr().out
    assert not any("previous build anyway" in q for q in asked)  # nothing stale to offer


def test_a_failed_build_offers_npm_ci_and_retries(frontend, monkeypatch, no_prompt):
    (frontend / "node_modules" / "x").mkdir(parents=True)
    results = iter([1, 0, 0])
    ran = []
    monkeypatch.setattr(launch.subprocess, "run",
                        lambda argv, **k: ran.append(argv) or subprocess.CompletedProcess(argv, next(results)))
    no_prompt.append(True)
    launch.build_frontend()
    assert ran == [["/usr/bin/npm", "run", "build"], ["/usr/bin/npm", "ci"], ["/usr/bin/npm", "run", "build"]]


def test_a_failed_build_asks_before_serving_a_stale_one(frontend, monkeypatch, no_prompt):
    _touch_dist(frontend, newer=False)
    monkeypatch.setattr(launch.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 1))
    no_prompt.extend([False, False])  # no npm ci, then: don't start with the stale build
    with pytest.raises(SystemExit):
        launch.build_frontend()
    no_prompt.extend([False, True])  # ... and yes, start anyway
    launch.build_frontend()


def test_no_npm_and_no_build_stops(frontend, monkeypatch):
    with pytest.raises(SystemExit):
        launch.build_frontend(node_ok=False)
    _touch_dist(frontend, newer=False)
    launch.build_frontend(node_ok=False)  # existing build is served


# --- LNCH-01 ------------------------------------------------------------------


def test_only_this_checkouts_serve_py_matches(tmp_path):
    ours = str(launch.SERVER_SCRIPT)
    assert launch._is_this_checkouts_server([sys.executable, ours, "--port", "1"], None, None)
    assert launch._is_this_checkouts_server([sys.executable, "server/serve.py"], None, str(launch.PROJECT_ROOT))
    assert not launch._is_this_checkouts_server([sys.executable, "server/serve.py"], None, str(tmp_path))
    assert not launch._is_this_checkouts_server([sys.executable, str(tmp_path / "server" / "serve.py")], None, None)
    assert not launch._is_this_checkouts_server(["vim", "serve.py"], None, str(tmp_path))
    assert not launch._is_this_checkouts_server(["tail", "-f", "serve.py.log"], None, None)
    assert launch._is_this_checkouts_server(None, f"python {ours} --no-browser", None)
    assert not launch._is_this_checkouts_server(None, "python /other/server/serve.py", None)


def _listen_child(script_arg):
    """A real process listening on a free loopback port, whose argv names
    `script_arg` (it never runs it)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    code = ("import socket, sys, time\n"
            f"s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {port})); s.listen()\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n")
    proc = subprocess.Popen([sys.executable, "-c", code, script_arg], stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "ready"
    return proc, port


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process tools")
def test_the_listener_is_found_by_port(tmp_path):
    proc, port = _listen_child(str(tmp_path / "unrelated" / "serve.py"))
    try:
        if launch._listening_pid(port) is None:
            pytest.skip("no lsof and no /proc on this host")
        assert launch._listening_pid(port) == proc.pid
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process tools")
def test_another_projects_server_on_the_port_is_left_alone(tmp_path, no_prompt, capsys):
    proc, port = _listen_child(str(tmp_path / "other-project" / "server" / "serve.py"))
    try:
        no_prompt.append(True)  # even a "yes" must not be asked for
        launch.stop_stale_server(port)
        assert proc.poll() is None
        out = capsys.readouterr().out
        assert "not this folder's dashboard server" in out or "couldn't identify" in out
        assert no_prompt == [True]
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process tools")
def test_our_leftover_server_is_stopped_gracefully_after_asking(no_prompt):
    proc, port = _listen_child(str(launch.SERVER_SCRIPT))
    try:
        if launch._listening_pid(port) is None:
            pytest.skip("no lsof and no /proc on this host")
        no_prompt.append(False)
        launch.stop_stale_server(port)
        assert proc.poll() is None  # declined: left running
        no_prompt.append(True)
        launch.stop_stale_server(port)
        assert proc.wait(timeout=10) == -signal.SIGTERM  # SIGTERM, not SIGKILL
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_stop_escalates_only_after_the_grace_period(monkeypatch):
    sent = []
    monkeypatch.setattr(launch, "IS_WINDOWS", False)
    monkeypatch.setattr(launch.os, "kill", lambda pid, sig: sent.append(sig))
    monkeypatch.setattr(launch, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(launch.time, "sleep", lambda s: None)
    t = iter([0.0, 1.0, 2.0, 9.0, 9.0])
    monkeypatch.setattr(launch.time, "monotonic", lambda: next(t))
    assert launch._stop_pid(1234, grace=5.0)
    assert sent == [signal.SIGTERM, signal.SIGKILL]


# --- LNCH-04 / LNCH-06 -----------------------------------------------------------


def test_posix_launcher_execs_the_server(monkeypatch):
    monkeypatch.setattr(launch, "IS_WINDOWS", False)
    calls = []

    class Replaced(Exception):
        """os.execv never returns; stand in for 'the process image is gone'."""

    def fake_execv(path, argv):
        calls.append((path, argv))
        raise Replaced

    monkeypatch.setattr(launch.os, "execv", fake_execv)
    monkeypatch.setattr(launch.subprocess, "Popen", lambda *a, **k: pytest.fail("no child on POSIX"))
    with pytest.raises(Replaced):
        launch.start_server(["--port", "9"])
    assert calls == [(sys.executable, [sys.executable, str(launch.SERVER_SCRIPT), "--port", "9"])]


class _FakeProc:
    def __init__(self, codes):
        self.codes = list(codes)
        self.timeouts = []
        self.terminated = self.killed = False

    def wait(self, timeout=None):
        self.timeouts.append(timeout)
        code = self.codes.pop(0)
        if isinstance(code, BaseException):
            raise code
        return code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


def test_windows_launcher_exits_with_the_servers_status(monkeypatch):
    monkeypatch.setattr(launch, "IS_WINDOWS", True)
    monkeypatch.setattr(launch.subprocess, "Popen", lambda argv: _FakeProc([3]))
    with pytest.raises(SystemExit) as exc:
        launch.start_server([])
    assert exc.value.code == 3


def test_windows_ctrl_c_gives_the_server_time_then_terminates(monkeypatch):
    monkeypatch.setattr(launch, "IS_WINDOWS", True)
    # Ctrl+C, a second Ctrl+C while waiting (doesn't abandon it), then the grace period runs out
    proc = _FakeProc([KeyboardInterrupt(), KeyboardInterrupt(), subprocess.TimeoutExpired("x", 10), 0])
    monkeypatch.setattr(launch.subprocess, "Popen", lambda argv: proc)
    with pytest.raises(SystemExit) as exc:
        launch.start_server([])
    assert proc.terminated and not proc.killed and exc.value.code == 0


def test_main_runs_from_the_checkout(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    seen = []
    monkeypatch.setattr(sys, "argv", ["launch.py", "--skip-checks"])
    monkeypatch.setattr(launch, "use_project_venv_if_present", lambda: None)
    monkeypatch.setattr(launch, "build_frontend", lambda node_ok=True: seen.append(os.getcwd()))
    monkeypatch.setattr(launch, "stop_stale_server", lambda port: None)
    monkeypatch.setattr(launch, "start_server", lambda args: seen.append(args))
    launch.main()
    assert seen == [str(launch.PROJECT_ROOT), []]
    os.chdir(tmp_path)


def test_wrapper_script_refuses_an_old_python(tmp_path):
    if sys.platform == "win32":
        pytest.skip("sh wrapper")
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "python3").write_text("#!/bin/sh\n"
                                  "case \"$*\" in *version_info*) exit 1;; esac\n"
                                  "echo launched\n")
    (fake / "python3").chmod(0o755)
    script = launch.PROJECT_ROOT / "start-wizard.sh"
    proc = subprocess.run(["bash", str(script)], env={**os.environ, "PATH": f"{fake}:/usr/bin:/bin"},
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0 and "3.9" in proc.stderr and "launched" not in proc.stdout
    (fake / "python3").write_text("#!/bin/sh\necho launched\n")
    proc = subprocess.run(["bash", str(script)], env={**os.environ, "PATH": f"{fake}:/usr/bin:/bin"},
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "launched" in proc.stdout


def test_running_in_project_venv_detects_a_real_venv(tmp_path, monkeypatch):
    """A real venv's python is a symlink to the base interpreter, so only
    sys.prefix tells them apart (review finding)."""
    import venv
    target = tmp_path / ".venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(target)
    out = subprocess.run([str(target / ("Scripts/python.exe" if launch.IS_WINDOWS else "bin/python")), "-c",
                          "import sys; print(sys.prefix)"], capture_output=True, text=True).stdout.strip()
    monkeypatch.setattr(launch, "VENV_DIR", target)
    monkeypatch.setattr(launch.sys, "prefix", out)
    assert launch._running_in_project_venv()
    monkeypatch.setattr(launch.sys, "prefix", sys.base_prefix)
    assert not launch._running_in_project_venv()


def test_windows_relaunch_keeps_the_grace_period(monkeypatch):
    monkeypatch.setattr(launch, "IS_WINDOWS", True)
    # the outer launcher never terminates the inner one: it just keeps waiting
    proc = _FakeProc([KeyboardInterrupt(), KeyboardInterrupt(), 0])
    monkeypatch.setattr(launch.subprocess, "Popen", lambda argv: proc)
    with pytest.raises(SystemExit) as exc:
        launch._relaunch_with("C:/x/.venv/Scripts/python.exe")
    assert exc.value.code == 0 and not proc.terminated and not proc.killed
    assert proc.timeouts == [None, None, None]  # never a grace deadline of its own
    monkeypatch.delenv(launch._REEXEC_MARKER, raising=False)
