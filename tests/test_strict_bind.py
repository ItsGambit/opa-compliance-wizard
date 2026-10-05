"""5.39.1: serve.py's StrictBindHTTPServer must (a) still refuse to bind over a LIVE listener on the
same port, and (b) on POSIX, bind while the previous server's closed connections are in TIME_WAIT
(the restart crash-loop seen live on 5.39.0's deploy)."""
import os
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler

import pytest

serve = pytest.importorskip("server.serve")


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def _start(port=0):
    srv = serve.StrictBindHTTPServer(("127.0.0.1", port), _Ok)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_second_instance_on_a_live_port_still_fails():
    first = _start()
    try:
        with pytest.raises(OSError):
            serve.StrictBindHTTPServer(("127.0.0.1", first.server_address[1]), _Ok)
    finally:
        first.shutdown()
        first.server_close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX SO_REUSEADDR semantics")
def test_restart_binds_while_old_connections_are_in_time_wait():
    first = _start()
    port = first.server_address[1]
    # Server-side close first (HTTP/1.0 response) leaves the server's end in TIME_WAIT.
    for _ in range(3):
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/").read() == b"ok"
    first.shutdown()
    first.server_close()
    second = serve.StrictBindHTTPServer(("127.0.0.1", port), _Ok)   # would raise EADDRINUSE before 5.39.1
    second.server_close()
