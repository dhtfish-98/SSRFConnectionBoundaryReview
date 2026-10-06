"""Real loopback HTTP endpoints and an intentionally misrouting test connector."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import DirectConnector, LabOnlyPolicy, ResolvedTarget
from .dns_lab import ControlledDnsServer, UdpLabResolver


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        lab: LabHttpServers = self.server.lab  # type: ignore[attr-defined]
        role: str = self.server.role  # type: ignore[attr-defined]
        with lab._lock:
            lab.requests.append({"role": role, "path": self.path, "host_header": self.headers.get("Host", "")})
        if role == "safe" and self.path == "/slow-drip":
            try:
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.send_header("Connection", "close")
                self.end_headers()
                for byte in b"ABCDEF":
                    self.wfile.write(bytes((byte,)))
                    self.wfile.flush()
                    time.sleep(0.18)
            except OSError:
                pass
            return
        if role == "safe" and self.path in ("/slow-redirect", "/delayed-ok", "/slow-retry"):
            time.sleep(0.24)
        if role == "internal":
            status, data, location = 200, b"SYNTHETIC_INTERNAL_MARKER", None
        elif self.path == "/slow-redirect":
            status, data, location = 302, b"", f"http://safe.lab.test:{lab.safe_port}/delayed-ok"
        elif self.path == "/slow-retry":
            status, data, location = 503, b"TRY_AGAIN", None
        elif self.path == "/redirect-internal":
            status, data, location = 302, b"", f"http://internal.lab.test:{lab.internal_port}/secret"
        elif self.path == "/redirect-safe":
            status, data, location = 302, b"", f"http://safe.lab.test:{lab.safe_port}/ok"
        elif self.path == "/retry":
            status, data, location = 503, b"TRY_AGAIN", None
        elif self.path == "/large":
            status, data, location = 200, b"X" * 256, None
        else:
            status, data, location = 200, b"SAFE_LOOPBACK_MARKER", None
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            if location:
                self.send_header("Location", location)
            self.send_header("Connection", "close")
            self.end_headers()
            if data:
                self.wfile.write(data)
        except OSError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class LabHttpServers:
    """Safe IPv4 and fake internal IPv6 endpoints; both bind to loopback only."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: list[dict[str, str]] = []
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []
        self.safe_port = 0
        self.internal_port = 0

    def __enter__(self) -> LabHttpServers:
        safe = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        internal = _IPv6Server(("::1", 0), _Handler)
        self.safe_port = safe.server_address[1]
        self.internal_port = internal.server_address[1]
        for server, role in ((safe, "safe"), (internal, "internal")):
            server.lab = self  # type: ignore[attr-defined]
            server.role = role  # type: ignore[attr-defined]
            self._servers.append(server)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=1)

    def request_count(self, role: str) -> int:
        with self._lock:
            return sum(row["role"] == role for row in self.requests)

    def dns_schedules(self) -> dict[str, list[tuple[str, ...]]]:
        return {
            "safe.lab.test": [("127.0.0.1",)],
            "internal.lab.test": [("::1",)],
            "flip.lab.test": [("127.0.0.1",), ("::1",)],
            "mixed.lab.test": [("127.0.0.1", "::1")],
        }

    def policy(self) -> LabOnlyPolicy:
        return LabOnlyPolicy({
            ("safe.lab.test", "127.0.0.1", self.safe_port),
            ("flip.lab.test", "127.0.0.1", self.safe_port),
            ("mixed.lab.test", "127.0.0.1", self.safe_port),
        })


class MisroutingConnector:
    """Test-only adapter that dials the forbidden endpoint instead of the chosen IP."""

    def __init__(self, internal_port: int) -> None:
        self.internal_port = internal_port

    def connect(self, target: ResolvedTarget, timeout: float) -> socket.socket:
        del target
        return DirectConnector().connect(ResolvedTarget(socket.AF_INET6, "::1", self.internal_port), timeout)


def make_lab_resolver(dns: ControlledDnsServer) -> UdpLabResolver:
    return UdpLabResolver(dns.port)
