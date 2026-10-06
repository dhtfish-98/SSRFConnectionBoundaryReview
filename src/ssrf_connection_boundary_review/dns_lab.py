"""A tiny loopback-only DNS fixture with scripted A/AAAA answer changes.

This is a deliberately narrow DNS wire-format subset for tests, not a general
resolver. It never forwards queries or answers with non-loopback addresses.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import socketserver
import struct
import threading
import time
from collections.abc import Mapping, Sequence

from .core import ResolvedTarget


def _question(message: bytes) -> tuple[str, int, bytes]:
    if len(message) < 17:
        raise ValueError("short_dns_query")
    _id, _flags, question_count, _answers, _authority, _additional = struct.unpack("!HHHHHH", message[:12])
    if question_count != 1:
        raise ValueError("one_question_required")
    labels: list[str] = []
    offset = 12
    while True:
        if offset >= len(message):
            raise ValueError("truncated_dns_name")
        length = message[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(message):
            raise ValueError("invalid_dns_label")
        labels.append(message[offset : offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 > len(message):
        raise ValueError("truncated_dns_question")
    qtype, qclass = struct.unpack("!HH", message[offset : offset + 4])
    if qclass != 1:
        raise ValueError("internet_class_required")
    return ".".join(labels), qtype, message[12 : offset + 4]


class _Server(socketserver.ThreadingUDPServer):
    daemon_threads = True


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        message, response_socket = self.request
        try:
            response = self.server.fixture.answer(message)  # type: ignore[attr-defined]
        except (ValueError, UnicodeDecodeError):
            return
        response_socket.sendto(response, self.client_address)


class ControlledDnsServer:
    """Schedule one address set per logical lookup; A starts each lookup."""

    def __init__(self, schedules: Mapping[str, Sequence[Sequence[str]]]) -> None:
        self.schedules: dict[str, tuple[tuple[str, ...], ...]] = {}
        for hostname, steps in schedules.items():
            name = hostname.lower()
            if not name.endswith(".lab.test") or not steps:
                raise ValueError("lab_dns_name_or_schedule")
            normalized: list[tuple[str, ...]] = []
            for step in steps:
                addresses = tuple(str(ipaddress.ip_address(x)) for x in step)
                if not addresses or any(not ipaddress.ip_address(x).is_loopback for x in addresses):
                    raise ValueError("lab_dns_answers_must_be_loopback")
                normalized.append(addresses)
            self.schedules[name] = tuple(normalized)
        self._next: dict[str, int] = {}
        self._current: dict[str, tuple[str, ...]] = {}
        self._lock = threading.Lock()
        self.queries: list[dict[str, object]] = []
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("dns_server_not_started")
        return self._server.server_address[1]

    def __enter__(self) -> ControlledDnsServer:
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.fixture = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def answer(self, message: bytes) -> bytes:
        host, qtype, question = _question(message)
        with self._lock:
            steps = self.schedules.get(host)
            if not steps:
                selected: tuple[str, ...] = ()
            elif qtype == 1:
                index = min(self._next.get(host, 0), len(steps) - 1)
                selected = steps[index]
                self._current[host] = selected
                self._next[host] = self._next.get(host, 0) + 1
            else:
                selected = self._current.get(host, steps[0])
            matching = [ipaddress.ip_address(x) for x in selected if ipaddress.ip_address(x).version == (4 if qtype == 1 else 6)]
            self.queries.append({"host": host, "type": "A" if qtype == 1 else "AAAA", "answers": [str(x) for x in matching]})
        header = struct.pack("!HHHHHH", struct.unpack("!H", message[:2])[0], 0x8000, 1, len(matching), 0, 0)
        records = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 0, len(x.packed)) + x.packed for x in matching)
        return header + question + records


class UdpLabResolver:
    """Query only a ControlledDnsServer bound to 127.0.0.1."""

    def __init__(self, port: int, *, timeout: float = 0.5) -> None:
        if not 1 <= port <= 65535 or timeout <= 0:
            raise ValueError("invalid_lab_dns_endpoint")
        self.port = port
        self.timeout = timeout

    def resolve(self, host: str, port: int) -> list[ResolvedTarget]:
        return self._resolve(host, port, None)

    def resolve_with_deadline(self, host: str, port: int, deadline: float) -> list[ResolvedTarget]:
        return self._resolve(host, port, deadline)

    def _resolve(self, host: str, port: int, deadline: float | None) -> list[ResolvedTarget]:
        def budget() -> float:
            if deadline is None:
                return self.timeout
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("whole_fetch_deadline")
            return min(self.timeout, remaining)

        budget()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if not host.endswith(".lab.test"):
                raise ValueError("uncontrolled_dns_name")
        else:
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
            return [ResolvedTarget(family, str(ip), port)]
        addresses: list[ResolvedTarget] = []
        for qtype, family in ((1, socket.AF_INET), (28, socket.AF_INET6)):
            query_timeout = budget()
            query_id = secrets.randbits(16)
            labels = host.encode("ascii").split(b".")
            name = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
            packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(query_timeout)
                connection.sendto(packet, ("127.0.0.1", self.port))
                response, peer = connection.recvfrom(4096)
            budget()
            if peer != ("127.0.0.1", self.port) or len(response) < 12:
                raise ValueError("invalid_dns_response_peer")
            response_id, flags, question_count, answer_count, _authority, _additional = struct.unpack("!HHHHHH", response[:12])
            if response_id != query_id or flags & 0x8000 == 0 or question_count != 1:
                raise ValueError("invalid_dns_response_header")
            _name, response_type, question_bytes = _question(response)
            if _name != host or response_type != qtype or response[12 : 12 + len(question_bytes)] != packet[12:]:
                raise ValueError("dns_question_mismatch")
            offset = 12 + len(question_bytes)
            for _ in range(answer_count):
                if offset + 12 > len(response) or response[offset : offset + 2] != b"\xc0\x0c":
                    raise ValueError("invalid_dns_answer")
                answer_type, answer_class, _ttl, length = struct.unpack("!HHIH", response[offset + 2 : offset + 12])
                offset += 12
                if answer_class != 1 or answer_type != qtype or offset + length > len(response):
                    raise ValueError("invalid_dns_answer_shape")
                payload = response[offset : offset + length]
                offset += length
                if length != (4 if qtype == 1 else 16):
                    raise ValueError("invalid_dns_address_length")
                addresses.append(ResolvedTarget(family, str(ipaddress.ip_address(payload)), port))
        return addresses
