"""HTTP connection controls used by the synthetic loopback laboratory.

The fetcher deliberately has no implicit system resolver, proxy, redirect,
retry, or DNS cache. A caller must supply a resolver and address policy. Every
hop and retry resolves afresh, checks all returned addresses, connects by a
validated numeric address, then checks the actual socket peer before sending
an HTTP request. This is a bounded experiment, not a production HTTP client.
"""

from __future__ import annotations

import http.client
import io
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urljoin, urlsplit


@dataclass(frozen=True)
class ResolvedTarget:
    family: int
    address: str
    port: int


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> list[ResolvedTarget]: ...


class Connector(Protocol):
    def connect(self, target: ResolvedTarget, timeout: float) -> socket.socket: ...


class AddressPolicy(Protocol):
    def require(self, host: str, address: str, port: int) -> None: ...


class FetchBlocked(Exception):
    def __init__(self, code: str, trace: list[dict[str, object]]):
        super().__init__(code)
        self.code = code
        self.trace = [dict(event) for event in trace]


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    final_host: str
    trace: tuple[dict[str, object], ...]


def _address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


class PublicOnlyPolicy:
    """Production-style classification policy; never used to dial public IPs here."""

    def __init__(self, forbidden_cidrs: tuple[str, ...] = ()) -> None:
        self._forbidden = tuple(ipaddress.ip_network(x, strict=False) for x in forbidden_cidrs)

    def require(self, host: str, address: str, port: int) -> None:
        del host, port
        try:
            ip = _address(address)
        except ValueError as exc:
            raise ValueError("invalid_ip_address") from exc
        if not ip.is_global or any(ip in network for network in self._forbidden):
            raise ValueError("non_public_or_forbidden_address")


class LabOnlyPolicy:
    """Explicit synthetic exceptions; this is not a public-address policy."""

    def __init__(self, allowed: set[tuple[str, str, int]]) -> None:
        normalized: set[tuple[str, str, int]] = set()
        for host, address, port in allowed:
            ip = _address(address)
            if not ip.is_loopback:
                raise ValueError("lab_policy_accepts_loopback_only")
            normalized.add((host.lower(), str(ip), port))
        self._allowed = frozenset(normalized)

    def require(self, host: str, address: str, port: int) -> None:
        try:
            ip = _address(address)
        except ValueError as exc:
            raise ValueError("invalid_ip_address") from exc
        if not ip.is_loopback or (host.lower(), str(ip), port) not in self._allowed:
            raise ValueError("not_an_explicit_lab_endpoint")


class DirectConnector:
    """Dial a numeric address without resolving the hostname a second time."""

    def connect(self, target: ResolvedTarget, timeout: float) -> socket.socket:
        connection = socket.socket(target.family, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect((target.address, target.port))
            return connection
        except BaseException:
            connection.close()
            raise


_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_REDIRECTS = frozenset((301, 302, 303, 307, 308))


class _DeadlineExpired(TimeoutError):
    pass


class _DeadlineReader(io.RawIOBase):
    """Reapply the remaining whole-fetch budget before every socket read."""

    def __init__(self, connection: socket.socket, deadline: float, operation_timeout: float) -> None:
        super().__init__()
        self.connection = connection
        self.deadline = deadline
        self.operation_timeout = operation_timeout

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExpired("whole_fetch_deadline")
        self.connection.settimeout(min(self.operation_timeout, remaining))
        try:
            count = self.connection.recv_into(buffer)
        except socket.timeout as exc:
            if time.monotonic() >= self.deadline:
                raise _DeadlineExpired("whole_fetch_deadline") from exc
            raise
        if time.monotonic() >= self.deadline:
            raise _DeadlineExpired("whole_fetch_deadline")
        return count


class _DeadlineSocketView:
    """Give http.client a deadline-aware makefile without wrapping the dialer."""

    def __init__(self, connection: socket.socket, deadline: float, operation_timeout: float) -> None:
        self.connection = connection
        self.deadline = deadline
        self.operation_timeout = operation_timeout

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("read_only_http_response")
        return io.BufferedReader(_DeadlineReader(self.connection, self.deadline, self.operation_timeout))


def _parse_url(url: str) -> tuple[SplitResult, str, int, str]:
    if not isinstance(url, str) or not url or url != url.strip():
        raise ValueError("invalid_url")
    if any(ord(c) < 33 or ord(c) > 126 or c == "\\" for c in url):
        raise ValueError("invalid_url_characters")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "http" or parsed.username is not None or parsed.password is not None:
        raise ValueError("unsupported_scheme_or_userinfo")
    if parsed.fragment or not parsed.netloc or parsed.hostname is None:
        raise ValueError("invalid_url_authority_or_fragment")
    host = parsed.hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_PATTERN.fullmatch(host) or ".." in host or host.endswith("."):
            raise ValueError("invalid_dns_hostname")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_port") from exc
    port = 80 if parsed_port is None else parsed_port
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise ValueError("invalid_path")
    if parsed.query:
        path += "?" + parsed.query
    return parsed, host, port, path


class Fetcher:
    def __init__(
        self,
        resolver: Resolver,
        policy: AddressPolicy,
        connector: Connector | None = None,
        *,
        max_redirects: int = 3,
        max_attempts: int = 2,
        timeout: float = 1.0,
        total_timeout: float = 3.0,
        body_limit: int = 65536,
    ) -> None:
        if max_redirects < 0 or max_attempts < 1 or timeout <= 0 or total_timeout <= 0 or body_limit < 1:
            raise ValueError("invalid_fetch_limits")
        self.resolver = resolver
        self.policy = policy
        self.connector = connector or DirectConnector()
        self.max_redirects = max_redirects
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.total_timeout = total_timeout
        self.body_limit = body_limit

    def _remaining(self, deadline: float, trace: list[dict[str, object]], phase: str) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            trace.append({"event": "deadline_exceeded", "phase": phase})
            raise FetchBlocked("DEADLINE_EXCEEDED", trace)
        return min(self.timeout, remaining)

    def fetch(self, url: str) -> FetchResult:
        trace: list[dict[str, object]] = []
        deadline = time.monotonic() + self.total_timeout
        current = url
        for hop in range(self.max_redirects + 1):
            self._remaining(deadline, trace, "hop")
            try:
                parsed, host, port, path = _parse_url(current)
            except ValueError as exc:
                trace.append({"event": "url_rejected", "reason": str(exc), "hop": hop})
                raise FetchBlocked("INVALID_URL", trace) from exc

            for attempt in range(self.max_attempts):
                self._remaining(deadline, trace, "resolution")
                try:
                    if hasattr(self.resolver, "resolve_with_deadline"):
                        answers = self.resolver.resolve_with_deadline(host, port, deadline)  # type: ignore[attr-defined]
                    else:
                        answers = self.resolver.resolve(host, port)
                except (OSError, ValueError) as exc:
                    self._remaining(deadline, trace, "resolution")
                    trace.append({"event": "dns_error", "host": host, "hop": hop, "attempt": attempt + 1})
                    raise FetchBlocked("DNS_ERROR", trace) from exc
                self._remaining(deadline, trace, "resolution")
                trace.append({"event": "resolved", "host": host, "addresses": [x.address for x in answers], "hop": hop, "attempt": attempt + 1})
                if not answers:
                    raise FetchBlocked("EMPTY_DNS_ANSWER", trace)
                for answer in answers:
                    try:
                        ip = ipaddress.ip_address(answer.address)
                        expected_family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
                        if answer.family != expected_family or answer.port != port:
                            raise ValueError("resolver_answer_shape")
                        self.policy.require(host, answer.address, port)
                    except ValueError as exc:
                        trace.append({"event": "address_rejected", "host": host, "address": answer.address, "reason": str(exc), "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("ADDRESS_BLOCKED", trace) from exc

                connected: socket.socket | None = None
                for answer in answers:
                    try:
                        connected = self.connector.connect(answer, self._remaining(deadline, trace, "connect"))
                        try:
                            self._remaining(deadline, trace, "connect")
                        except FetchBlocked:
                            connected.close()
                            raise
                    except OSError:
                        self._remaining(deadline, trace, "connect")
                        trace.append({"event": "connect_error", "host": host, "address": answer.address, "hop": hop, "attempt": attempt + 1})
                        continue
                    break
                if connected is None:
                    if attempt + 1 < self.max_attempts:
                        trace.append({"event": "retry", "reason": "connect_error", "hop": hop, "attempt": attempt + 1})
                        continue
                    raise FetchBlocked("CONNECT_FAILED", trace)

                with connected:
                    self._remaining(deadline, trace, "peer")
                    try:
                        actual_ip, actual_port = connected.getpeername()[:2]
                    except OSError as exc:
                        trace.append({"event": "peer_unknown", "host": host, "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("PEER_UNKNOWN", trace) from exc
                    trace.append({"event": "connected_peer", "host": host, "address": actual_ip, "port": actual_port, "hop": hop, "attempt": attempt + 1})
                    try:
                        self.policy.require(host, actual_ip, actual_port)
                        if _address(actual_ip) != _address(answer.address) or actual_port != answer.port:
                            raise ValueError("peer_differs_from_validated_dns_answer")
                    except ValueError as exc:
                        trace.append({"event": "peer_rejected", "host": host, "address": actual_ip, "port": actual_port, "reason": str(exc), "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("PEER_BLOCKED", trace) from exc

                    authority = host if port == 80 else f"{host}:{port}"
                    if ":" in host:
                        authority = f"[{host}]" if port == 80 else f"[{host}]:{port}"
                    request = f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
                    try:
                        connected.settimeout(self._remaining(deadline, trace, "send"))
                        connected.sendall(request.encode("ascii"))
                    except OSError as exc:
                        self._remaining(deadline, trace, "send")
                        trace.append({"event": "http_send_error", "host": host, "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("HTTP_ERROR", trace) from exc
                    self._remaining(deadline, trace, "send")
                    response = http.client.HTTPResponse(_DeadlineSocketView(connected, deadline, self.timeout))
                    try:
                        response.begin()
                        body = response.read(self.body_limit + 1)
                        self._remaining(deadline, trace, "response")
                        if len(body) > self.body_limit:
                            trace.append({"event": "body_limit", "host": host, "hop": hop, "attempt": attempt + 1})
                            raise FetchBlocked("BODY_LIMIT", trace)
                        status = response.status
                        location = response.getheader("Location")
                    except _DeadlineExpired as exc:
                        trace.append({"event": "deadline_exceeded", "phase": "response", "host": host, "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("DEADLINE_EXCEEDED", trace) from exc
                    except (http.client.HTTPException, OSError) as exc:
                        self._remaining(deadline, trace, "response")
                        trace.append({"event": "http_error", "host": host, "hop": hop, "attempt": attempt + 1})
                        raise FetchBlocked("HTTP_ERROR", trace) from exc
                    finally:
                        response.close()

                trace.append({"event": "response", "host": host, "status": status, "hop": hop, "attempt": attempt + 1})
                if status in _REDIRECTS:
                    if not location:
                        raise FetchBlocked("REDIRECT_WITHOUT_LOCATION", trace)
                    if hop >= self.max_redirects:
                        raise FetchBlocked("REDIRECT_LIMIT", trace)
                    trace.append({"event": "redirect", "from_host": host, "hop": hop})
                    current = urljoin(parsed.geturl(), location)
                    break
                if status in (502, 503, 504) and attempt + 1 < self.max_attempts:
                    trace.append({"event": "retry", "reason": "transient_status", "hop": hop, "attempt": attempt + 1})
                    continue
                return FetchResult(status=status, body=body, final_host=host, trace=tuple(trace))
            else:
                raise FetchBlocked("ATTEMPTS_EXHAUSTED", trace)
        raise FetchBlocked("REDIRECT_LIMIT", trace)
