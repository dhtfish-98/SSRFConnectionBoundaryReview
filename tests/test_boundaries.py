"""Black-box loopback tests for the network decisions and HTTP side effects."""

from __future__ import annotations

import socket
import time
import unittest

from ssrf_connection_boundary_review.core import DirectConnector, FetchBlocked, Fetcher, PublicOnlyPolicy
from ssrf_connection_boundary_review.dns_lab import ControlledDnsServer
from ssrf_connection_boundary_review.lab import LabHttpServers, MisroutingConnector, make_lab_resolver


class _NeverConnect:
    def connect(self, target: object, timeout: float) -> socket.socket:
        del target, timeout
        raise AssertionError("a blocked destination reached the connector")


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = LabHttpServers().__enter__()
        self.dns = ControlledDnsServer(self.lab.dns_schedules()).__enter__()
        self.resolver = make_lab_resolver(self.dns)
        self.policy = self.lab.policy()

    def tearDown(self) -> None:
        self.dns.__exit__(None, None, None)
        self.lab.__exit__(None, None, None)

    def _url(self, host: str, path: str, *, port: int | None = None) -> str:
        return f"http://{host}:{port or self.lab.safe_port}{path}"

    def test_initial_fetch_uses_validated_numeric_peer_and_preserves_host(self) -> None:
        result = Fetcher(self.resolver, self.policy).fetch(self._url("safe.lab.test", "/ok"))
        self.assertEqual((result.status, result.body), (200, b"SAFE_LOOPBACK_MARKER"))
        self.assertEqual(self.lab.request_count("safe"), 1)
        self.assertEqual(self.lab.requests[0]["host_header"], f"safe.lab.test:{self.lab.safe_port}")
        peers = [x for x in result.trace if x["event"] == "connected_peer"]
        self.assertEqual([(x["address"], x["port"]) for x in peers], [("127.0.0.1", self.lab.safe_port)])

    def test_allowed_redirect_resolves_and_connects_twice(self) -> None:
        result = Fetcher(self.resolver, self.policy).fetch(self._url("safe.lab.test", "/redirect-safe"))
        self.assertEqual(result.status, 200)
        self.assertEqual([x["path"] for x in self.lab.requests], ["/redirect-safe", "/ok"])
        self.assertEqual(sum(x["event"] == "connected_peer" for x in result.trace), 2)
        self.assertEqual(sum(x["host"] == "safe.lab.test" and x["type"] == "A" for x in self.dns.queries), 2)

    def test_redirect_to_fake_internal_is_rejected_before_request(self) -> None:
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy).fetch(self._url("safe.lab.test", "/redirect-internal"))
        self.assertEqual(caught.exception.code, "ADDRESS_BLOCKED")
        self.assertEqual(self.lab.request_count("internal"), 0)
        self.assertEqual(self.lab.request_count("safe"), 1)
        self.assertTrue(any(x["event"] == "address_rejected" and x["address"] == "::1" for x in caught.exception.trace))

    def test_retry_reresolves_and_rejects_changed_dns_answer(self) -> None:
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy).fetch(self._url("flip.lab.test", "/retry"))
        self.assertEqual(caught.exception.code, "ADDRESS_BLOCKED")
        self.assertEqual([x["path"] for x in self.lab.requests], ["/retry"])
        self.assertEqual(self.lab.request_count("internal"), 0)
        self.assertEqual([x["addresses"] for x in caught.exception.trace if x["event"] == "resolved"], [["127.0.0.1"], ["::1"]])
        self.assertEqual(sum(x["host"] == "flip.lab.test" and x["type"] == "A" for x in self.dns.queries), 2)

    def test_mixed_a_and_aaaa_fail_closed_before_any_connection(self) -> None:
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy, connector=_NeverConnect()).fetch(self._url("mixed.lab.test", "/ok"))
        self.assertEqual(caught.exception.code, "ADDRESS_BLOCKED")
        self.assertEqual(self.lab.requests, [])
        self.assertEqual(next(x["addresses"] for x in caught.exception.trace if x["event"] == "resolved"), ["127.0.0.1", "::1"])

    def test_actual_peer_mismatch_is_closed_before_http_request(self) -> None:
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy, connector=MisroutingConnector(self.lab.internal_port)).fetch(self._url("safe.lab.test", "/ok"))
        self.assertEqual(caught.exception.code, "PEER_BLOCKED")
        self.assertEqual(self.lab.requests, [])
        self.assertTrue(any(x["event"] == "connected_peer" and x["address"] == "::1" for x in caught.exception.trace))

    def test_public_policy_blocks_non_public_addresses_and_supports_forbidden_cidr(self) -> None:
        policy = PublicOnlyPolicy(("8.8.8.0/24",))
        for address in ("127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "8.8.8.8"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                policy.require("any.example", address, 80)
        PublicOnlyPolicy().require("any.example", "8.8.8.8", 80)
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, PublicOnlyPolicy(), connector=_NeverConnect()).fetch(self._url("safe.lab.test", "/ok"))
        self.assertEqual(caught.exception.code, "ADDRESS_BLOCKED")
        self.assertEqual(self.lab.requests, [])

    def test_invalid_url_forms_never_resolve_or_connect(self) -> None:
        before = len(self.dns.queries)
        bad = (
            "file:///etc/passwd",
            self._url("safe.lab.test", "/ok") + "#fragment",
            f"http://user:pass@safe.lab.test:{self.lab.safe_port}/ok",
            self._url("safe.lab.test", "/bad path"),
            self._url("safe.lab.test", "/ok") + "\\@evil",
            "http://safe.lab.test:0/ok",
        )
        for url in bad:
            with self.subTest(url=url), self.assertRaises(FetchBlocked) as caught:
                Fetcher(self.resolver, self.policy, connector=_NeverConnect()).fetch(url)
            self.assertEqual(caught.exception.code, "INVALID_URL")
        self.assertEqual(len(self.dns.queries), before)
        self.assertEqual(self.lab.requests, [])

    def test_body_and_redirect_limits_are_enforced(self) -> None:
        with self.assertRaises(FetchBlocked) as body:
            Fetcher(self.resolver, self.policy, body_limit=32).fetch(self._url("safe.lab.test", "/large"))
        self.assertEqual(body.exception.code, "BODY_LIMIT")
        with self.assertRaises(FetchBlocked) as redirect:
            Fetcher(self.resolver, self.policy, max_redirects=0).fetch(self._url("safe.lab.test", "/redirect-safe"))
        self.assertEqual(redirect.exception.code, "REDIRECT_LIMIT")

    def test_lab_policy_cannot_be_configured_for_public_network(self) -> None:
        from ssrf_connection_boundary_review.core import LabOnlyPolicy

        with self.assertRaises(ValueError):
            LabOnlyPolicy({("unsafe.lab.test", "8.8.8.8", 80)})

    def _assert_whole_fetch_deadline(self, path: str, *, total_timeout: float) -> None:
        started = time.monotonic()
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy, timeout=1.0, total_timeout=total_timeout).fetch(
                self._url("safe.lab.test", path)
            )
        elapsed = time.monotonic() - started
        self.assertEqual(caught.exception.code, "DEADLINE_EXCEEDED")
        self.assertTrue(any(row["event"] == "deadline_exceeded" for row in caught.exception.trace))
        self.assertLess(elapsed, 0.75, (path, elapsed))
        self.assertEqual(self.lab.request_count("internal"), 0)

    def test_slow_drip_cannot_extend_whole_fetch_deadline(self) -> None:
        self._assert_whole_fetch_deadline("/slow-drip", total_timeout=0.42)

    def test_redirects_share_whole_fetch_deadline(self) -> None:
        self._assert_whole_fetch_deadline("/slow-redirect", total_timeout=0.38)
        self.assertEqual([row["path"] for row in self.lab.requests], ["/slow-redirect", "/delayed-ok"])

    def test_retries_share_whole_fetch_deadline(self) -> None:
        self._assert_whole_fetch_deadline("/slow-retry", total_timeout=0.38)
        self.assertEqual([row["path"] for row in self.lab.requests], ["/slow-retry", "/slow-retry"])

    def test_connected_socket_is_closed_if_connector_returns_after_deadline(self) -> None:
        class DelayedConnector:
            connection: socket.socket | None = None

            def connect(self, target: object, timeout: float) -> socket.socket:
                self.connection = DirectConnector().connect(target, timeout)
                time.sleep(0.12)
                return self.connection

        connector = DelayedConnector()
        with self.assertRaises(FetchBlocked) as caught:
            Fetcher(self.resolver, self.policy, connector=connector, total_timeout=0.06).fetch(
                self._url("safe.lab.test", "/ok")
            )
        self.assertEqual(caught.exception.code, "DEADLINE_EXCEEDED")
        self.assertIsNotNone(connector.connection)
        self.assertEqual(connector.connection.fileno(), -1)
        self.assertEqual(self.lab.request_count("safe"), 0)


if __name__ == "__main__":
    unittest.main()
