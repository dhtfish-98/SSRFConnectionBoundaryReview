"""Run the bounded, real-socket loopback experiment and write a JSON receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import time
from pathlib import Path

from .core import FetchBlocked, Fetcher, PublicOnlyPolicy
from .dns_lab import ControlledDnsServer
from .lab import LabHttpServers, MisroutingConnector, make_lab_resolver


def _blocked(fetcher: Fetcher, url: str, expected_code: str) -> dict[str, object]:
    try:
        fetcher.fetch(url)
    except FetchBlocked as exc:
        assert exc.code == expected_code, (exc.code, expected_code)
        return {"outcome": exc.code, "trace": exc.trace}
    raise AssertionError(f"expected {expected_code}")


def _deadline_blocked(fetcher: Fetcher, url: str, *, marker: str | None = None) -> dict[str, object]:
    started = time.monotonic()
    row = _blocked(fetcher, url, "DEADLINE_EXCEEDED")
    elapsed = time.monotonic() - started
    assert elapsed < 0.75, elapsed
    assert any(event["event"] == "deadline_exceeded" for event in row["trace"])
    if marker is not None:
        assert any(event["event"] == marker for event in row["trace"])
    row["elapsed_seconds"] = round(elapsed, 6)
    row["total_timeout_seconds"] = fetcher.total_timeout
    return row


def run_experiments() -> dict[str, object]:
    with LabHttpServers() as lab, ControlledDnsServer(lab.dns_schedules()) as dns:
        resolver = make_lab_resolver(dns)
        policy = lab.policy()
        scenarios: dict[str, dict[str, object]] = {}

        initial = Fetcher(resolver, policy).fetch(f"http://safe.lab.test:{lab.safe_port}/ok")
        assert initial.status == 200 and initial.body == b"SAFE_LOOPBACK_MARKER"
        assert any(x["event"] == "connected_peer" and x["address"] == "127.0.0.1" for x in initial.trace)
        scenarios["initial_allowed_lab_endpoint"] = {"outcome": "PASS", "status": initial.status, "trace": list(initial.trace)}

        allowed_redirect = Fetcher(resolver, policy).fetch(f"http://safe.lab.test:{lab.safe_port}/redirect-safe")
        assert allowed_redirect.status == 200 and sum(x["event"] == "connected_peer" for x in allowed_redirect.trace) == 2
        scenarios["allowed_redirect_rechecked"] = {"outcome": "PASS", "status": allowed_redirect.status, "trace": list(allowed_redirect.trace)}

        before_internal = lab.request_count("internal")
        scenarios["redirect_to_fake_internal"] = _blocked(
            Fetcher(resolver, policy), f"http://safe.lab.test:{lab.safe_port}/redirect-internal", "ADDRESS_BLOCKED"
        )
        assert lab.request_count("internal") == before_internal
        scenarios["redirect_to_fake_internal"]["internal_http_requests_delta"] = 0

        before_internal = lab.request_count("internal")
        scenarios["dns_change_during_retry"] = _blocked(
            Fetcher(resolver, policy), f"http://flip.lab.test:{lab.safe_port}/retry", "ADDRESS_BLOCKED"
        )
        assert lab.request_count("internal") == before_internal
        assert any(x["event"] == "retry" for x in scenarios["dns_change_during_retry"]["trace"])
        scenarios["dns_change_during_retry"]["internal_http_requests_delta"] = 0

        before_safe = lab.request_count("safe")
        scenarios["mixed_a_aaaa_fail_closed"] = _blocked(
            Fetcher(resolver, policy), f"http://mixed.lab.test:{lab.safe_port}/ok", "ADDRESS_BLOCKED"
        )
        assert lab.request_count("safe") == before_safe
        scenarios["mixed_a_aaaa_fail_closed"]["safe_http_requests_delta"] = 0

        before_internal = lab.request_count("internal")
        scenarios["actual_peer_mismatch_before_request"] = _blocked(
            Fetcher(resolver, policy, connector=MisroutingConnector(lab.internal_port)),
            f"http://safe.lab.test:{lab.safe_port}/ok",
            "PEER_BLOCKED",
        )
        assert lab.request_count("internal") == before_internal
        scenarios["actual_peer_mismatch_before_request"]["internal_http_requests_delta"] = 0

        before_safe = lab.request_count("safe")
        scenarios["public_policy_blocks_loopback"] = _blocked(
            Fetcher(resolver, PublicOnlyPolicy()), f"http://safe.lab.test:{lab.safe_port}/ok", "ADDRESS_BLOCKED"
        )
        assert lab.request_count("safe") == before_safe
        scenarios["public_policy_blocks_loopback"]["safe_http_requests_delta"] = 0

        scenarios["slow_drip_whole_fetch_deadline"] = _deadline_blocked(
            Fetcher(resolver, policy, timeout=1.0, total_timeout=0.42),
            f"http://safe.lab.test:{lab.safe_port}/slow-drip",
        )
        scenarios["redirects_share_whole_fetch_deadline"] = _deadline_blocked(
            Fetcher(resolver, policy, timeout=1.0, total_timeout=0.38),
            f"http://safe.lab.test:{lab.safe_port}/slow-redirect",
            marker="redirect",
        )
        scenarios["retries_share_whole_fetch_deadline"] = _deadline_blocked(
            Fetcher(resolver, policy, timeout=1.0, total_timeout=0.38),
            f"http://safe.lab.test:{lab.safe_port}/slow-retry",
            marker="retry",
        )

        assert lab.request_count("internal") == 0
        assert all(row["outcome"] in ("PASS", "ADDRESS_BLOCKED", "PEER_BLOCKED", "DEADLINE_EXCEEDED") for row in scenarios.values())
        return {
            "schema": "ssrf-connection-boundary-lab-experiment-v1",
            "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "project_version": "0.1.0",
            "python_version": platform.python_version(),
            "network_scope": "Only 127.0.0.1 TCP/UDP and ::1 TCP; no public DNS or target network scanning",
            "policy_note": "LabOnlyPolicy explicitly permits one synthetic IPv4 loopback endpoint; PublicOnlyPolicy blocks loopback and is never used to dial public targets here",
            "safe_endpoint": {"bind": "127.0.0.1", "port": lab.safe_port},
            "fake_internal_endpoint": {"bind": "::1", "port": lab.internal_port},
            "controlled_dns_endpoint": {"bind": "127.0.0.1", "port": dns.port, "queries": dns.queries},
            "http_requests": list(lab.requests),
            "scenarios": scenarios,
            "pass_count": len(scenarios),
            "cvp_qualification": "OPEN",
            "upstream_vulnerability_claim": False,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run only the synthetic loopback SSRF boundary lab")
    parser.add_argument("--output", type=Path, required=True, help="Write receipt under the workspace Build directory")
    args = parser.parse_args()
    result = run_experiments()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "PASS_LOCAL_LOOPBACK", "scenarios": result["pass_count"], "receipt": str(args.output)}))


if __name__ == "__main__":
    main()
