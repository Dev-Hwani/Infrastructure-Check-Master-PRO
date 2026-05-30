from __future__ import annotations

import asyncio
import socket
import unittest
from unittest.mock import AsyncMock, patch

from app.models import PortTarget, ServerTarget
from app.services import port_checker


class _FakeDnsSocket:
    def __init__(self, rcode: int):
        self._rcode = rcode
        self._sent: bytes = b""
        self._timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self._timeout = value

    def sendto(self, data: bytes, _sockaddr: tuple[str, int]) -> None:
        self._sent = data

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        tx_id = self._sent[:2]
        # request includes EDNS OPT additional RR(11 bytes). keep question only.
        question = self._sent[12:-11]
        flags = 0x8000 | (self._rcode & 0x0F)  # qr=1 + rcode
        header = tx_id + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + (0).to_bytes(2, "big") * 3
        response = header + question
        return response, ("127.0.0.1", 53)

    def close(self) -> None:
        return None


class PortCheckerRetryPolicyTests(unittest.TestCase):
    def test_should_retry_denies_unknown_host_by_reason_code(self) -> None:
        result = port_checker._should_retry(
            status="UNKNOWN_HOST",
            reason_code="EAI_NONAME",
            attempt_no=1,
            max_attempts=3,
            retry_reason_allowlist={"WSAETIMEDOUT"},
            retry_reason_denylist={"EAI_NONAME"},
        )
        self.assertFalse(result)

    def test_should_retry_allows_timeout_reason(self) -> None:
        result = port_checker._should_retry(
            status="ERROR",
            reason_code="WSAETIMEDOUT",
            attempt_no=1,
            max_attempts=3,
            retry_reason_allowlist={"WSAETIMEDOUT"},
            retry_reason_denylist={"EAI_NONAME"},
        )
        self.assertTrue(result)


class DnsProbePolicyTests(unittest.TestCase):
    def _run_dns_probe_with_rcode(self, rcode: int) -> dict[str, object]:
        fake_socket = _FakeDnsSocket(rcode)
        with patch("app.services.port_checker.socket.getaddrinfo") as mock_getaddrinfo, patch(
            "app.services.port_checker.socket.socket",
            return_value=fake_socket,
        ), patch("app.services.port_checker.os.urandom", return_value=b"\x12\x34"):
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 53))
            ]
            return port_checker._dns_probe_sync(
                "dns.local",
                53,
                1.5,
                "dns_a",
            )

    def test_dns_servfail_is_probe_failed(self) -> None:
        result = self._run_dns_probe_with_rcode(2)
        self.assertEqual(result["probe_status"], "PROBE_FAILED")
        self.assertIn("SERVFAIL", str(result.get("probe_detail", "")))

    def test_dns_refused_is_probe_failed(self) -> None:
        result = self._run_dns_probe_with_rcode(5)
        self.assertEqual(result["probe_status"], "PROBE_FAILED")
        self.assertIn("REFUSED", str(result.get("probe_detail", "")))


class PortCheckerAsyncIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_circuit_breaker_skips_remaining_targets(self) -> None:
        server = ServerTarget(
            name="HOST-A",
            host="unknown-host.local",
            ports=[],
            port_targets=[
                PortTarget(port=53, transport="tcp", probe="none", retries=0),
                PortTarget(port=443, transport="tcp", probe="none", retries=0),
            ],
            services=[],
            enable_remote_metrics=False,
        )

        async def fake_single_check(**_kwargs):
            return {
                "checked_at": "2026-01-01T00:00:00Z",
                "server_id": server.id,
                "server_name": server.name,
                "host": server.host,
                "port": 53,
                "transport": "tcp",
                "probe_type": "none",
                "retry_count": 0,
                "attempt_count": 1,
                "status": "UNKNOWN_HOST",
                "reason_code": "EAI_NONAME",
                "detail": "mock unknown host",
                "recommended_action": "mock action",
                "consistency": "STABLE",
                "consistency_score": 100.0,
                "latency_ms": 0.1,
                "total_latency_ms": 0.1,
                "attempts": [{"attempt": 1, "status": "UNKNOWN_HOST", "reason_code": "EAI_NONAME"}],
                "probe_result": {
                    "probe_type": "none",
                    "probe_status": "SKIPPED",
                    "probe_detail": "No application probe configured.",
                    "probe_latency_ms": 0.0,
                },
            }

        with patch(
            "app.services.port_checker.check_single_port_target",
            new=AsyncMock(side_effect=fake_single_check),
        ) as mock_check:
            result = await port_checker.run_port_sweep(
                [server],
                timeout_seconds=2.0,
                default_retries=0,
            )

        self.assertEqual(mock_check.call_count, 1)
        self.assertEqual(len(result["results"]), 2)
        second = result["results"][1]
        self.assertEqual(second["reason_code"], "HOST_CIRCUIT_BREAKER")
        self.assertEqual(second["attempt_count"], 0)

    async def test_probe_params_are_forwarded_to_probe_runner(self) -> None:
        target = PortTarget(
            port=443,
            transport="tcp",
            probe="https",
            retries=0,
            probe_params={
                "http_host": "service.internal",
                "http_path": "/healthz",
                "tls_sni": "service.internal",
            },
        )

        async def fake_tcp_attempt(_host: str, _port: int, _timeout: float, attempt: int):
            return {
                "attempt": attempt,
                "status": "OPEN",
                "reason_code": "NONE",
                "detail": "mock open",
                "latency_ms": 1.0,
            }

        async def fake_probe(
            _host: str,
            _port: int,
            _probe_type: str,
            _timeout: float,
            passed_target: PortTarget,
        ):
            self.assertEqual(passed_target.probe_params.get("http_host"), "service.internal")
            self.assertEqual(passed_target.probe_params.get("http_path"), "/healthz")
            self.assertEqual(passed_target.probe_params.get("tls_sni"), "service.internal")
            return {
                "probe_status": "PROBE_OK",
                "probe_detail": "mock probe ok",
                "probe_latency_ms": 1.0,
                "probe_meta": {},
            }

        with patch("app.services.port_checker._tcp_attempt", new=AsyncMock(side_effect=fake_tcp_attempt)), patch(
            "app.services.port_checker._run_application_probe",
            new=AsyncMock(side_effect=fake_probe),
        ):
            result = await port_checker.check_single_port_target(
                server_id="s1",
                server_name="S1",
                host="127.0.0.1",
                target=target,
                timeout_seconds=2.0,
                default_retries=0,
            )

        self.assertEqual(result["probe_result"]["probe_status"], "PROBE_OK")

    async def test_udp_uncertain_promoted_to_open_by_probe_success(self) -> None:
        target = PortTarget(
            port=53,
            transport="udp",
            probe="dns_a",
            retries=0,
        )

        async def fake_udp_attempt(_host: str, _port: int, _timeout: float, attempt: int):
            return {
                "attempt": attempt,
                "status": "UDP_OPEN_OR_FILTERED",
                "reason_code": "NO_UDP_RESPONSE",
                "detail": "mock udp uncertain",
                "latency_ms": 1.0,
            }

        async def fake_probe(*_args, **_kwargs):
            return {
                "probe_status": "PROBE_OK",
                "probe_detail": "dns ok",
                "probe_latency_ms": 1.0,
                "probe_meta": {},
            }

        with patch("app.services.port_checker._udp_attempt", new=AsyncMock(side_effect=fake_udp_attempt)), patch(
            "app.services.port_checker._run_application_probe",
            new=AsyncMock(side_effect=fake_probe),
        ):
            result = await port_checker.check_single_port_target(
                server_id="s1",
                server_name="S1",
                host="127.0.0.1",
                target=target,
                timeout_seconds=2.0,
                default_retries=0,
                udp_enforce_probe_on_open_or_filtered=True,
            )

        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["reason_code"], "UDP_PROBE_CONFIRMED")

    async def test_udp_uncertain_without_probe_marks_policy_reason(self) -> None:
        target = PortTarget(
            port=9999,
            transport="udp",
            probe="none",
            retries=0,
        )

        async def fake_udp_attempt(_host: str, _port: int, _timeout: float, attempt: int):
            return {
                "attempt": attempt,
                "status": "UDP_OPEN_OR_FILTERED",
                "reason_code": "NO_UDP_RESPONSE",
                "detail": "mock udp uncertain",
                "latency_ms": 1.0,
            }

        with patch("app.services.port_checker._udp_attempt", new=AsyncMock(side_effect=fake_udp_attempt)):
            result = await port_checker.check_single_port_target(
                server_id="s1",
                server_name="S1",
                host="127.0.0.1",
                target=target,
                timeout_seconds=2.0,
                default_retries=0,
                udp_enforce_probe_on_open_or_filtered=True,
            )

        self.assertEqual(result["status"], "UDP_OPEN_OR_FILTERED")
        self.assertEqual(result["reason_code"], "UDP_PROBE_REQUIRED")


if __name__ == "__main__":
    unittest.main()
