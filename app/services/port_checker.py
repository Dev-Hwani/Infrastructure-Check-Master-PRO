from __future__ import annotations

import asyncio
import errno
import socket
import ssl
from contextlib import suppress
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from ..models import PortStatus, PortTarget, ProbeType, ServerTarget

WINSOCK_ERRNO_NAMES = {
    10013: "WSAEACCES",
    10051: "WSAENETUNREACH",
    10052: "WSAENETRESET",
    10053: "WSAECONNABORTED",
    10054: "WSAECONNRESET",
    10060: "WSAETIMEDOUT",
    10061: "WSAECONNREFUSED",
    10064: "WSAEHOSTDOWN",
    10065: "WSAEHOSTUNREACH",
}

AUTO_PROBE_PORTS: dict[int, ProbeType] = {
    80: "http",
    443: "https",
    3389: "rdp",
}

RETRYABLE_STATUSES: set[str] = {"TIMEOUT", "FILTERED", "ERROR", "PROBE_TIMEOUT"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_errno_value(name: str) -> int:
    return getattr(errno, name, -1)


ERR_REFUSED = {10061, _safe_errno_value("ECONNREFUSED")}
ERR_TIMEOUT = {10060, _safe_errno_value("ETIMEDOUT")}
ERR_NET_UNREACHABLE = {10051, _safe_errno_value("ENETUNREACH"), _safe_errno_value("ENETDOWN")}
ERR_HOST_UNREACHABLE = {10064, _safe_errno_value("EHOSTDOWN"), _safe_errno_value("EHOSTUNREACH")}
ERR_PERMISSION = {10013, _safe_errno_value("EACCES"), _safe_errno_value("EPERM")}
ERR_CONN_RESET = {10054, _safe_errno_value("ECONNRESET")}


def _resolve_probe_type(probe: ProbeType, port: int) -> ProbeType:
    if probe != "auto":
        return probe
    return AUTO_PROBE_PORTS.get(port, "none")


def _errno_reason_name(number: int | None) -> str:
    if number is None:
        return "UNKNOWN"
    if number in WINSOCK_ERRNO_NAMES:
        return WINSOCK_ERRNO_NAMES[number]
    if number in errno.errorcode:
        return errno.errorcode[number]
    return f"ERRNO_{number}"


def _normalized_error_number(exc: OSError) -> int | None:
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    err_no = getattr(exc, "errno", None)
    if isinstance(err_no, int):
        return err_no
    return None


def _map_os_error(exc: OSError, transport: str) -> tuple[PortStatus, str, str]:
    number = _normalized_error_number(exc)
    reason = _errno_reason_name(number)
    text = str(exc) or repr(exc)
    lower_text = text.lower()

    if number in ERR_REFUSED:
        return ("REFUSED", reason, "Target is reachable but the service port is closed.")
    if number in ERR_TIMEOUT:
        return ("TIMEOUT", reason, "No response within timeout window.")
    if number in ERR_NET_UNREACHABLE:
        return ("NETWORK_UNREACHABLE", reason, "Network is unreachable from the current host.")
    if number in ERR_HOST_UNREACHABLE:
        if "no route" in lower_text or number == 10065:
            return ("NO_ROUTE", reason, "No route to target host from the current host.")
        return ("HOST_UNREACHABLE", reason, "Target host is unreachable.")
    if number in ERR_PERMISSION:
        return ("FILTERED", reason, "Connection blocked by firewall/security policy.")
    if number in ERR_CONN_RESET and transport == "udp":
        return ("UDP_CLOSED", reason, "ICMP port unreachable received (UDP port likely closed).")

    if "no route" in lower_text:
        return ("NO_ROUTE", reason, text)
    return ("ERROR", reason, text)


def _attempt_payload(
    *,
    attempt: int,
    status: PortStatus,
    reason_code: str,
    detail: str,
    latency_ms: float,
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "status": status,
        "reason_code": reason_code,
        "detail": detail,
        "latency_ms": round(latency_ms, 2),
    }


async def _tcp_attempt(host: str, port: int, timeout_seconds: float, attempt: int) -> dict[str, Any]:
    started = perf_counter()
    try:
        open_connection = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(open_connection, timeout=timeout_seconds)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        return _attempt_payload(
            attempt=attempt,
            status="OPEN",
            reason_code="NONE",
            detail="TCP handshake succeeded.",
            latency_ms=(perf_counter() - started) * 1000,
        )
    except ConnectionRefusedError as exc:
        status, reason_code, detail = _map_os_error(exc, "tcp")
        return _attempt_payload(
            attempt=attempt,
            status=status,
            reason_code=reason_code,
            detail=detail,
            latency_ms=(perf_counter() - started) * 1000,
        )
    except asyncio.TimeoutError:
        return _attempt_payload(
            attempt=attempt,
            status="TIMEOUT",
            reason_code="WSAETIMEDOUT",
            detail=f"No response within {timeout_seconds:.1f}s.",
            latency_ms=(perf_counter() - started) * 1000,
        )
    except socket.gaierror as exc:
        return _attempt_payload(
            attempt=attempt,
            status="UNKNOWN_HOST",
            reason_code="EAI_NONAME",
            detail=f"Hostname or IP could not be resolved: {exc}",
            latency_ms=(perf_counter() - started) * 1000,
        )
    except OSError as exc:
        status, reason_code, detail = _map_os_error(exc, "tcp")
        return _attempt_payload(
            attempt=attempt,
            status=status,
            reason_code=reason_code,
            detail=detail,
            latency_ms=(perf_counter() - started) * 1000,
        )


def _udp_attempt_sync(host: str, port: int, timeout_seconds: float, attempt: int) -> dict[str, Any]:
    started = perf_counter()
    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        return _attempt_payload(
            attempt=attempt,
            status="UNKNOWN_HOST",
            reason_code="EAI_NONAME",
            detail=f"Hostname or IP could not be resolved: {exc}",
            latency_ms=(perf_counter() - started) * 1000,
        )

    last_error: OSError | None = None
    for family, socktype, proto, _, sockaddr in addr_infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout_seconds)
        try:
            sock.connect(sockaddr)
            sock.send(b"ICMPROBE")
            try:
                data = sock.recv(64)
                if data:
                    return _attempt_payload(
                        attempt=attempt,
                        status="OPEN",
                        reason_code="UDP_RESPONSE",
                        detail="UDP payload received from target port.",
                        latency_ms=(perf_counter() - started) * 1000,
                    )
            except socket.timeout:
                return _attempt_payload(
                    attempt=attempt,
                    status="UDP_OPEN_OR_FILTERED",
                    reason_code="NO_UDP_RESPONSE",
                    detail="No UDP response; UDP is either open (silent) or filtered.",
                    latency_ms=(perf_counter() - started) * 1000,
                )
            except OSError as exc:
                status, reason_code, detail = _map_os_error(exc, "udp")
                return _attempt_payload(
                    attempt=attempt,
                    status=status,
                    reason_code=reason_code,
                    detail=detail,
                    latency_ms=(perf_counter() - started) * 1000,
                )
        except OSError as exc:
            last_error = exc
        finally:
            sock.close()

    if last_error is not None:
        status, reason_code, detail = _map_os_error(last_error, "udp")
        return _attempt_payload(
            attempt=attempt,
            status=status,
            reason_code=reason_code,
            detail=detail,
            latency_ms=(perf_counter() - started) * 1000,
        )

    return _attempt_payload(
        attempt=attempt,
        status="ERROR",
        reason_code="UDP_UNKNOWN",
        detail="UDP probe failed for unknown reason.",
        latency_ms=(perf_counter() - started) * 1000,
    )


async def _udp_attempt(host: str, port: int, timeout_seconds: float, attempt: int) -> dict[str, Any]:
    return await asyncio.to_thread(_udp_attempt_sync, host, port, timeout_seconds, attempt)


async def _http_probe(host: str, port: int, timeout_seconds: float, use_tls: bool) -> dict[str, Any]:
    started = perf_counter()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=timeout_seconds,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout_seconds,
            )

        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
        first_line = await asyncio.wait_for(reader.readline(), timeout=timeout_seconds)
        if not first_line:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": "No HTTP response line received.",
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }

        text = first_line.decode("latin-1", errors="ignore").strip()
        tokens = text.split(" ")
        if len(tokens) < 2 or not tokens[0].startswith("HTTP/"):
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": f"Unexpected HTTP response line: {text}",
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }

        status_code = tokens[1]
        return {
            "probe_status": "PROBE_OK",
            "probe_detail": f"HTTP response received: {status_code}",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except asyncio.TimeoutError:
        return {
            "probe_status": "PROBE_TIMEOUT",
            "probe_detail": f"No application response within {timeout_seconds:.1f}s.",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except ssl.SSLError as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": f"TLS handshake failed: {exc}",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": str(exc),
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


async def _rdp_probe(host: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    started = perf_counter()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_seconds)
        # X.224 Connection Request + RDP Negotiation Request
        packet = bytes.fromhex("030000130ee000000000000100080003000000")
        writer.write(packet)
        await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
        response = await asyncio.wait_for(reader.read(64), timeout=timeout_seconds)

        if len(response) >= 7 and response[0] == 0x03 and response[5] in {0xD0, 0xF0}:
            return {
                "probe_status": "PROBE_OK",
                "probe_detail": "RDP negotiation response received.",
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        if response:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": f"Unexpected RDP response bytes: {response.hex()}",
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        return {
            "probe_status": "INVALID_RESPONSE",
            "probe_detail": "No RDP negotiation response received.",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except asyncio.TimeoutError:
        return {
            "probe_status": "PROBE_TIMEOUT",
            "probe_detail": f"No application response within {timeout_seconds:.1f}s.",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": str(exc),
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()


async def _run_application_probe(host: str, port: int, probe_type: ProbeType, timeout_seconds: float) -> dict[str, Any]:
    if probe_type == "http":
        return await _http_probe(host, port, timeout_seconds, use_tls=False)
    if probe_type == "https":
        return await _http_probe(host, port, timeout_seconds, use_tls=True)
    if probe_type == "rdp":
        return await _rdp_probe(host, port, timeout_seconds)
    return {
        "probe_status": "SKIPPED",
        "probe_detail": "No application probe configured.",
        "probe_latency_ms": 0.0,
    }


def _choose_final_status(attempts: list[dict[str, Any]], transport: str) -> PortStatus:
    statuses = [str(item["status"]) for item in attempts]
    if "OPEN" in statuses:
        return "OPEN"
    if transport == "udp" and "UDP_OPEN_OR_FILTERED" in statuses:
        return "UDP_OPEN_OR_FILTERED"
    if transport == "udp" and "UDP_CLOSED" in statuses:
        return "UDP_CLOSED"
    if "REFUSED" in statuses:
        return "REFUSED"
    if "NO_ROUTE" in statuses:
        return "NO_ROUTE"
    if "HOST_UNREACHABLE" in statuses:
        return "HOST_UNREACHABLE"
    if "NETWORK_UNREACHABLE" in statuses:
        return "NETWORK_UNREACHABLE"
    if "UNKNOWN_HOST" in statuses:
        return "UNKNOWN_HOST"
    if statuses and all(status in {"TIMEOUT", "FILTERED"} for status in statuses):
        return "FILTERED"
    if "TIMEOUT" in statuses:
        return "TIMEOUT"
    if "FILTERED" in statuses:
        return "FILTERED"
    return "ERROR"


def _should_retry(status: PortStatus) -> bool:
    return status in RETRYABLE_STATUSES


def _expand_server_port_targets(server: ServerTarget) -> list[PortTarget]:
    combined = [PortTarget(port=port, transport="tcp", probe="auto") for port in server.ports]
    combined.extend(server.port_targets)
    deduped: dict[tuple[int, str, str, int | None], PortTarget] = {}
    for target in combined:
        key = (target.port, target.transport, target.probe, target.retries)
        if key not in deduped:
            deduped[key] = target
    return list(deduped.values())


async def check_single_port_target(
    *,
    server_id: str,
    server_name: str,
    host: str,
    target: PortTarget,
    timeout_seconds: float = 2.0,
    default_retries: int = 2,
) -> dict[str, Any]:
    check_started = perf_counter()
    retries = target.retries if target.retries is not None else default_retries
    max_attempts = retries + 1
    attempts: list[dict[str, Any]] = []

    for attempt_no in range(1, max_attempts + 1):
        if target.transport == "udp":
            attempt = await _udp_attempt(host, target.port, timeout_seconds, attempt_no)
        else:
            attempt = await _tcp_attempt(host, target.port, timeout_seconds, attempt_no)
        attempts.append(attempt)

        if attempt["status"] == "OPEN":
            break
        if not _should_retry(attempt["status"]):
            break

    final_status = _choose_final_status(attempts, target.transport)
    final_attempt = attempts[-1]
    probe_type = _resolve_probe_type(target.probe, target.port)
    probe_result = {
        "probe_type": probe_type,
        "probe_status": "SKIPPED",
        "probe_detail": "No application probe configured.",
        "probe_latency_ms": 0.0,
    }

    if final_status == "OPEN" and target.transport == "tcp" and probe_type != "none":
        probe_result = {
            "probe_type": probe_type,
            **(await _run_application_probe(host, target.port, probe_type, timeout_seconds)),
        }

    detail = final_attempt["detail"]
    if final_status == "FILTERED":
        detail = f"{detail} Final decision: likely filtered/dropped after {len(attempts)} attempts."

    total_elapsed = round((perf_counter() - check_started) * 1000, 2)
    return {
        "checked_at": _utc_now_iso(),
        "server_id": server_id,
        "server_name": server_name,
        "host": host,
        "port": target.port,
        "transport": target.transport,
        "probe_type": probe_type,
        "retry_count": retries,
        "attempt_count": len(attempts),
        "status": final_status,
        "reason_code": final_attempt["reason_code"],
        "detail": detail,
        "latency_ms": round(final_attempt["latency_ms"], 2),
        "total_latency_ms": total_elapsed,
        "attempts": attempts,
        "probe_result": probe_result,
    }


async def run_port_sweep(
    servers: list[ServerTarget],
    timeout_seconds: float = 2.0,
    default_retries: int = 2,
) -> dict[str, Any]:
    started = perf_counter()
    tasks: list[asyncio.Task[dict[str, Any]]] = []

    for server in servers:
        for target in _expand_server_port_targets(server):
            tasks.append(
                asyncio.create_task(
                    check_single_port_target(
                        server_id=server.id,
                        server_name=server.name,
                        host=server.host,
                        target=target,
                        timeout_seconds=timeout_seconds,
                        default_retries=default_retries,
                    )
                )
            )

    results = await asyncio.gather(*tasks) if tasks else []
    status_counts: dict[str, int] = {}
    transport_counts: dict[str, int] = {}
    probe_counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        transport = str(result["transport"])
        probe_status = str(result["probe_result"]["probe_status"])
        status_counts[status] = status_counts.get(status, 0) + 1
        transport_counts[transport] = transport_counts.get(transport, 0) + 1
        probe_counts[probe_status] = probe_counts.get(probe_status, 0) + 1

    total_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "results": results,
        "summary": {
            "total_checks": len(results),
            "duration_ms": total_ms,
            "status_counts": status_counts,
            "transport_counts": transport_counts,
            "probe_status_counts": probe_counts,
        },
    }

