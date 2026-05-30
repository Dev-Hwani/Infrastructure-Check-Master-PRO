from __future__ import annotations

import asyncio
import errno
import inspect
import json
import os
import socket
import ssl
import struct
from collections import Counter
from contextlib import suppress
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Awaitable, Callable

from ..models import PortStatus, PortTarget, ProbeType, ServerTarget

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]

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

AUTO_TCP_PROBE_PORTS: dict[int, ProbeType] = {
    80: "http",
    443: "https",
    3389: "rdp",
}
AUTO_UDP_PROBE_PORTS: dict[int, ProbeType] = {
    53: "dns_a",
    123: "ntp",
}

RETRYABLE_STATUSES: set[str] = {
    "TIMEOUT",
    "FILTERED",
    "ERROR",
    "PROBE_TIMEOUT",
    "NETWORK_UNREACHABLE",
    "HOST_UNREACHABLE",
    "NO_ROUTE",
    "UDP_OPEN_OR_FILTERED",
}
NON_RETRYABLE_STATUSES: set[str] = {"OPEN", "REFUSED", "UNKNOWN_HOST", "UDP_CLOSED"}

DEFAULT_RETRY_REASON_ALLOWLIST: set[str] = {
    "WSAETIMEDOUT",
    "ETIMEDOUT",
    "NO_UDP_RESPONSE",
    "WSAENETUNREACH",
    "ENETUNREACH",
    "WSAEHOSTUNREACH",
    "EHOSTUNREACH",
    "WSAENETRESET",
    "WSAECONNRESET",
    "ECONNRESET",
    "WSAECONNABORTED",
    "ECONNABORTED",
}

DEFAULT_RETRY_REASON_DENYLIST: set[str] = {
    "EAI_NONAME",
    "WSAECONNREFUSED",
    "ECONNREFUSED",
    "WSAEACCES",
    "EACCES",
    "EPERM",
    "HOST_CIRCUIT_BREAKER",
}

ADAPTIVE_REASON_MULTIPLIERS: dict[str, float] = {
    "WSAETIMEDOUT": 1.2,
    "ETIMEDOUT": 1.2,
    "NO_UDP_RESPONSE": 1.0,
    "WSAENETUNREACH": 1.7,
    "ENETUNREACH": 1.7,
    "WSAEHOSTUNREACH": 1.5,
    "EHOSTUNREACH": 1.5,
    "WSAEACCES": 1.4,
}

REASON_CODE_ACTION_GUIDE = {
    "WSAETIMEDOUT": "No response before timeout. Check firewall/ACL and service latency.",
    "ETIMEDOUT": "No response before timeout. Validate routing and service responsiveness.",
    "WSAENETUNREACH": "Network unreachable. Check gateway, route table, VLAN and vSwitch path.",
    "ENETUNREACH": "Network unreachable. Validate subnet path and upstream routing.",
    "WSAEHOSTUNREACH": "Host unreachable. Check server power state/NIC and path policy.",
    "EHOSTUNREACH": "Host unreachable. Validate destination host and path.",
    "WSAECONNREFUSED": "Target reachable but port is not listening.",
    "ECONNREFUSED": "Target reachable but service is not listening on this port.",
    "WSAEACCES": "Blocked by local/remote policy. Check firewall, EDR and ACL controls.",
    "EAI_NONAME": "DNS resolve failed. Verify hostname and DNS resolver settings.",
    "NO_UDP_RESPONSE": "UDP may be open-silent or filtered. Validate with DNS/NTP probe details.",
    "HOST_CIRCUIT_BREAKER": "Host-level circuit breaker triggered. Verify host reachability/DNS routing first.",
    "UDP_PROBE_REQUIRED": "Policy requires protocol probe for UDP uncertainty. Configure DNS/NTP probe.",
    "UDP_PROBE_CONFIRMED": "UDP uncertainty resolved by successful protocol probe.",
}

STATUS_PRIORITY_DEFAULT: dict[str, int] = {
    "OPEN": 1000,
    "REFUSED": 920,
    "NO_ROUTE": 900,
    "HOST_UNREACHABLE": 860,
    "NETWORK_UNREACHABLE": 850,
    "UNKNOWN_HOST": 840,
    "UDP_CLOSED": 820,
    "FILTERED": 780,
    "TIMEOUT": 760,
    "UDP_OPEN_OR_FILTERED": 730,
    "ERROR": 100,
}


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


def _resolve_probe_type(probe: ProbeType, port: int, transport: str) -> ProbeType:
    if probe == "dns":
        return "dns_a"
    if probe != "auto":
        return probe
    if transport == "udp":
        return AUTO_UDP_PROBE_PORTS.get(port, "none")
    return AUTO_TCP_PROBE_PORTS.get(port, "none")


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


def _normalize_reason_code_set(values: set[str] | list[str] | None, fallback: set[str]) -> set[str]:
    if not values:
        return set(fallback)
    normalized: set[str] = set()
    for raw in values:
        name = str(raw).strip().upper()
        if name:
            normalized.add(name)
    if not normalized:
        return set(fallback)
    return normalized


def _probe_param_string(
    target: PortTarget,
    key: str,
    *,
    max_len: int = 255,
) -> str | None:
    value = target.probe_params.get(key)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def _probe_param_bool(target: PortTarget, key: str) -> bool | None:
    value = target.probe_params.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y"}:
            return True
        if lowered in {"0", "false", "no", "n"}:
            return False
    return None


def _probe_param_rcodes(target: PortTarget, key: str = "dns_acceptable_rcodes") -> set[int] | None:
    raw = target.probe_params.get(key)
    if raw is None:
        return None
    values: list[int] = []
    if isinstance(raw, int):
        values = [raw]
    elif isinstance(raw, str):
        tokens = [item.strip() for item in raw.split(",")]
        for token in tokens:
            if not token:
                continue
            try:
                values.append(int(token))
            except ValueError:
                continue
    if not values:
        return None
    return {item for item in values if 0 <= item <= 4095}


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


def _recommended_action(status: PortStatus, transport: str, probe_status: str, reason_code: str) -> str:
    if reason_code in REASON_CODE_ACTION_GUIDE:
        return REASON_CODE_ACTION_GUIDE[reason_code]
    if status == "OPEN" and probe_status == "PROBE_OK":
        return "Port and application probe are healthy."
    if status == "OPEN" and probe_status in {"PROBE_FAILED", "INVALID_RESPONSE", "PROBE_TIMEOUT"}:
        return "Port is open but application protocol failed. Check app/service logs."
    if status == "REFUSED":
        return "Target is reachable, but the service is not listening on this port."
    if status in {"TIMEOUT", "FILTERED"}:
        return "Possible firewall drop/policy block. Validate inbound/outbound and ACL policies."
    if status == "NO_ROUTE":
        return "No path to host. Verify gateway/static route/Hyper-V vSwitch path."
    if status in {"NETWORK_UNREACHABLE", "HOST_UNREACHABLE"}:
        return "Unreachable path. Verify subnet/VLAN route and destination host network state."
    if status == "UNKNOWN_HOST":
        return "Hostname resolution failed. Verify DNS settings or use direct IP."
    if status == "UDP_OPEN_OR_FILTERED":
        return "UDP can be silent. Validate with DNS/NTP application probe data."
    if status == "UDP_CLOSED":
        return "UDP appears closed (ICMP Port Unreachable)."
    if transport == "udp" and probe_status == "PROBE_TIMEOUT":
        return "UDP probe timed out. Verify service bind state and middlebox policy."
    return "Check reason_code plus target-side logs for deeper diagnosis."


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
        detail="UDP attempt failed for unknown reason.",
        latency_ms=(perf_counter() - started) * 1000,
    )


async def _udp_attempt(host: str, port: int, timeout_seconds: float, attempt: int) -> dict[str, Any]:
    return await asyncio.to_thread(_udp_attempt_sync, host, port, timeout_seconds, attempt)


async def _http_probe(
    host: str,
    port: int,
    timeout_seconds: float,
    use_tls: bool,
    *,
    host_header: str | None = None,
    path: str = "/",
    tls_sni: str | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        req_host = host_header or host
        req_path = path if path.startswith("/") else f"/{path}"
        sni_host = tls_sni or req_host or host
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=sni_host),
                timeout=timeout_seconds,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout_seconds,
            )

        request = (
            f"GET {req_path} HTTP/1.1\r\n"
            f"Host: {req_host}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
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
                "probe_meta": {"raw_response_line": text},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }

        status_code = tokens[1]
        return {
            "probe_status": "PROBE_OK",
            "probe_detail": f"HTTP response received: {status_code}",
            "probe_meta": {"http_status": status_code},
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
        response = await asyncio.wait_for(reader.read(96), timeout=timeout_seconds)

        if len(response) >= 7 and response[0] == 0x03 and response[5] in {0xD0, 0xF0}:
            return {
                "probe_status": "PROBE_OK",
                "probe_detail": "RDP negotiation response received.",
                "probe_meta": {"response_hex": response[:48].hex()},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        if response:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": f"Unexpected RDP response bytes: {response.hex()}",
                "probe_meta": {"response_hex": response[:96].hex()},
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


DNS_QTYPE_BY_PROBE = {
    "dns_a": 1,  # A
    "dns_aaaa": 28,  # AAAA
    "dns_mx": 15,  # MX
    "dns_txt": 16,  # TXT
    "dns_soa": 6,  # SOA
    "dns_srv": 33,  # SRV
}

DNS_RCODE_NAME = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_TYPE_NAME = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
}

DNS_QUERY_NAME_BY_PROBE = {
    "dns_a": "example.com",
    "dns_aaaa": "example.com",
    "dns_mx": "example.com",
    "dns_txt": "example.com",
    "dns_soa": "example.com",
    "dns_srv": "_ldap._tcp.example.com",
}


def _encode_dns_name(name: str) -> bytes:
    labels = [label for label in name.strip(".").split(".") if label]
    encoded = b""
    for label in labels:
        raw = label.encode("ascii", errors="ignore")
        encoded += len(raw).to_bytes(1, "big") + raw
    return encoded + b"\x00"


def _build_edns_opt_record(udp_payload_size: int = 1232, do_bit: bool = False) -> bytes:
    flags = 0x8000 if do_bit else 0x0000
    ttl = flags
    return b"\x00" + struct.pack("!HHIH", 41, udp_payload_size, ttl, 0)


def _sanitize_dns_query_name(raw: str | None, default_name: str) -> str:
    if raw is None:
        return default_name
    candidate = str(raw).strip().strip(".")
    if not candidate:
        return default_name
    if len(candidate) > 253:
        return default_name
    labels = candidate.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return default_name
    return candidate


def _dns_rcode_name(code: int) -> str:
    return DNS_RCODE_NAME.get(code, f"RCODE_{code}")


def _build_dns_query_packet(
    probe_type: ProbeType,
    *,
    query_name_override: str | None = None,
) -> tuple[int, bytes, int, str]:
    normalized_probe = probe_type if probe_type in DNS_QTYPE_BY_PROBE else "dns_a"
    tx_id = int.from_bytes(os.urandom(2), "big")
    query_name = _sanitize_dns_query_name(
        query_name_override,
        DNS_QUERY_NAME_BY_PROBE[normalized_probe],
    )
    qtype = DNS_QTYPE_BY_PROBE[normalized_probe]
    # RD=1, QD=1, AR=1(EDNS OPT)
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 1)
    question = _encode_dns_name(query_name) + struct.pack("!HH", qtype, 1)  # QCLASS=IN
    return tx_id, header + question + _build_edns_opt_record(), qtype, query_name


def _decode_dns_name(
    packet: bytes,
    offset: int,
    *,
    _visited: set[int] | None = None,
    _depth: int = 0,
) -> tuple[str, int]:
    if _visited is None:
        _visited = set()
    if _depth > 20:
        raise ValueError("DNS name compression recursion too deep.")

    labels: list[str] = []
    cursor = offset
    jumped = False
    next_offset = offset
    while True:
        if cursor >= len(packet):
            raise ValueError("DNS name offset out of packet bounds.")
        length = packet[cursor]
        if (length & 0xC0) == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Invalid DNS compression pointer.")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer in _visited:
                raise ValueError("DNS compression pointer loop detected.")
            _visited.add(pointer)
            pointed_name, _ = _decode_dns_name(
                packet,
                pointer,
                _visited=_visited,
                _depth=_depth + 1,
            )
            labels.append(pointed_name)
            cursor += 2
            if not jumped:
                next_offset = cursor
                jumped = True
            break
        if length == 0:
            cursor += 1
            if not jumped:
                next_offset = cursor
            break
        cursor += 1
        end = cursor + length
        if end > len(packet):
            raise ValueError("DNS label exceeds packet boundary.")
        label = packet[cursor:end].decode("ascii", errors="ignore")
        labels.append(label)
        cursor = end

    name = ".".join(part for part in labels if part)
    return name, next_offset


def _skip_dns_questions(packet: bytes, offset: int, question_count: int) -> int:
    cursor = offset
    for _ in range(question_count):
        _, cursor = _decode_dns_name(packet, cursor)
        if cursor + 4 > len(packet):
            raise ValueError("DNS question section truncated.")
        cursor += 4
    return cursor


def _dns_type_name(qtype: int) -> str:
    return DNS_TYPE_NAME.get(qtype, f"TYPE{qtype}")


def _parse_edns_options(rdata: bytes) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 4 <= len(rdata):
        option_code, option_len = struct.unpack("!HH", rdata[cursor : cursor + 4])
        cursor += 4
        end = cursor + option_len
        if end > len(rdata):
            break
        option_raw = rdata[cursor:end]
        options.append(
            {
                "code": option_code,
                "length": option_len,
                "data_hex": option_raw[:64].hex(),
            }
        )
        cursor = end
    return options


def _parse_dns_rr(packet: bytes, offset: int, section: str) -> tuple[dict[str, Any], int]:
    name, cursor = _decode_dns_name(packet, offset)
    if cursor + 10 > len(packet):
        raise ValueError("DNS resource record header truncated.")

    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[cursor : cursor + 10])
    cursor += 10
    rdata_start = cursor
    rdata_end = rdata_start + rdlength
    if rdata_end > len(packet):
        raise ValueError("DNS resource record data truncated.")

    parsed: dict[str, Any] = {
        "section": section,
        "name": name,
        "type": rtype,
        "type_name": _dns_type_name(rtype),
        "class": rclass,
        "ttl": ttl,
    }

    if rtype == 1 and rdlength == 4:  # A
        parsed["address"] = socket.inet_ntoa(packet[rdata_start:rdata_end])
    elif rtype == 28 and rdlength == 16:  # AAAA
        parsed["address"] = socket.inet_ntop(socket.AF_INET6, packet[rdata_start:rdata_end])
    elif rtype == 33 and rdlength >= 6:  # SRV
        priority, weight, service_port = struct.unpack("!HHH", packet[rdata_start : rdata_start + 6])
        target, _ = _decode_dns_name(packet, rdata_start + 6)
        parsed["priority"] = priority
        parsed["weight"] = weight
        parsed["port"] = service_port
        parsed["target"] = target
    elif rtype == 15 and rdlength >= 3:  # MX
        preference = int.from_bytes(packet[rdata_start : rdata_start + 2], "big")
        exchange, _ = _decode_dns_name(packet, rdata_start + 2)
        parsed["preference"] = preference
        parsed["exchange"] = exchange
    elif rtype == 16 and rdlength >= 1:  # TXT
        txt_values: list[str] = []
        txt_cursor = rdata_start
        while txt_cursor < rdata_end:
            text_len = packet[txt_cursor]
            txt_cursor += 1
            end = min(txt_cursor + text_len, rdata_end)
            txt_values.append(packet[txt_cursor:end].decode("utf-8", errors="ignore"))
            txt_cursor = end
        parsed["txt"] = txt_values
    elif rtype == 6:  # SOA
        mname, soa_cursor = _decode_dns_name(packet, rdata_start)
        rname, soa_cursor = _decode_dns_name(packet, soa_cursor)
        if soa_cursor + 20 <= rdata_end:
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII",
                packet[soa_cursor : soa_cursor + 20],
            )
            parsed["mname"] = mname
            parsed["rname"] = rname
            parsed["serial"] = serial
            parsed["refresh"] = refresh
            parsed["retry"] = retry
            parsed["expire"] = expire
            parsed["minimum"] = minimum
    elif rtype == 41:  # OPT (EDNS0)
        ext_rcode = (ttl >> 24) & 0xFF
        edns_version = (ttl >> 16) & 0xFF
        z = ttl & 0xFFFF
        parsed["udp_payload_size"] = rclass
        parsed["extended_rcode"] = ext_rcode
        parsed["edns_version"] = edns_version
        parsed["dnssec_ok"] = bool(z & 0x8000)
        parsed["z_flags"] = z
        parsed["options"] = _parse_edns_options(packet[rdata_start:rdata_end])
    else:
        preview = packet[rdata_start:rdata_end][:24]
        parsed["rdata_hex"] = preview.hex()

    return parsed, rdata_end


def _parse_dns_sections(
    packet: bytes,
    question_count: int,
    answer_count: int,
    authority_count: int,
    additional_count: int,
) -> dict[str, list[dict[str, Any]]]:
    cursor = _skip_dns_questions(packet, 12, question_count)

    answers: list[dict[str, Any]] = []
    authorities: list[dict[str, Any]] = []
    additionals: list[dict[str, Any]] = []

    for _ in range(answer_count):
        record, cursor = _parse_dns_rr(packet, cursor, "answer")
        answers.append(record)
    for _ in range(authority_count):
        record, cursor = _parse_dns_rr(packet, cursor, "authority")
        authorities.append(record)
    for _ in range(additional_count):
        record, cursor = _parse_dns_rr(packet, cursor, "additional")
        additionals.append(record)

    return {
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }


def _dns_records_summary(
    answers: list[dict[str, Any]],
    authorities: list[dict[str, Any]],
    additionals: list[dict[str, Any]],
    max_items: int = 3,
) -> str:
    def summarize(record: dict[str, Any]) -> str:
        type_name = str(record.get("type_name", "UNKNOWN"))
        if type_name == "A":
            return f"A {record.get('address', '-')}"
        if type_name == "AAAA":
            return f"AAAA {record.get('address', '-')}"
        if type_name == "MX":
            return f"MX {record.get('preference', '-')}" f" {record.get('exchange', '-')}"
        if type_name == "TXT":
            txt_values = record.get("txt") or []
            joined = " | ".join(str(item) for item in txt_values[:2])
            return f"TXT {joined or '-'}"
        if type_name == "SRV":
            return (
                "SRV "
                f"{record.get('priority', '-')}/{record.get('weight', '-')}/{record.get('port', '-')}"
                f" -> {record.get('target', '-')}"
            )
        if type_name == "SOA":
            return (
                "SOA "
                f"{record.get('mname', '-')} {record.get('rname', '-')}"
                f" serial={record.get('serial', '-')}"
            )
        if type_name == "OPT":
            return (
                "OPT "
                f"udp={record.get('udp_payload_size', '-')}"
                f" ver={record.get('edns_version', '-')}"
            )
        return f"{type_name} {record.get('name', '-')}"

    source = answers or authorities or additionals
    if not source:
        return "no records"
    items = [summarize(item) for item in source[:max_items]]
    if len(source) > max_items:
        items.append(f"+{len(source) - max_items} more")
    return "; ".join(items)


def _extract_edns_meta(additionals: list[dict[str, Any]]) -> dict[str, Any] | None:
    for record in additionals:
        if record.get("type") == 41 or record.get("type_name") == "OPT":
            return {
                "udp_payload_size": record.get("udp_payload_size"),
                "extended_rcode": record.get("extended_rcode"),
                "edns_version": record.get("edns_version"),
                "dnssec_ok": record.get("dnssec_ok"),
                "options": record.get("options") or [],
            }
    return None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise OSError("Socket closed while receiving data.")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _dns_probe_sync(
    host: str,
    port: int,
    timeout_seconds: float,
    probe_type: ProbeType,
    *,
    query_name_override: str | None = None,
    acceptable_rcodes: set[int] | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    query_id, packet, qtype, query_name = _build_dns_query_packet(
        probe_type,
        query_name_override=query_name_override,
    )
    qtype_name = _dns_type_name(qtype)
    accepted_rcode_set = acceptable_rcodes if acceptable_rcodes is not None else {0}

    def build_result(
        *,
        probe_status: str,
        probe_detail: str,
        probe_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "probe_status": probe_status,
            "probe_detail": probe_detail,
            "probe_meta": probe_meta or {},
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }

    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        return build_result(
            probe_status="PROBE_FAILED",
            probe_detail=f"DNS probe resolve failed: {exc}",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )

    family, socktype, proto, _, sockaddr = addr_infos[0]
    udp_response: bytes | None = None
    used_transport = "udp"
    tcp_fallback = False
    tc_flag = 0
    try:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout_seconds)
        try:
            sock.sendto(packet, sockaddr)
            udp_response, _ = sock.recvfrom(4096)
        finally:
            sock.close()
    except socket.timeout:
        return build_result(
            probe_status="PROBE_TIMEOUT",
            probe_detail=f"DNS probe timeout after {timeout_seconds:.1f}s.",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )
    except OSError as exc:
        return build_result(
            probe_status="PROBE_FAILED",
            probe_detail=f"DNS probe failed: {exc}",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )

    if not udp_response or len(udp_response) < 12:
        return build_result(
            probe_status="INVALID_RESPONSE",
            probe_detail="DNS response too short.",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )

    response = udp_response
    response_id = int.from_bytes(response[:2], "big")
    flags = int.from_bytes(response[2:4], "big")
    qr = (flags >> 15) & 0x01
    tc_flag = (flags >> 9) & 0x01

    if tc_flag == 1:
        # TC bit set: retry over TCP for full answer fidelity.
        try:
            stream_family = family if family in {socket.AF_INET, socket.AF_INET6} else socket.AF_INET
            tcp_sock = socket.socket(stream_family, socket.SOCK_STREAM)
            tcp_sock.settimeout(timeout_seconds)
            try:
                tcp_sock.connect(sockaddr)
                tcp_sock.sendall(struct.pack("!H", len(packet)) + packet)
                length_prefix = _recv_exact(tcp_sock, 2)
                message_length = int.from_bytes(length_prefix, "big")
                response = _recv_exact(tcp_sock, message_length)
                used_transport = "tcp"
                tcp_fallback = True
            finally:
                tcp_sock.close()
        except OSError:
            # Keep UDP payload and expose truncated state if TCP fallback fails.
            response = udp_response

    if len(response) < 12:
        return build_result(
            probe_status="INVALID_RESPONSE",
            probe_detail="DNS response header is invalid after TCP fallback.",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )

    flags = int.from_bytes(response[2:4], "big")
    qr = (flags >> 15) & 0x01
    rcode = flags & 0x0F
    qdcount = int.from_bytes(response[4:6], "big")
    ancount = int.from_bytes(response[6:8], "big")
    nscount = int.from_bytes(response[8:10], "big")
    arcount = int.from_bytes(response[10:12], "big")

    if response_id != query_id or qr != 1:
        return build_result(
            probe_status="INVALID_RESPONSE",
            probe_detail="DNS response header is invalid.",
            probe_meta={"query_type": qtype, "query_name": query_name},
        )

    parse_error: str | None = None
    answers: list[dict[str, Any]] = []
    authorities: list[dict[str, Any]] = []
    additionals: list[dict[str, Any]] = []
    edns_meta: dict[str, Any] | None = None

    try:
        sections = _parse_dns_sections(response, qdcount, ancount, nscount, arcount)
        answers = sections["answers"]
        authorities = sections["authorities"]
        additionals = sections["additionals"]
        edns_meta = _extract_edns_meta(additionals)
    except Exception as exc:
        parse_error = str(exc)

    summary = _dns_records_summary(answers, authorities, additionals)
    ext_rcode = 0
    if edns_meta and isinstance(edns_meta.get("extended_rcode"), int):
        ext_rcode = int(edns_meta["extended_rcode"])
    full_rcode = (ext_rcode << 4) | rcode
    rcode_name = _dns_rcode_name(full_rcode)
    detail = (
        f"DNS {qtype_name} response via {used_transport.upper()} "
        f"(rcode={full_rcode}:{rcode_name}, answers={ancount}, auth={nscount}, add={arcount})"
    )
    if summary:
        detail = f"{detail}: {summary}"

    probe_status = "PROBE_OK"
    if parse_error:
        probe_status = "INVALID_RESPONSE"
    elif full_rcode not in accepted_rcode_set:
        # Hard fail by policy: SERVFAIL/REFUSED must be treated as probe failure.
        probe_status = "PROBE_FAILED"
        if full_rcode in {2, 5}:
            detail = f"{detail} (hard fail rcode={rcode_name})"
        else:
            detail = f"{detail} (unexpected rcode={rcode_name})"

    return build_result(
        probe_status=probe_status,
        probe_detail=detail,
        probe_meta={
            "query_type": qtype,
            "query_type_name": qtype_name,
            "query_name": query_name,
            "rcode": rcode,
            "extended_rcode": ext_rcode,
            "full_rcode": full_rcode,
            "rcode_name": rcode_name,
            "accepted_rcodes": sorted(accepted_rcode_set),
            "answer_count": ancount,
            "authority_count": nscount,
            "additional_count": arcount,
            "truncated_udp": bool(tc_flag),
            "fallback_to_tcp": tcp_fallback,
            "response_transport": used_transport,
            "answers": answers[:12],
            "authorities": authorities[:12],
            "additionals": additionals[:12],
            "edns": edns_meta,
            "parse_error": parse_error,
            "raw_query_hex": packet[:96].hex(),
            "raw_response_hex": response[:256].hex(),
        },
    )


def _ntp_probe_sync(host: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    started = perf_counter()
    request = b"\x1b" + (47 * b"\x00")
    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": f"NTP probe resolve failed: {exc}",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }

    family, socktype, proto, _, sockaddr = addr_infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout_seconds)
    try:
        sock.sendto(request, sockaddr)
        response, _ = sock.recvfrom(512)
        if len(response) < 48:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": "NTP response too short.",
                "probe_meta": {"response_hex": response[:96].hex()},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        first_byte = response[0]
        mode = first_byte & 0x07
        version = (first_byte >> 3) & 0x07
        stratum = response[1]
        if mode not in {4, 5}:  # server / broadcast server
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": f"Unexpected NTP mode: {mode} (version={version}, stratum={stratum})",
                "probe_meta": {
                    "mode": mode,
                    "version": version,
                    "stratum": stratum,
                    "response_hex": response[:96].hex(),
                },
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        return {
            "probe_status": "PROBE_OK",
            "probe_detail": f"NTP response received (version={version}, stratum={stratum}, mode={mode}).",
            "probe_meta": {
                "mode": mode,
                "version": version,
                "stratum": stratum,
                "response_hex": response[:96].hex(),
            },
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except socket.timeout:
        return {
            "probe_status": "PROBE_TIMEOUT",
            "probe_detail": f"NTP probe timeout after {timeout_seconds:.1f}s.",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except OSError as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": f"NTP probe failed: {exc}",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    finally:
        sock.close()


async def _run_application_probe(
    host: str,
    port: int,
    probe_type: ProbeType,
    timeout_seconds: float,
    target: PortTarget,
) -> dict[str, Any]:
    http_host = _probe_param_string(target, "http_host")
    http_path = _probe_param_string(target, "http_path") or "/"
    tls_sni = _probe_param_string(target, "tls_sni")
    dns_query_name = _probe_param_string(target, "dns_query_name")
    dns_acceptable_rcodes = _probe_param_rcodes(target)

    if probe_type == "http":
        return await _http_probe(
            host,
            port,
            timeout_seconds,
            use_tls=False,
            host_header=http_host,
            path=http_path,
        )
    if probe_type == "https":
        return await _http_probe(
            host,
            port,
            timeout_seconds,
            use_tls=True,
            host_header=http_host,
            path=http_path,
            tls_sni=tls_sni,
        )
    if probe_type == "rdp":
        return await _rdp_probe(host, port, timeout_seconds)
    if probe_type in {"dns", "dns_a", "dns_aaaa", "dns_mx", "dns_txt", "dns_srv", "dns_soa"}:
        return await asyncio.to_thread(
            _dns_probe_sync,
            host,
            port,
            timeout_seconds,
            probe_type,
            query_name_override=dns_query_name,
            acceptable_rcodes=dns_acceptable_rcodes,
        )
    if probe_type == "ntp":
        return await asyncio.to_thread(_ntp_probe_sync, host, port, timeout_seconds)
    return {
        "probe_status": "SKIPPED",
        "probe_detail": "No application probe configured.",
        "probe_latency_ms": 0.0,
    }


def _status_priority(status: str, overrides: dict[str, int] | None = None) -> int:
    name = status.upper()
    if overrides and name in overrides:
        return int(overrides[name])
    return STATUS_PRIORITY_DEFAULT.get(name, 0)


def _choose_final_status(
    attempts: list[dict[str, Any]],
    *,
    status_priority_overrides: dict[str, int] | None = None,
) -> PortStatus:
    if not attempts:
        return "ERROR"

    statuses = [str(item["status"]).upper() for item in attempts]
    counter = Counter(statuses)
    ranked = sorted(
        counter.items(),
        key=lambda item: (
            _status_priority(item[0], status_priority_overrides),
            item[1],  # frequency
            max(i for i, status in enumerate(statuses) if status == item[0]),  # last seen
        ),
        reverse=True,
    )
    chosen = ranked[0][0]
    return chosen if chosen in STATUS_PRIORITY_DEFAULT else "ERROR"


def _should_retry(
    *,
    status: PortStatus,
    reason_code: str,
    attempt_no: int,
    max_attempts: int,
    retry_reason_allowlist: set[str],
    retry_reason_denylist: set[str],
) -> bool:
    if attempt_no >= max_attempts:
        return False
    reason = str(reason_code).upper()
    if reason in retry_reason_denylist:
        return False
    if status in NON_RETRYABLE_STATUSES:
        return False
    if reason in retry_reason_allowlist:
        return True
    if status in RETRYABLE_STATUSES:
        return True
    # Retry unknown status only for known transient reason codes.
    return reason in ADAPTIVE_REASON_MULTIPLIERS


def _adaptive_backoff_seconds(
    *,
    base_ms: int,
    cap_ms: int,
    attempt_no: int,
    status: PortStatus,
    reason_code: str,
) -> float:
    if base_ms <= 0 or cap_ms <= 0:
        return 0.0

    multiplier = ADAPTIVE_REASON_MULTIPLIERS.get(reason_code, 1.0)
    if status in {"TIMEOUT", "FILTERED"}:
        multiplier = max(multiplier, 1.3)
    elif status in {"NETWORK_UNREACHABLE", "HOST_UNREACHABLE", "NO_ROUTE"}:
        multiplier = max(multiplier, 1.7)
    elif status == "UDP_OPEN_OR_FILTERED":
        multiplier = max(multiplier, 1.1)

    expo = 2 ** max(attempt_no - 1, 0)
    delay_ms = min(int(base_ms * expo * multiplier), cap_ms)
    return round(delay_ms / 1000.0, 4)


def _consistency_indicator(attempts: list[dict[str, Any]], threshold_percent: float) -> tuple[str, float]:
    if not attempts:
        return ("UNKNOWN", 0.0)
    statuses = [str(item["status"]) for item in attempts]
    counter = Counter(statuses)
    most_common_count = counter.most_common(1)[0][1]
    score = round((most_common_count / len(statuses)) * 100, 2)
    label = "STABLE" if score >= threshold_percent else "FLAKY"
    return (label, score)


def _expand_server_port_targets(server: ServerTarget) -> list[PortTarget]:
    combined = [PortTarget(port=port, transport="tcp", probe="auto") for port in server.ports]
    combined.extend(server.port_targets)
    deduped: dict[tuple[int, str, str, int | None, str], PortTarget] = {}
    for target in combined:
        params_key = json.dumps(target.probe_params, sort_keys=True, ensure_ascii=True)
        key = (target.port, target.transport, target.probe, target.retries, params_key)
        if key not in deduped:
            deduped[key] = target
    return list(deduped.values())


def _build_host_circuit_breaker_result(
    *,
    server: ServerTarget,
    target: PortTarget,
    trigger_status: PortStatus,
    trigger_port: int,
    trigger_reason_code: str,
) -> dict[str, Any]:
    return {
        "checked_at": _utc_now_iso(),
        "server_id": server.id,
        "server_name": server.name,
        "host": server.host,
        "port": target.port,
        "transport": target.transport,
        "probe_type": _resolve_probe_type(target.probe, target.port, target.transport),
        "retry_count": target.retries if target.retries is not None else 0,
        "attempt_count": 0,
        "status": trigger_status,
        "reason_code": "HOST_CIRCUIT_BREAKER",
        "detail": (
            f"Skipped by host circuit breaker after {trigger_status} on "
            f"port {trigger_port} ({trigger_reason_code})."
        ),
        "recommended_action": _recommended_action(
            trigger_status,
            target.transport,
            "SKIPPED",
            trigger_reason_code,
        ),
        "consistency": "UNKNOWN",
        "consistency_score": 0.0,
        "latency_ms": 0.0,
        "total_latency_ms": 0.0,
        "attempts": [],
        "probe_result": {
            "probe_type": _resolve_probe_type(target.probe, target.port, target.transport),
            "probe_status": "SKIPPED",
            "probe_detail": "Skipped by host circuit breaker.",
            "probe_latency_ms": 0.0,
        },
    }


async def _emit_progress(progress_callback: ProgressCallback | None, payload: dict[str, Any]) -> None:
    if progress_callback is None:
        return
    maybe_result = progress_callback(payload)
    if inspect.isawaitable(maybe_result):
        await maybe_result


async def check_single_port_target(
    *,
    server_id: str,
    server_name: str,
    host: str,
    target: PortTarget,
    timeout_seconds: float = 2.0,
    probe_timeout_seconds: float | None = None,
    default_retries: int = 2,
    retry_backoff_base_ms: int = 0,
    retry_backoff_max_ms: int = 0,
    flaky_threshold_percent: float = 100.0,
    status_priority_overrides: dict[str, int] | None = None,
    retry_reason_allowlist: set[str] | list[str] | None = None,
    retry_reason_denylist: set[str] | list[str] | None = None,
    udp_enforce_probe_on_open_or_filtered: bool = True,
) -> dict[str, Any]:
    check_started = perf_counter()
    retries = target.retries if target.retries is not None else default_retries
    max_attempts = retries + 1
    attempts: list[dict[str, Any]] = []
    retry_allow_set = _normalize_reason_code_set(
        retry_reason_allowlist,
        DEFAULT_RETRY_REASON_ALLOWLIST,
    )
    retry_deny_set = _normalize_reason_code_set(
        retry_reason_denylist,
        DEFAULT_RETRY_REASON_DENYLIST,
    )

    for attempt_no in range(1, max_attempts + 1):
        if target.transport == "udp":
            attempt = await _udp_attempt(host, target.port, timeout_seconds, attempt_no)
        else:
            attempt = await _tcp_attempt(host, target.port, timeout_seconds, attempt_no)
        attempts.append(attempt)

        if attempt["status"] == "OPEN":
            break
        if not _should_retry(
            status=attempt["status"],
            reason_code=str(attempt["reason_code"]),
            attempt_no=attempt_no,
            max_attempts=max_attempts,
            retry_reason_allowlist=retry_allow_set,
            retry_reason_denylist=retry_deny_set,
        ):
            break

        backoff_seconds = _adaptive_backoff_seconds(
            base_ms=retry_backoff_base_ms,
            cap_ms=retry_backoff_max_ms,
            attempt_no=attempt_no,
            status=attempt["status"],
            reason_code=str(attempt["reason_code"]),
        )
        if backoff_seconds > 0:
            await asyncio.sleep(backoff_seconds)

    final_status = _choose_final_status(
        attempts,
        status_priority_overrides=status_priority_overrides,
    )
    final_attempt = attempts[-1]
    final_reason_code = str(final_attempt["reason_code"])
    probe_type = _resolve_probe_type(target.probe, target.port, target.transport)
    probe_result = {
        "probe_type": probe_type,
        "probe_status": "SKIPPED",
        "probe_detail": "No application probe configured.",
        "probe_latency_ms": 0.0,
    }

    can_probe_tcp = target.transport == "tcp" and final_status == "OPEN"
    can_probe_udp = target.transport == "udp" and final_status in {"OPEN", "UDP_OPEN_OR_FILTERED"}
    probe_timeout = min(float(probe_timeout_seconds or timeout_seconds), timeout_seconds)
    if probe_type != "none" and (can_probe_tcp or can_probe_udp):
        probe_result = {
            "probe_type": probe_type,
            **(await _run_application_probe(host, target.port, probe_type, probe_timeout, target)),
        }

    detail = final_attempt["detail"]
    if final_status == "FILTERED":
        detail = f"{detail} Final decision: likely filtered/dropped after {len(attempts)} attempts."

    # UDP refinement policy:
    # - Promote uncertain UDP status to OPEN when application probe succeeds.
    # - If uncertain and no probe is configured while policy is enabled, annotate as policy failure.
    if target.transport == "udp" and final_status == "UDP_OPEN_OR_FILTERED":
        if str(probe_result.get("probe_status")) == "PROBE_OK":
            final_status = "OPEN"
            final_reason_code = "UDP_PROBE_CONFIRMED"
            detail = f"{detail} Promoted to OPEN by UDP application probe success."
        elif udp_enforce_probe_on_open_or_filtered and probe_type == "none":
            final_reason_code = "UDP_PROBE_REQUIRED"
            detail = (
                f"{detail} Policy requires an explicit UDP application probe "
                "for OPEN_OR_FILTERED verdict."
            )

    consistency, consistency_score = _consistency_indicator(attempts, threshold_percent=flaky_threshold_percent)

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
        "reason_code": final_reason_code,
        "detail": detail,
        "recommended_action": _recommended_action(
            final_status,
            target.transport,
            str(probe_result["probe_status"]),
            final_reason_code,
        ),
        "consistency": consistency,
        "consistency_score": consistency_score,
        "latency_ms": round(final_attempt["latency_ms"], 2),
        "total_latency_ms": total_elapsed,
        "attempts": attempts,
        "probe_result": probe_result,
    }


async def run_port_sweep(
    servers: list[ServerTarget],
    timeout_seconds: float = 2.0,
    probe_timeout_seconds: float | None = None,
    default_retries: int = 2,
    max_concurrency: int = 200,
    batch_size: int = 250,
    retry_backoff_base_ms: int = 0,
    retry_backoff_max_ms: int = 0,
    flaky_threshold_percent: float = 100.0,
    status_priority_overrides: dict[str, int] | None = None,
    retry_reason_allowlist: list[str] | set[str] | None = None,
    retry_reason_denylist: list[str] | set[str] | None = None,
    udp_enforce_probe_on_open_or_filtered: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    started = perf_counter()
    max_concurrency = max(1, int(max_concurrency))
    batch_size = max(max_concurrency, int(batch_size))
    retry_allow_set = _normalize_reason_code_set(
        retry_reason_allowlist,
        DEFAULT_RETRY_REASON_ALLOWLIST,
    )
    retry_deny_set = _normalize_reason_code_set(
        retry_reason_denylist,
        DEFAULT_RETRY_REASON_DENYLIST,
    )

    expanded_targets: list[tuple[ServerTarget, PortTarget]] = []
    for server in servers:
        for target in _expand_server_port_targets(server):
            expanded_targets.append((server, target))

    total_targets = len(expanded_targets)
    if total_targets == 0:
        return {
            "results": [],
            "summary": {
                "total_checks": 0,
                "duration_ms": 0.0,
                "status_counts": {},
                "transport_counts": {},
                "probe_status_counts": {},
                "consistency_counts": {},
                "batch_count": 0,
                "max_concurrency": max_concurrency,
            },
        }

    semaphore = asyncio.Semaphore(max_concurrency)
    progress_lock = asyncio.Lock()
    results: list[dict[str, Any]] = []
    processed = 0
    batch_count = 0

    async def check_worker(server: ServerTarget, target: PortTarget) -> dict[str, Any]:
        async with semaphore:
            return await check_single_port_target(
                server_id=server.id,
                server_name=server.name,
                host=server.host,
                target=target,
                timeout_seconds=timeout_seconds,
                probe_timeout_seconds=probe_timeout_seconds,
                default_retries=default_retries,
                retry_backoff_base_ms=retry_backoff_base_ms,
                retry_backoff_max_ms=retry_backoff_max_ms,
                flaky_threshold_percent=flaky_threshold_percent,
                status_priority_overrides=status_priority_overrides,
                retry_reason_allowlist=retry_allow_set,
                retry_reason_denylist=retry_deny_set,
                udp_enforce_probe_on_open_or_filtered=udp_enforce_probe_on_open_or_filtered,
            )

    async def push_result(result: dict[str, Any], *, batch_index: int, batch_total: int) -> None:
        nonlocal processed
        async with progress_lock:
            results.append(result)
            processed += 1
            payload = {
                "processed": processed,
                "total": total_targets,
                "progress_percent": round((processed / total_targets) * 100, 2),
                "batch_index": batch_index,
                "batch_total": batch_total,
                "last": {
                    "server_name": result.get("server_name"),
                    "host": result.get("host"),
                    "port": result.get("port"),
                    "transport": result.get("transport"),
                    "status": result.get("status"),
                    "reason_code": result.get("reason_code"),
                },
            }
        await _emit_progress(progress_callback, payload)

    # Group by host to support host-level circuit breaker.
    host_targets: dict[str, list[tuple[ServerTarget, PortTarget]]] = {}
    for server, target in expanded_targets:
        host_targets.setdefault(server.host, []).append((server, target))

    host_items = list(host_targets.items())
    host_batch_size = max(1, min(len(host_items), batch_size))
    total_host_batches = (len(host_items) + host_batch_size - 1) // host_batch_size

    async def host_worker(
        host: str,
        targets: list[tuple[ServerTarget, PortTarget]],
        *,
        batch_index: int,
    ) -> None:
        breaker: tuple[PortStatus, int, str] | None = None
        for server, target in targets:
            if breaker is not None:
                trigger_status, trigger_port, trigger_reason = breaker
                skipped = _build_host_circuit_breaker_result(
                    server=server,
                    target=target,
                    trigger_status=trigger_status,
                    trigger_port=trigger_port,
                    trigger_reason_code=trigger_reason,
                )
                await push_result(
                    skipped,
                    batch_index=batch_index,
                    batch_total=total_host_batches,
                )
                continue

            result = await check_worker(server, target)
            await push_result(
                result,
                batch_index=batch_index,
                batch_total=total_host_batches,
            )
            status = str(result.get("status", "")).upper()
            if status in {"UNKNOWN_HOST", "NO_ROUTE"}:
                breaker = (
                    status if status in {"UNKNOWN_HOST", "NO_ROUTE"} else "UNKNOWN_HOST",
                    int(result.get("port") or target.port),
                    str(result.get("reason_code") or "UNKNOWN"),
                )

    for batch_start in range(0, len(host_items), host_batch_size):
        chunk = host_items[batch_start : batch_start + host_batch_size]
        batch_count += 1
        tasks = [
            asyncio.create_task(
                host_worker(host, targets, batch_index=batch_count),
            )
            for host, targets in chunk
        ]
        try:
            for finished in asyncio.as_completed(tasks):
                await finished
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            with suppress(Exception):
                await asyncio.gather(*tasks, return_exceptions=True)

    status_counts: dict[str, int] = {}
    transport_counts: dict[str, int] = {}
    probe_counts: dict[str, int] = {}
    consistency_counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        transport = str(result["transport"])
        probe_status = str(result["probe_result"]["probe_status"])
        consistency = str(result.get("consistency", "UNKNOWN"))
        status_counts[status] = status_counts.get(status, 0) + 1
        transport_counts[transport] = transport_counts.get(transport, 0) + 1
        probe_counts[probe_status] = probe_counts.get(probe_status, 0) + 1
        consistency_counts[consistency] = consistency_counts.get(consistency, 0) + 1

    total_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "results": results,
        "summary": {
            "total_checks": len(results),
            "duration_ms": total_ms,
            "status_counts": status_counts,
            "transport_counts": transport_counts,
            "probe_status_counts": probe_counts,
            "consistency_counts": consistency_counts,
            "batch_count": batch_count,
            "max_concurrency": max_concurrency,
        },
    }
