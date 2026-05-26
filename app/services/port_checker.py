from __future__ import annotations

import asyncio
import errno
import os
import struct
import socket
import ssl
from collections import Counter
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

AUTO_TCP_PROBE_PORTS: dict[int, ProbeType] = {
    80: "http",
    443: "https",
    3389: "rdp",
}
AUTO_UDP_PROBE_PORTS: dict[int, ProbeType] = {
    53: "dns_a",
    123: "ntp",
}

RETRYABLE_STATUSES: set[str] = {"TIMEOUT", "FILTERED", "ERROR", "PROBE_TIMEOUT"}

REASON_CODE_ACTION_GUIDE = {
    "WSAETIMEDOUT": "타임아웃: 대상/중간 방화벽 드롭 정책과 경로 지연을 확인하세요.",
    "ETIMEDOUT": "타임아웃: 대상 서비스 지연 또는 네트워크 드롭 여부를 확인하세요.",
    "WSAENETUNREACH": "네트워크 도달 불가: 라우팅 테이블, 게이트웨이, VLAN 구성을 확인하세요.",
    "ENETUNREACH": "네트워크 도달 불가: 경로 및 서브넷 설정을 확인하세요.",
    "WSAEHOSTUNREACH": "호스트 도달 불가: 대상 서버 전원 및 NIC 연결 상태를 확인하세요.",
    "EHOSTUNREACH": "호스트 도달 불가: 대상 IP와 네트워크 경로를 확인하세요.",
    "WSAECONNREFUSED": "포트 거절: 서비스 미기동 또는 리슨 포트 오설정 가능성이 큽니다.",
    "ECONNREFUSED": "포트 거절: 대상 서비스가 해당 포트를 리슨 중인지 확인하세요.",
    "WSAEACCES": "접근 차단: 로컬/원격 방화벽 또는 보안정책(EDR/ACL) 확인이 필요합니다.",
    "EAI_NONAME": "호스트명 해석 실패: DNS 서버 설정 및 호스트명 오타를 확인하세요.",
    "NO_UDP_RESPONSE": "UDP 무응답: UDP는 무응답이 정상일 수 있습니다. DNS/NTP 프로브 결과를 함께 확인하세요.",
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
        return "접속 및 애플리케이션 응답이 정상입니다."
    if status == "OPEN" and probe_status in {"PROBE_FAILED", "INVALID_RESPONSE", "PROBE_TIMEOUT"}:
        return "포트는 열려 있으나 앱 응답이 비정상입니다. 서비스 프로세스/앱 로그를 확인하세요."
    if status == "REFUSED":
        return "대상은 도달되지만 서비스가 포트를 리슨하지 않습니다. 서비스 실행 상태를 확인하세요."
    if status in {"TIMEOUT", "FILTERED"}:
        return "방화벽/보안장비 드롭 가능성이 높습니다. 인바운드/아웃바운드 및 ACL 정책을 점검하세요."
    if status == "NO_ROUTE":
        return "라우팅 경로가 없습니다. 게이트웨이, 정적 라우트, Hyper-V vSwitch 구성을 확인하세요."
    if status in {"NETWORK_UNREACHABLE", "HOST_UNREACHABLE"}:
        return "네트워크/호스트 도달 불가입니다. 대상 IP, 서브넷, VLAN, 전원 상태를 확인하세요."
    if status == "UNKNOWN_HOST":
        return "호스트명 해석 실패입니다. DNS 설정 또는 IP 직접 입력을 확인하세요."
    if status == "UDP_OPEN_OR_FILTERED":
        return "UDP는 무응답이 정상일 수 있습니다. DNS/NTP 같은 프로토콜 프로브를 함께 사용하세요."
    if status == "UDP_CLOSED":
        return "UDP 포트가 닫혀 있거나 ICMP Port Unreachable 응답을 받았습니다."
    if transport == "udp" and probe_status == "PROBE_TIMEOUT":
        return "UDP 프로브 응답이 없습니다. 서비스 기동 여부와 중간 장비 드롭 정책을 확인하세요."
    return "상세 오류코드(reason_code)와 서버 로그를 기반으로 추가 점검이 필요합니다."


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


DNS_QTYPE_BY_PROBE = {
    "dns_a": 1,  # A
    "dns_soa": 6,  # SOA
    "dns_srv": 33,  # SRV
}

DNS_QUERY_NAME_BY_PROBE = {
    "dns_a": "example.com",
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


def _build_dns_query_packet(probe_type: ProbeType) -> tuple[int, bytes, int, str]:
    normalized_probe = probe_type if probe_type in DNS_QTYPE_BY_PROBE else "dns_a"
    tx_id = int.from_bytes(os.urandom(2), "big")
    query_name = DNS_QUERY_NAME_BY_PROBE[normalized_probe]
    qtype = DNS_QTYPE_BY_PROBE[normalized_probe]
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(query_name) + struct.pack("!HH", qtype, 1)  # QCLASS=IN
    return tx_id, header + question, qtype, query_name


def _dns_probe_sync(host: str, port: int, timeout_seconds: float, probe_type: ProbeType) -> dict[str, Any]:
    started = perf_counter()
    query_id, packet, qtype, query_name = _build_dns_query_packet(probe_type)
    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": f"DNS probe resolve failed: {exc}",
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }

    family, socktype, proto, _, sockaddr = addr_infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout_seconds)
    try:
        sock.sendto(packet, sockaddr)
        response, _ = sock.recvfrom(512)
        if len(response) < 12:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": "DNS response too short.",
                "probe_meta": {"query_type": qtype, "query_name": query_name},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        response_id = int.from_bytes(response[:2], "big")
        qr = (response[2] >> 7) & 0x01
        rcode = response[3] & 0x0F
        ancount = int.from_bytes(response[6:8], "big")
        if response_id != query_id or qr != 1:
            return {
                "probe_status": "INVALID_RESPONSE",
                "probe_detail": "DNS response header is invalid.",
                "probe_meta": {"query_type": qtype, "query_name": query_name},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        return {
            "probe_status": "PROBE_OK",
            "probe_detail": f"DNS response received (qtype={qtype}, rcode={rcode}, answers={ancount}).",
            "probe_meta": {
                "query_type": qtype,
                "query_name": query_name,
                "rcode": rcode,
                "answer_count": ancount,
            },
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except socket.timeout:
        return {
            "probe_status": "PROBE_TIMEOUT",
            "probe_detail": f"DNS probe timeout after {timeout_seconds:.1f}s.",
            "probe_meta": {"query_type": qtype, "query_name": query_name},
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    except OSError as exc:
        return {
            "probe_status": "PROBE_FAILED",
            "probe_detail": f"DNS probe failed: {exc}",
            "probe_meta": {"query_type": qtype, "query_name": query_name},
            "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
        }
    finally:
        sock.close()


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
                "probe_meta": {"mode": mode, "version": version, "stratum": stratum},
                "probe_latency_ms": round((perf_counter() - started) * 1000, 2),
            }
        return {
            "probe_status": "PROBE_OK",
            "probe_detail": f"NTP response received (version={version}, stratum={stratum}, mode={mode}).",
            "probe_meta": {"mode": mode, "version": version, "stratum": stratum},
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


async def _run_application_probe(host: str, port: int, probe_type: ProbeType, timeout_seconds: float) -> dict[str, Any]:
    if probe_type == "http":
        return await _http_probe(host, port, timeout_seconds, use_tls=False)
    if probe_type == "https":
        return await _http_probe(host, port, timeout_seconds, use_tls=True)
    if probe_type == "rdp":
        return await _rdp_probe(host, port, timeout_seconds)
    if probe_type in {"dns", "dns_a", "dns_srv", "dns_soa"}:
        return await asyncio.to_thread(_dns_probe_sync, host, port, timeout_seconds, probe_type)
    if probe_type == "ntp":
        return await asyncio.to_thread(_ntp_probe_sync, host, port, timeout_seconds)
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


def _consistency_indicator(attempts: list[dict[str, Any]]) -> tuple[str, float]:
    if not attempts:
        return ("UNKNOWN", 0.0)
    statuses = [str(item["status"]) for item in attempts]
    counter = Counter(statuses)
    most_common_count = counter.most_common(1)[0][1]
    score = round((most_common_count / len(statuses)) * 100, 2)
    label = "STABLE" if len(counter) == 1 else "FLAKY"
    return (label, score)


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
    probe_type = _resolve_probe_type(target.probe, target.port, target.transport)
    probe_result = {
        "probe_type": probe_type,
        "probe_status": "SKIPPED",
        "probe_detail": "No application probe configured.",
        "probe_latency_ms": 0.0,
    }

    can_probe_tcp = target.transport == "tcp" and final_status == "OPEN"
    can_probe_udp = target.transport == "udp" and final_status in {"OPEN", "UDP_OPEN_OR_FILTERED"}
    if probe_type != "none" and (can_probe_tcp or can_probe_udp):
        probe_result = {
            "probe_type": probe_type,
            **(await _run_application_probe(host, target.port, probe_type, timeout_seconds)),
        }

    detail = final_attempt["detail"]
    if final_status == "FILTERED":
        detail = f"{detail} Final decision: likely filtered/dropped after {len(attempts)} attempts."
    consistency, consistency_score = _consistency_indicator(attempts)

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
        "recommended_action": _recommended_action(
            final_status,
            target.transport,
            str(probe_result["probe_status"]),
            str(final_attempt["reason_code"]),
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
        },
    }
