from __future__ import annotations

import asyncio
import socket
from contextlib import suppress
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from ..models import PortStatus, ServerTarget


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def check_single_port(
    *,
    server_id: str,
    server_name: str,
    host: str,
    port: int,
    timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    started = perf_counter()
    status: PortStatus
    detail: str

    try:
        open_connection = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(open_connection, timeout=timeout_seconds)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        status = "OPEN"
        detail = "TCP handshake succeeded."
    except ConnectionRefusedError:
        status = "REFUSED"
        detail = "Target is reachable but the service port is closed."
    except asyncio.TimeoutError:
        status = "TIMEOUT"
        detail = "No response within 2.0s (likely firewall drop)."
    except socket.gaierror:
        status = "UNKNOWN_HOST"
        detail = "Hostname or IP could not be resolved."
    except OSError as exc:
        if getattr(exc, "errno", None) in {10060, 110}:
            status = "TIMEOUT"
            detail = f"No response within 2.0s: {exc}"
        else:
            status = "ERROR"
            detail = str(exc)

    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "checked_at": _utc_now_iso(),
        "server_id": server_id,
        "server_name": server_name,
        "host": host,
        "port": port,
        "status": status,
        "detail": detail,
        "latency_ms": elapsed_ms,
    }


async def run_port_sweep(
    servers: list[ServerTarget],
    timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    started = perf_counter()
    tasks: list[asyncio.Task[dict[str, Any]]] = []

    for server in servers:
        for port in server.ports:
            tasks.append(
                asyncio.create_task(
                    check_single_port(
                        server_id=server.id,
                        server_name=server.name,
                        host=server.host,
                        port=port,
                        timeout_seconds=timeout_seconds,
                    )
                )
            )

    results = await asyncio.gather(*tasks) if tasks else []
    counts = {
        "OPEN": 0,
        "REFUSED": 0,
        "TIMEOUT": 0,
        "UNKNOWN_HOST": 0,
        "ERROR": 0,
    }
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    total_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "results": results,
        "summary": {
            "total_checks": len(results),
            "duration_ms": total_ms,
            "status_counts": counts,
        },
    }

