from __future__ import annotations

import asyncio
import json
import platform
from datetime import datetime, timezone
from typing import Any

from ..models import ServerTarget


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_ps_single_quote(value: str) -> str:
    return value.replace("'", "''")


async def _check_service(server: ServerTarget, service_name: str) -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "SKIPPED",
            "detail": "Windows host required",
        }

    host = _escape_ps_single_quote(server.host)
    service = _escape_ps_single_quote(service_name)
    script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $svc = Get-Service -ComputerName '{host}' -Name '{service}'
    [PSCustomObject]@{{
        status = 'OK'
        service_state = $svc.Status.ToString()
    }} | ConvertTo-Json -Compress
}} catch {{
    [PSCustomObject]@{{
        status = 'ERROR'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
""".strip()

    proc = await asyncio.create_subprocess_exec(
        "powershell",
        "-NoProfile",
        "-Command",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": "Service query timed out",
        }

    output = stdout.decode("utf-8", errors="ignore").strip()
    error_output = stderr.decode("utf-8", errors="ignore").strip()
    if not output:
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": error_output or "No output",
        }

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": output,
        }

    if payload.get("status") == "OK":
        raw_state = str(payload.get("service_state", "")).upper()
        mapped = "RUNNING" if raw_state == "RUNNING" else "STOPPED"
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": mapped,
            "detail": raw_state or "UNKNOWN",
        }

    error_message = payload.get("error") or error_output or "Unknown error"
    mapped = "NOT_FOUND" if "cannot find any service" in error_message.lower() else "ERROR"
    return {
        "checked_at": _utc_now_iso(),
        "server_id": server.id,
        "server_name": server.name,
        "host": server.host,
        "service_name": service_name,
        "status": mapped,
        "detail": error_message,
    }


async def run_service_sweep(servers: list[ServerTarget]) -> dict[str, Any]:
    tasks: list[asyncio.Task[dict[str, Any]]] = []
    for server in servers:
        for service_name in server.services:
            tasks.append(asyncio.create_task(_check_service(server, service_name)))

    results = await asyncio.gather(*tasks) if tasks else []
    counts = {
        "RUNNING": 0,
        "STOPPED": 0,
        "NOT_FOUND": 0,
        "ERROR": 0,
        "SKIPPED": 0,
    }
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    return {
        "results": results,
        "summary": {
            "total_checks": len(results),
            "status_counts": counts,
        },
    }

