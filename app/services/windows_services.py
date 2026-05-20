from __future__ import annotations

import asyncio
import json
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any

from ..models import ServerTarget


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_ps_single_quote(value: str) -> str:
    return value.replace("'", "''")


def _run_powershell_script(script: str, timeout_seconds: float = 8.0) -> tuple[bytes, bytes, str | None]:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        return completed.stdout, completed.stderr, None
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        return b"", stderr, "TIMEOUT"
    except FileNotFoundError:
        return b"", b"powershell executable not found", "POWERSHELL_NOT_FOUND"
    except Exception as exc:  # Defensive guard: never crash /api/check on service query failure
        return b"", str(exc).encode("utf-8", errors="ignore"), "EXEC_ERROR"


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
    stdout, stderr, exec_error = await asyncio.to_thread(_run_powershell_script, script, 8.0)
    if exec_error == "TIMEOUT":
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": "Service query timed out",
        }
    if exec_error:
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": f"PowerShell execution failed: {exec_error}",
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
    task_specs: list[tuple[ServerTarget, str, asyncio.Task[dict[str, Any]]]] = []
    for server in servers:
        for service_name in server.services:
            task_specs.append((server, service_name, asyncio.create_task(_check_service(server, service_name))))

    tasks = [task for _, _, task in task_specs]
    gathered = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    results: list[dict[str, Any]] = []
    for (server, service_name, _), item in zip(task_specs, gathered):
        if isinstance(item, Exception):
            results.append(
                {
                    "checked_at": _utc_now_iso(),
                    "server_id": server.id,
                    "server_name": server.name,
                    "host": server.host,
                    "service_name": service_name,
                    "status": "ERROR",
                    "detail": f"Unexpected service check error: {item}",
                }
            )
        else:
            results.append(item)

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
