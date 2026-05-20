from __future__ import annotations

import asyncio
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import psutil

from ..models import ServerTarget


def collect_local_metrics() -> dict[str, Any]:
    cpu_percent = psutil.cpu_percent(interval=0.2)
    memory = psutil.virtual_memory()
    disk_root = Path.cwd().anchor or "/"
    disk = psutil.disk_usage(disk_root)
    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": round(cpu_percent, 2),
        "memory_percent": round(memory.percent, 2),
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "memory_total_gb": round(memory.total / (1024**3), 2),
        "disk_percent": round(disk.percent, 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
    }


def _escape_ps_single_quote(value: str) -> str:
    return value.replace("'", "''")


async def _query_remote_metrics(server: ServerTarget) -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "SKIPPED",
            "detail": "Remote PowerShell metrics are only supported on Windows host.",
        }

    host = _escape_ps_single_quote(server.host)
    started = perf_counter()

    script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $cpu = (Get-Counter -ComputerName '{host}' -Counter '\\Processor(_Total)\\% Processor Time' -MaxSamples 1).CounterSamples[0].CookedValue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName '{host}'
    $mem = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100
    [PSCustomObject]@{{
        status = 'OK'
        host = '{host}'
        cpu_percent = [math]::Round($cpu, 2)
        memory_percent = [math]::Round($mem, 2)
    }} | ConvertTo-Json -Compress
}} catch {{
    [PSCustomObject]@{{
        status = 'ERROR'
        host = '{host}'
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
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": "Remote metrics command timed out.",
        }

    output = stdout.decode("utf-8", errors="ignore").strip()
    error = stderr.decode("utf-8", errors="ignore").strip()

    if not output:
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": error or "No output from PowerShell command.",
        }

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": f"Failed to parse PowerShell output: {output}",
        }

    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    if payload.get("status") == "OK":
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "OK",
            "cpu_percent": payload.get("cpu_percent"),
            "memory_percent": payload.get("memory_percent"),
            "latency_ms": elapsed_ms,
        }

    return {
        "server_id": server.id,
        "server_name": server.name,
        "host": server.host,
        "status": "ERROR",
        "detail": payload.get("error") or error or "Unknown error",
    }


async def collect_remote_metrics(servers: list[ServerTarget]) -> list[dict[str, Any]]:
    enabled_servers = [server for server in servers if server.enable_remote_metrics]
    deduped: dict[str, ServerTarget] = {}
    for server in enabled_servers:
        if server.host not in deduped:
            deduped[server.host] = server

    tasks = [asyncio.create_task(_query_remote_metrics(server)) for server in deduped.values()]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)

