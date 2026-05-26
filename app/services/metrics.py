from __future__ import annotations

import asyncio
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import psutil

from ..models import CredentialProfile, ServerTarget
from .secret_store import SecretStoreError, get_secret_material


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
    except Exception as exc:  # Defensive guard: never crash /api/check on remote metric failure
        return b"", str(exc).encode("utf-8", errors="ignore"), "EXEC_ERROR"


def _resolved_username(profile: CredentialProfile) -> str:
    if profile.domain:
        return f"{profile.domain}\\{profile.username}"
    return profile.username


def _credential_preamble(
    profile: CredentialProfile | None,
) -> tuple[str, str, str]:
    if profile is None:
        return "$cred = $null", "current_user", "current_user"
    material = get_secret_material(profile)
    username = _escape_ps_single_quote(_resolved_username(profile))
    encrypted_password = _escape_ps_single_quote(material.encrypted_password)
    preamble = (
        f"$secPwd = ConvertTo-SecureString '{encrypted_password}'; "
        f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $secPwd)"
    )
    source = material.provider
    if material.provider in {"env", "azure_key_vault"}:
        source = f"{material.provider}:{material.source_detail}"
    return preamble, profile.name, source


def _build_remote_metrics_script(host: str, credential_preamble: str) -> str:
    return f"""
$ErrorActionPreference = 'Stop'
{credential_preamble}
try {{
    if ($null -eq $cred) {{
        $cpuSamples = Get-CimInstance -ClassName Win32_Processor -ComputerName '{host}' | Select-Object -ExpandProperty LoadPercentage
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName '{host}'
    }} else {{
        $cpuSamples = Get-CimInstance -ClassName Win32_Processor -ComputerName '{host}' -Credential $cred | Select-Object -ExpandProperty LoadPercentage
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName '{host}' -Credential $cred
    }}

    $cpu = ($cpuSamples | Measure-Object -Average).Average
    if ($null -eq $cpu) {{ $cpu = 0 }}
    $mem = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100
    [PSCustomObject]@{{
        status = 'OK'
        host = '{host}'
        cpu_percent = [math]::Round([double]$cpu, 2)
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


async def _query_remote_metrics(
    server: ServerTarget,
    profile_lookup: dict[str, CredentialProfile],
) -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "SKIPPED",
            "detail": "Remote PowerShell metrics are only supported on Windows host.",
            "credential_profile": server.credential_profile_id or "current_user",
        }

    profile: CredentialProfile | None = None
    if server.credential_profile_id:
        profile = profile_lookup.get(server.credential_profile_id)
        if profile is None:
            return {
                "server_id": server.id,
                "server_name": server.name,
                "host": server.host,
                "status": "ERROR",
                "detail": f"Credential profile not found: {server.credential_profile_id}",
                "credential_profile": server.credential_profile_id,
            }

    host = _escape_ps_single_quote(server.host)
    started = perf_counter()

    try:
        credential_preamble, profile_name, profile_source = _credential_preamble(profile)
    except SecretStoreError as exc:
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": f"Credential resolution failed: {exc}",
            "credential_profile": profile.name if profile else "current_user",
        }

    script = _build_remote_metrics_script(host, credential_preamble)
    stdout, stderr, exec_error = await asyncio.to_thread(_run_powershell_script, script, 8.0)
    if exec_error == "TIMEOUT":
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": "Remote metrics command timed out.",
            "credential_profile": profile_name,
            "credential_source": profile_source,
        }
    if exec_error:
        return {
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "status": "ERROR",
            "detail": f"PowerShell execution failed: {exec_error}",
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
        }

    return {
        "server_id": server.id,
        "server_name": server.name,
        "host": server.host,
        "status": "ERROR",
        "detail": payload.get("error") or error or "Unknown error",
        "credential_profile": profile_name,
        "credential_source": profile_source,
    }


async def collect_remote_metrics(
    servers: list[ServerTarget],
    credential_profiles: list[CredentialProfile],
) -> list[dict[str, Any]]:
    enabled_servers = [server for server in servers if server.enable_remote_metrics]
    deduped: dict[str, ServerTarget] = {}
    for server in enabled_servers:
        if server.host not in deduped:
            deduped[server.host] = server

    profile_lookup = {profile.id: profile for profile in credential_profiles}
    tasks = [
        asyncio.create_task(_query_remote_metrics(server, profile_lookup))
        for server in deduped.values()
    ]
    if not tasks:
        return []
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[dict[str, Any]] = []
    for server, item in zip(deduped.values(), gathered):
        if isinstance(item, Exception):
            results.append(
                {
                    "server_id": server.id,
                    "server_name": server.name,
                    "host": server.host,
                    "status": "ERROR",
                    "detail": f"Unexpected remote metrics error: {item}",
                    "credential_profile": server.credential_profile_id or "current_user",
                }
            )
        else:
            results.append(item)
    return results
