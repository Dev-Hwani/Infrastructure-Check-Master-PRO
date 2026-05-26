from __future__ import annotations

import asyncio
import json
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any

from ..models import CredentialProfile, ServerTarget
from .secret_store import SecretStoreError, get_secret_material


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


def _resolved_username(profile: CredentialProfile) -> str:
    if profile.domain:
        return f"{profile.domain}\\{profile.username}"
    return profile.username


def _credential_preamble(profile: CredentialProfile | None) -> tuple[str, str, str]:
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


def _build_service_script(host: str, service: str, credential_preamble: str) -> str:
    service_filter = service.replace("'", "''")
    return f"""
$ErrorActionPreference = 'Stop'
{credential_preamble}
try {{
    if ($null -eq $cred) {{
        $svc = Get-CimInstance -ClassName Win32_Service -ComputerName '{host}' -Filter "Name='{service_filter}'"
    }} else {{
        $svc = Get-CimInstance -ClassName Win32_Service -ComputerName '{host}' -Filter "Name='{service_filter}'" -Credential $cred
    }}

    if ($null -eq $svc) {{
        [PSCustomObject]@{{
            status = 'NOT_FOUND'
            service_state = ''
            detail = 'Service not found'
        }} | ConvertTo-Json -Compress
    }} else {{
        [PSCustomObject]@{{
            status = 'OK'
            service_state = $svc.State
            detail = $svc.DisplayName
        }} | ConvertTo-Json -Compress
    }}
}} catch {{
    [PSCustomObject]@{{
        status = 'ERROR'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
""".strip()


async def _check_service(
    server: ServerTarget,
    service_name: str,
    profile_lookup: dict[str, CredentialProfile],
) -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "SKIPPED",
            "detail": "Windows host required",
            "credential_profile": server.credential_profile_id or "current_user",
        }

    profile: CredentialProfile | None = None
    if server.credential_profile_id:
        profile = profile_lookup.get(server.credential_profile_id)
        if profile is None:
            return {
                "checked_at": _utc_now_iso(),
                "server_id": server.id,
                "server_name": server.name,
                "host": server.host,
                "service_name": service_name,
                "status": "ERROR",
                "detail": f"Credential profile not found: {server.credential_profile_id}",
                "credential_profile": server.credential_profile_id,
            }

    host = _escape_ps_single_quote(server.host)
    service = _escape_ps_single_quote(service_name)
    try:
        credential_preamble, profile_name, profile_source = _credential_preamble(profile)
    except SecretStoreError as exc:
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "ERROR",
            "detail": f"Credential resolution failed: {exc}",
            "credential_profile": profile.name if profile else "current_user",
        }

    script = _build_service_script(host, service, credential_preamble)
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
        }

    status = payload.get("status")
    if status == "OK":
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
            "credential_profile": profile_name,
            "credential_source": profile_source,
        }

    if status == "NOT_FOUND":
        return {
            "checked_at": _utc_now_iso(),
            "server_id": server.id,
            "server_name": server.name,
            "host": server.host,
            "service_name": service_name,
            "status": "NOT_FOUND",
            "detail": payload.get("detail") or "Service not found",
            "credential_profile": profile_name,
            "credential_source": profile_source,
        }

    error_message = payload.get("error") or error_output or "Unknown error"
    return {
        "checked_at": _utc_now_iso(),
        "server_id": server.id,
        "server_name": server.name,
        "host": server.host,
        "service_name": service_name,
        "status": "ERROR",
        "detail": error_message,
        "credential_profile": profile_name,
        "credential_source": profile_source,
    }


async def run_service_sweep(
    servers: list[ServerTarget],
    credential_profiles: list[CredentialProfile],
) -> dict[str, Any]:
    profile_lookup = {profile.id: profile for profile in credential_profiles}
    task_specs: list[tuple[ServerTarget, str, asyncio.Task[dict[str, Any]]]] = []
    for server in servers:
        for service_name in server.services:
            task_specs.append(
                (
                    server,
                    service_name,
                    asyncio.create_task(_check_service(server, service_name, profile_lookup)),
                )
            )

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
                    "credential_profile": server.credential_profile_id or "current_user",
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
