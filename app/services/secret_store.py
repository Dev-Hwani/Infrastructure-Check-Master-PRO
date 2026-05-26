from __future__ import annotations

import json
import os
import platform
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..models import CredentialProfile

AZURE_KV_API_VERSION = "7.4"


class SecretStoreError(ValueError):
    pass


@dataclass(frozen=True)
class SecretMaterial:
    provider: str
    encrypted_password: str
    source_detail: str


def _escape_ps_single_quote(value: str) -> str:
    return value.replace("'", "''")


def _run_powershell_script(script: str, timeout_seconds: float = 8.0) -> str:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SecretStoreError("PowerShell executable not found.") from exc
    except subprocess.TimeoutExpired as exc:
        raise SecretStoreError("PowerShell encryption command timed out.") from exc
    except Exception as exc:
        raise SecretStoreError(f"PowerShell encryption command failed: {exc}") from exc

    stdout = completed.stdout.decode("utf-8", errors="ignore").strip()
    stderr = completed.stderr.decode("utf-8", errors="ignore").strip()
    if completed.returncode != 0:
        raise SecretStoreError(stderr or "PowerShell command failed while handling secret.")
    if not stdout:
        raise SecretStoreError(stderr or "PowerShell command returned empty output.")
    return stdout


def encrypt_password_dpapi(password: str) -> str:
    if platform.system().lower() != "windows":
        raise SecretStoreError("DPAPI encryption is supported only on Windows.")
    escaped = _escape_ps_single_quote(password)
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$sec=ConvertTo-SecureString '{escaped}' -AsPlainText -Force; "
        "$enc=ConvertFrom-SecureString $sec; "
        "Write-Output $enc"
    )
    return _run_powershell_script(script, timeout_seconds=8.0)


def _normalize_azure_secret_url(secret_ref: str) -> str:
    ref = secret_ref.strip()
    if ref.lower().startswith("azurekv:"):
        ref = ref[8:].strip()
    elif ref.startswith("@Microsoft.KeyVault(") and "SecretUri=" in ref:
        marker = "SecretUri="
        start = ref.index(marker) + len(marker)
        end = ref.rfind(")")
        ref = ref[start:end] if end > start else ref[start:]
    if not ref.lower().startswith("https://"):
        raise SecretStoreError("azure_key_vault secret_ref must be an HTTPS URL.")
    if "api-version=" in ref:
        return ref
    separator = "&" if "?" in ref else "?"
    return f"{ref}{separator}api-version={AZURE_KV_API_VERSION}"


def _resolve_env_secret(secret_ref: str) -> str:
    ref = secret_ref.strip()
    var_name = ref[4:] if ref.lower().startswith("env:") else ref
    var_name = var_name.strip()
    if not var_name:
        raise SecretStoreError("env secret_ref is empty.")
    value = os.getenv(var_name)
    if not value:
        raise SecretStoreError(f"Environment secret not found: {var_name}")
    return value


def _resolve_azure_key_vault_secret(secret_ref: str) -> str:
    token = os.getenv("AZURE_KEYVAULT_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")
    if not token:
        raise SecretStoreError(
            "Azure Key Vault token not found. Set AZURE_KEYVAULT_TOKEN or AZURE_ACCESS_TOKEN."
        )
    url = _normalize_azure_secret_url(secret_ref)
    request = urllib.request.Request(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=8.0) as response:
            payload = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        raise SecretStoreError(f"Azure Key Vault HTTP error ({exc.code}): {body}") from exc
    except urllib.error.URLError as exc:
        raise SecretStoreError(f"Azure Key Vault network error: {exc}") from exc

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SecretStoreError("Azure Key Vault response is not valid JSON.") from exc

    value = data.get("value")
    if not isinstance(value, str) or not value:
        raise SecretStoreError("Azure Key Vault secret response does not contain a valid 'value'.")
    return value


def resolve_secret_text(provider: str, secret_ref: str) -> str:
    if provider == "env":
        return _resolve_env_secret(secret_ref)
    if provider == "azure_key_vault":
        return _resolve_azure_key_vault_secret(secret_ref)
    raise SecretStoreError(f"Unsupported external secret provider: {provider}")


def get_secret_material(profile: CredentialProfile) -> SecretMaterial:
    provider = profile.secret_provider
    if provider == "dpapi":
        if not profile.encrypted_password:
            raise SecretStoreError(f"Credential profile '{profile.name}' has no encrypted_password.")
        return SecretMaterial(
            provider="dpapi",
            encrypted_password=profile.encrypted_password,
            source_detail="dpapi",
        )

    if provider in {"env", "azure_key_vault"}:
        if not profile.secret_ref:
            raise SecretStoreError(f"Credential profile '{profile.name}' has no secret_ref.")
        plain_secret = resolve_secret_text(provider, profile.secret_ref)
        encrypted = encrypt_password_dpapi(plain_secret)
        return SecretMaterial(
            provider=provider,
            encrypted_password=encrypted,
            source_detail=profile.secret_ref,
        )

    if provider == "legacy_plaintext":
        if not profile.legacy_password:
            raise SecretStoreError(f"Credential profile '{profile.name}' has empty legacy password.")
        encrypted = encrypt_password_dpapi(profile.legacy_password)
        return SecretMaterial(
            provider="legacy_plaintext",
            encrypted_password=encrypted,
            source_detail="legacy_plaintext",
        )

    raise SecretStoreError(f"Unsupported credential provider: {provider}")

