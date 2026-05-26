from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    AppConfig,
    CredentialProfile,
    CredentialProfileCreate,
    CredentialProfileUpdate,
    ServerCreate,
    ServerTarget,
    ServerUpdate,
    TargetTemplate,
    TemplateCreate,
    TemplateUpdate,
)
from .services.secret_store import SecretStoreError, encrypt_password_dpapi


class ConfigManager:
    def __init__(self, config_path: Path):
        self._config_path = config_path
        self._lock = threading.RLock()
        self._config = self._load_or_bootstrap()

    def _default_config(self) -> AppConfig:
        return AppConfig(
            servers=[
                ServerTarget(
                    name="AD-01",
                    host="192.168.0.101",
                    ports=[53, 88, 135, 389, 445, 3389],
                    services=["NTDS", "DNS"],
                    enable_remote_metrics=True,
                ),
                ServerTarget(
                    name="WEB-01",
                    host="192.168.0.110",
                    ports=[80, 443, 3389],
                    services=["W3SVC"],
                    enable_remote_metrics=True,
                ),
            ]
        )

    def _migrate_legacy_credential_profiles(self, config: AppConfig) -> bool:
        changed = False
        for profile in config.credential_profiles:
            has_legacy = bool(profile.legacy_password)
            if not has_legacy:
                continue
            try:
                profile.encrypted_password = encrypt_password_dpapi(profile.legacy_password or "")
            except SecretStoreError as exc:
                raise ValueError(
                    f"Failed to migrate legacy plaintext credential profile '{profile.name}': {exc}"
                ) from exc
            profile.secret_provider = "dpapi"
            profile.legacy_password = None
            changed = True
        return changed

    def _load_or_bootstrap(self) -> AppConfig:
        if not self._config_path.exists():
            config = self._default_config()
            self._write(config)
            return config

        raw = self._config_path.read_text(encoding="utf-8")
        if not raw.strip():
            config = self._default_config()
            self._write(config)
            return config

        config = AppConfig.model_validate_json(raw)
        if self._migrate_legacy_credential_profiles(config):
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
        return config

    def _write(self, config: AppConfig) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = config.model_dump(mode="json")
        self._config_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _credential_profile_exists(self, config: AppConfig, profile_id: str) -> bool:
        return any(profile.id == profile_id for profile in config.credential_profiles)

    def _validate_server_credential_profile(self, config: AppConfig, server: ServerTarget) -> None:
        profile_id = server.credential_profile_id
        if profile_id is None:
            return
        if not self._credential_profile_exists(config, profile_id):
            raise ValueError(f"Credential profile not found: {profile_id}")

    def _build_profile_for_create(self, payload: CredentialProfileCreate) -> CredentialProfile:
        provider = payload.secret_provider
        if provider == "dpapi":
            if not payload.password:
                raise ValueError("password is required for dpapi profile.")
            try:
                encrypted = encrypt_password_dpapi(payload.password)
            except SecretStoreError as exc:
                raise ValueError(str(exc)) from exc
            return CredentialProfile(
                name=payload.name,
                username=payload.username,
                secret_provider="dpapi",
                encrypted_password=encrypted,
                secret_ref=None,
                domain=payload.domain,
                description=payload.description,
            )

        return CredentialProfile(
            name=payload.name,
            username=payload.username,
            secret_provider=provider,
            encrypted_password=None,
            secret_ref=payload.secret_ref,
            domain=payload.domain,
            description=payload.description,
        )

    def _build_profile_for_update(
        self,
        existing: CredentialProfile,
        payload: CredentialProfileUpdate,
        profile_id: str,
    ) -> CredentialProfile:
        provider = payload.secret_provider
        if provider == "dpapi":
            encrypted_password: str | None = None
            if payload.password:
                try:
                    encrypted_password = encrypt_password_dpapi(payload.password)
                except SecretStoreError as exc:
                    raise ValueError(str(exc)) from exc
            elif existing.secret_provider == "dpapi" and existing.encrypted_password:
                encrypted_password = existing.encrypted_password
            else:
                raise ValueError(
                    "password is required when switching to dpapi or when existing encrypted secret is unavailable."
                )

            return CredentialProfile(
                id=profile_id,
                name=payload.name,
                username=payload.username,
                secret_provider="dpapi",
                encrypted_password=encrypted_password,
                secret_ref=None,
                domain=payload.domain,
                description=payload.description,
            )

        return CredentialProfile(
            id=profile_id,
            name=payload.name,
            username=payload.username,
            secret_provider=provider,
            encrypted_password=None,
            secret_ref=payload.secret_ref,
            domain=payload.domain,
            description=payload.description,
        )

    def get_config(self) -> AppConfig:
        with self._lock:
            return self._config.model_copy(deep=True)

    def list_servers(self) -> list[ServerTarget]:
        return self.get_config().servers

    def add_server(self, server_create: ServerCreate) -> ServerTarget:
        with self._lock:
            server = ServerTarget(**server_create.model_dump())
            config = self._config.model_copy(deep=True)
            self._validate_server_credential_profile(config, server)
            config.servers.append(server)
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return server

    def update_server(self, server_id: str, server_update: ServerUpdate) -> ServerTarget:
        with self._lock:
            config = self._config.model_copy(deep=True)
            index = next(
                (i for i, server in enumerate(config.servers) if server.id == server_id),
                None,
            )
            if index is None:
                raise KeyError(f"Server not found: {server_id}")

            updated = ServerTarget(id=server_id, **server_update.model_dump())
            self._validate_server_credential_profile(config, updated)
            config.servers[index] = updated
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return updated

    def delete_server(self, server_id: str) -> None:
        with self._lock:
            config = self._config.model_copy(deep=True)
            before = len(config.servers)
            config.servers = [server for server in config.servers if server.id != server_id]
            if len(config.servers) == before:
                raise KeyError(f"Server not found: {server_id}")
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config

    def list_templates(self) -> list[TargetTemplate]:
        return self.get_config().templates

    def add_template(self, template_create: TemplateCreate) -> TargetTemplate:
        with self._lock:
            template = TargetTemplate(**template_create.model_dump())
            config = self._config.model_copy(deep=True)
            config.templates.append(template)
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return template

    def update_template(self, template_id: str, template_update: TemplateUpdate) -> TargetTemplate:
        with self._lock:
            config = self._config.model_copy(deep=True)
            index = next(
                (i for i, template in enumerate(config.templates) if template.id == template_id),
                None,
            )
            if index is None:
                raise KeyError(f"Template not found: {template_id}")

            updated = TargetTemplate(id=template_id, **template_update.model_dump())
            config.templates[index] = updated
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return updated

    def delete_template(self, template_id: str) -> None:
        with self._lock:
            config = self._config.model_copy(deep=True)
            before = len(config.templates)
            config.templates = [template for template in config.templates if template.id != template_id]
            if len(config.templates) == before:
                raise KeyError(f"Template not found: {template_id}")
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config

    def list_credential_profiles(self) -> list[CredentialProfile]:
        return self.get_config().credential_profiles

    def add_credential_profile(self, profile_create: CredentialProfileCreate) -> CredentialProfile:
        with self._lock:
            profile = self._build_profile_for_create(profile_create)
            config = self._config.model_copy(deep=True)
            config.credential_profiles.append(profile)
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return profile

    def update_credential_profile(
        self,
        profile_id: str,
        profile_update: CredentialProfileUpdate,
    ) -> CredentialProfile:
        with self._lock:
            config = self._config.model_copy(deep=True)
            index = next(
                (i for i, profile in enumerate(config.credential_profiles) if profile.id == profile_id),
                None,
            )
            if index is None:
                raise KeyError(f"Credential profile not found: {profile_id}")

            existing = config.credential_profiles[index]
            updated = self._build_profile_for_update(existing, profile_update, profile_id)
            config.credential_profiles[index] = updated
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
            return updated

    def delete_credential_profile(self, profile_id: str) -> None:
        with self._lock:
            config = self._config.model_copy(deep=True)
            for server in config.servers:
                if server.credential_profile_id == profile_id:
                    raise ValueError(
                        f"Credential profile is in use by server '{server.name}' ({server.host})."
                    )

            before = len(config.credential_profiles)
            config.credential_profiles = [
                profile for profile in config.credential_profiles if profile.id != profile_id
            ]
            if len(config.credential_profiles) == before:
                raise KeyError(f"Credential profile not found: {profile_id}")
            config.updated_at = datetime.now(timezone.utc)
            self._write(config)
            self._config = config
