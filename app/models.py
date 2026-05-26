from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


TransportProtocol = Literal["tcp", "udp"]
ProbeType = Literal[
    "none",
    "auto",
    "http",
    "https",
    "rdp",
    "dns",
    "dns_a",
    "dns_aaaa",
    "dns_mx",
    "dns_txt",
    "dns_srv",
    "dns_soa",
    "ntp",
]

TCP_ONLY_PROBES = frozenset({"http", "https", "rdp"})
UDP_ONLY_PROBES = frozenset(
    {
        "dns",
        "dns_a",
        "dns_aaaa",
        "dns_mx",
        "dns_txt",
        "dns_srv",
        "dns_soa",
        "ntp",
    }
)

CredentialSecretProvider = Literal[
    "dpapi",
    "env",
    "azure_key_vault",
    "aws_secrets_manager",
    "hashicorp_vault",
    "legacy_plaintext",
]
CredentialSecretProviderInput = Literal[
    "dpapi",
    "env",
    "azure_key_vault",
    "aws_secrets_manager",
    "hashicorp_vault",
]


class PortTarget(BaseModel):
    port: int = Field(ge=1, le=65535)
    transport: TransportProtocol = "tcp"
    probe: ProbeType = "auto"
    retries: int | None = Field(default=None, ge=0, le=5)

    @model_validator(mode="after")
    def validate_probe_transport(self) -> "PortTarget":
        if self.transport == "tcp" and self.probe in UDP_ONLY_PROBES:
            raise ValueError(f"Probe '{self.probe}' requires UDP transport.")
        if self.transport == "udp" and self.probe in TCP_ONLY_PROBES:
            raise ValueError(f"Probe '{self.probe}' requires TCP transport.")
        return self


class TargetTemplate(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=300)
    port_targets: list[PortTarget] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return value.strip()

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        deduped: dict[tuple[int, str, str], PortTarget] = {}
        for target in port_targets:
            key = (target.port, target.transport, target.probe)
            if key not in deduped:
                deduped[key] = target
        return list(deduped.values())

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "TargetTemplate":
        if not self.port_targets:
            raise ValueError("Template requires at least one port_target.")
        return self


class TemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=300)
    port_targets: list[PortTarget] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return TargetTemplate.validate_name(value)

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        return TargetTemplate.validate_description(value)

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        return TargetTemplate.validate_port_targets(port_targets)

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "TemplateCreate":
        if not self.port_targets:
            raise ValueError("Template requires at least one port_target.")
        return self


class TemplateUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=300)
    port_targets: list[PortTarget] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return TargetTemplate.validate_name(value)

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        return TargetTemplate.validate_description(value)

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        return TargetTemplate.validate_port_targets(port_targets)

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "TemplateUpdate":
        if not self.port_targets:
            raise ValueError("Template requires at least one port_target.")
        return self


class CredentialProfile(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=255)
    secret_provider: CredentialSecretProvider = "dpapi"
    encrypted_password: str | None = Field(default=None, max_length=4000)
    secret_ref: str | None = Field(default=None, max_length=1024)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)
    legacy_password: str | None = Field(default=None, validation_alias="password", exclude=True)

    @field_validator("name", "username")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field cannot be empty.")
        return stripped

    @field_validator("domain", "description", "encrypted_password", "secret_ref", "legacy_password")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @model_validator(mode="after")
    def validate_secret_fields(self) -> "CredentialProfile":
        if self.secret_provider == "dpapi":
            if not self.encrypted_password and not self.legacy_password:
                raise ValueError("DPAPI profile requires encrypted_password.")
        elif self.secret_provider in {
            "env",
            "azure_key_vault",
            "aws_secrets_manager",
            "hashicorp_vault",
        }:
            if not self.secret_ref:
                raise ValueError(f"{self.secret_provider} profile requires secret_ref.")
        elif self.secret_provider == "legacy_plaintext":
            if not self.legacy_password:
                raise ValueError("legacy_plaintext profile requires password.")
        return self


class CredentialProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=255)
    secret_provider: CredentialSecretProviderInput = "dpapi"
    password: str | None = Field(default=None, min_length=1, max_length=255)
    secret_ref: str | None = Field(default=None, max_length=1024)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("name", "username")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        return CredentialProfile.validate_required_text(value)

    @field_validator("password", "secret_ref", "domain", "description")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        return CredentialProfile.validate_optional_text(value)

    @model_validator(mode="after")
    def validate_secret_input(self) -> "CredentialProfileCreate":
        if self.secret_provider == "dpapi" and not self.password:
            raise ValueError("password is required when secret_provider=dpapi.")
        if self.secret_provider in {
            "env",
            "azure_key_vault",
            "aws_secrets_manager",
            "hashicorp_vault",
        } and not self.secret_ref:
            raise ValueError("secret_ref is required for external secret providers.")
        return self


class CredentialProfileUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=255)
    secret_provider: CredentialSecretProviderInput = "dpapi"
    password: str | None = Field(default=None, min_length=1, max_length=255)
    secret_ref: str | None = Field(default=None, max_length=1024)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("name", "username")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        return CredentialProfile.validate_required_text(value)

    @field_validator("password", "secret_ref", "domain", "description")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        return CredentialProfile.validate_optional_text(value)

    @model_validator(mode="after")
    def validate_secret_input(self) -> "CredentialProfileUpdate":
        if self.secret_provider in {
            "env",
            "azure_key_vault",
            "aws_secrets_manager",
            "hashicorp_vault",
        } and not self.secret_ref:
            raise ValueError("secret_ref is required for external secret providers.")
        return self


class ServerTarget(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(default_factory=list)
    port_targets: list[PortTarget] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    enable_remote_metrics: bool = True
    credential_profile_id: str | None = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        normalized = sorted({int(port) for port in ports})
        for port in normalized:
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")
        return normalized

    @field_validator("services")
    @classmethod
    def validate_services(cls, services: list[str]) -> list[str]:
        normalized = [service.strip() for service in services if service.strip()]
        return list(dict.fromkeys(normalized))

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        deduped: dict[tuple[int, str, str], PortTarget] = {}
        for target in port_targets:
            key = (target.port, target.transport, target.probe)
            if key not in deduped:
                deduped[key] = target
        return list(deduped.values())

    @field_validator("credential_profile_id")
    @classmethod
    def validate_credential_profile_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "ServerTarget":
        if not self.ports and not self.port_targets:
            raise ValueError("At least one port or port_target is required.")
        return self


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(default_factory=list)
    port_targets: list[PortTarget] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    enable_remote_metrics: bool = True
    credential_profile_id: str | None = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        return ServerTarget.validate_ports(ports)

    @field_validator("services")
    @classmethod
    def validate_services(cls, services: list[str]) -> list[str]:
        return ServerTarget.validate_services(services)

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        return ServerTarget.validate_port_targets(port_targets)

    @field_validator("credential_profile_id")
    @classmethod
    def validate_credential_profile_id(cls, value: str | None) -> str | None:
        return ServerTarget.validate_credential_profile_id(value)

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "ServerCreate":
        if not self.ports and not self.port_targets:
            raise ValueError("At least one port or port_target is required.")
        return self


class ServerUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(default_factory=list)
    port_targets: list[PortTarget] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    enable_remote_metrics: bool = True
    credential_profile_id: str | None = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        return ServerTarget.validate_ports(ports)

    @field_validator("services")
    @classmethod
    def validate_services(cls, services: list[str]) -> list[str]:
        return ServerTarget.validate_services(services)

    @field_validator("port_targets")
    @classmethod
    def validate_port_targets(cls, port_targets: list[PortTarget]) -> list[PortTarget]:
        return ServerTarget.validate_port_targets(port_targets)

    @field_validator("credential_profile_id")
    @classmethod
    def validate_credential_profile_id(cls, value: str | None) -> str | None:
        return ServerTarget.validate_credential_profile_id(value)

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "ServerUpdate":
        if not self.ports and not self.port_targets:
            raise ValueError("At least one port or port_target is required.")
        return self


class AppConfig(BaseModel):
    timeout_seconds: float = 2.0
    probe_timeout_seconds: float = 1.5
    port_check_retries: int = 2
    max_concurrency: int = 200
    batch_size: int = 250
    retry_backoff_base_ms: int = 120
    retry_backoff_max_ms: int = 1500
    flaky_threshold_percent: float = 100.0
    status_priority_overrides: dict[str, int] = Field(default_factory=dict)
    history_enabled: bool = True
    history_retention_days: int = 30
    default_page_size: int = 200
    servers: list[ServerTarget] = Field(default_factory=list)
    templates: list[TargetTemplate] = Field(default_factory=list)
    credential_profiles: list[CredentialProfile] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: float) -> float:
        if round(float(value), 1) != 2.0:
            raise ValueError("timeout_seconds must be exactly 2.0")
        return 2.0

    @field_validator("port_check_retries")
    @classmethod
    def validate_retry_count(cls, value: int) -> int:
        value = int(value)
        if value < 0 or value > 5:
            raise ValueError("port_check_retries must be between 0 and 5")
        return value

    @field_validator("probe_timeout_seconds")
    @classmethod
    def validate_probe_timeout(cls, value: float) -> float:
        value = float(value)
        if value <= 0 or value > 10:
            raise ValueError("probe_timeout_seconds must be between 0 and 10")
        return round(value, 3)

    @field_validator("max_concurrency")
    @classmethod
    def validate_max_concurrency(cls, value: int) -> int:
        value = int(value)
        if value < 1 or value > 5000:
            raise ValueError("max_concurrency must be between 1 and 5000")
        return value

    @field_validator("batch_size")
    @classmethod
    def validate_batch_size(cls, value: int) -> int:
        value = int(value)
        if value < 1 or value > 10000:
            raise ValueError("batch_size must be between 1 and 10000")
        return value

    @field_validator("retry_backoff_base_ms")
    @classmethod
    def validate_backoff_base(cls, value: int) -> int:
        value = int(value)
        if value < 0 or value > 5000:
            raise ValueError("retry_backoff_base_ms must be between 0 and 5000")
        return value

    @field_validator("retry_backoff_max_ms")
    @classmethod
    def validate_backoff_max(cls, value: int) -> int:
        value = int(value)
        if value < 0 or value > 30000:
            raise ValueError("retry_backoff_max_ms must be between 0 and 30000")
        return value

    @field_validator("flaky_threshold_percent")
    @classmethod
    def validate_flaky_threshold(cls, value: float) -> float:
        value = float(value)
        if value < 50 or value > 100:
            raise ValueError("flaky_threshold_percent must be between 50 and 100")
        return round(value, 2)

    @field_validator("status_priority_overrides")
    @classmethod
    def validate_status_priority_overrides(cls, value: dict[str, int]) -> dict[str, int]:
        normalized: dict[str, int] = {}
        for key, raw in value.items():
            name = str(key).strip().upper()
            if not name:
                continue
            weight = int(raw)
            if weight < 0 or weight > 10000:
                raise ValueError(f"status priority out of range for {name}: {weight}")
            normalized[name] = weight
        return normalized

    @field_validator("history_retention_days")
    @classmethod
    def validate_history_retention_days(cls, value: int) -> int:
        value = int(value)
        if value < 1 or value > 3650:
            raise ValueError("history_retention_days must be between 1 and 3650")
        return value

    @field_validator("default_page_size")
    @classmethod
    def validate_default_page_size(cls, value: int) -> int:
        value = int(value)
        if value < 20 or value > 1000:
            raise ValueError("default_page_size must be between 20 and 1000")
        return value

    @model_validator(mode="after")
    def validate_cross_fields(self) -> "AppConfig":
        if self.probe_timeout_seconds > self.timeout_seconds:
            raise ValueError("probe_timeout_seconds cannot exceed timeout_seconds")
        if self.retry_backoff_max_ms < self.retry_backoff_base_ms:
            raise ValueError("retry_backoff_max_ms must be >= retry_backoff_base_ms")
        if self.batch_size < self.max_concurrency:
            # Keep batch big enough to avoid starving configured concurrency.
            self.batch_size = self.max_concurrency
        return self


PortStatus = Literal[
    "OPEN",
    "REFUSED",
    "TIMEOUT",
    "UNKNOWN_HOST",
    "NETWORK_UNREACHABLE",
    "HOST_UNREACHABLE",
    "NO_ROUTE",
    "FILTERED",
    "UDP_OPEN_OR_FILTERED",
    "UDP_CLOSED",
    "PROBE_TIMEOUT",
    "PROBE_FAILED",
    "INVALID_RESPONSE",
    "ERROR",
]
