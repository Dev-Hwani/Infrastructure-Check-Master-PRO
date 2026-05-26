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
    "dns_srv",
    "dns_soa",
    "ntp",
]


class PortTarget(BaseModel):
    port: int = Field(ge=1, le=65535)
    transport: TransportProtocol = "tcp"
    probe: ProbeType = "auto"
    retries: int | None = Field(default=None, ge=0, le=5)


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
    password: str = Field(min_length=1, max_length=255)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("name", "username", "password")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field cannot be empty.")
        return stripped

    @field_validator("domain", "description")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class CredentialProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=255)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("name", "username", "password")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        return CredentialProfile.validate_required_text(value)

    @field_validator("domain", "description")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        return CredentialProfile.validate_optional_text(value)


class CredentialProfileUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=255)
    domain: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=300)

    @field_validator("name", "username", "password")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        return CredentialProfile.validate_required_text(value)

    @field_validator("domain", "description")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        return CredentialProfile.validate_optional_text(value)


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
    port_check_retries: int = 2
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
