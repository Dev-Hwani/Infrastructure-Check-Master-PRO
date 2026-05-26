from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


TransportProtocol = Literal["tcp", "udp"]
ProbeType = Literal["none", "auto", "http", "https", "rdp", "dns", "ntp"]


class PortTarget(BaseModel):
    port: int = Field(ge=1, le=65535)
    transport: TransportProtocol = "tcp"
    probe: ProbeType = "auto"
    retries: int | None = Field(default=None, ge=0, le=5)


class ServerTarget(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(default_factory=list)
    port_targets: list[PortTarget] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    enable_remote_metrics: bool = True

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

    @model_validator(mode="after")
    def ensure_port_targets_exist(self) -> "ServerUpdate":
        if not self.ports and not self.port_targets:
            raise ValueError("At least one port or port_target is required.")
        return self


class AppConfig(BaseModel):
    timeout_seconds: float = 2.0
    port_check_retries: int = 2
    servers: list[ServerTarget] = Field(default_factory=list)
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
