from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ServerTarget(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
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


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
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


class ServerUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(min_length=1)
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


class AppConfig(BaseModel):
    timeout_seconds: float = 2.0
    servers: list[ServerTarget] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, value: float) -> float:
        if round(float(value), 1) != 2.0:
            raise ValueError("timeout_seconds must be exactly 2.0")
        return 2.0


PortStatus = Literal["OPEN", "REFUSED", "TIMEOUT", "UNKNOWN_HOST", "ERROR"]
