from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config_manager import ConfigManager
from .models import (
    CredentialProfileCreate,
    CredentialProfileUpdate,
    ServerCreate,
    ServerUpdate,
    TemplateCreate,
    TemplateUpdate,
)
from .services.metrics import collect_local_metrics, collect_remote_metrics
from .services.port_checker import run_port_sweep
from .services.report import build_excel_report
from .services.windows_services import run_service_sweep

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config.json"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Infrastructure Check Master PRO",
    description="Async infrastructure check dashboard backend",
    version="1.0.0",
)

config_manager = ConfigManager(CONFIG_PATH)
latest_check_lock = asyncio.Lock()
latest_check_snapshot: dict[str, Any] = {}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
async def get_config() -> dict[str, Any]:
    config = config_manager.get_config()
    return config.model_dump(mode="json")


@app.post("/api/servers", status_code=201)
async def create_server(server: ServerCreate) -> dict[str, Any]:
    try:
        created = config_manager.add_server(server)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return created.model_dump(mode="json")


@app.put("/api/servers/{server_id}")
async def update_server(server_id: str, server: ServerUpdate) -> dict[str, Any]:
    try:
        updated = config_manager.update_server(server_id, server)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return updated.model_dump(mode="json")


@app.delete("/api/servers/{server_id}", status_code=204)
async def delete_server(server_id: str) -> Response:
    try:
        config_manager.delete_server(server_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@app.get("/api/templates")
async def list_templates() -> list[dict[str, Any]]:
    templates = config_manager.list_templates()
    return [template.model_dump(mode="json") for template in templates]


@app.post("/api/templates", status_code=201)
async def create_template(template: TemplateCreate) -> dict[str, Any]:
    created = config_manager.add_template(template)
    return created.model_dump(mode="json")


@app.put("/api/templates/{template_id}")
async def update_template(template_id: str, template: TemplateUpdate) -> dict[str, Any]:
    try:
        updated = config_manager.update_template(template_id, template)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return updated.model_dump(mode="json")


@app.delete("/api/templates/{template_id}", status_code=204)
async def delete_template(template_id: str) -> Response:
    try:
        config_manager.delete_template(template_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@app.get("/api/credential-profiles")
async def list_credential_profiles() -> list[dict[str, Any]]:
    profiles = config_manager.list_credential_profiles()
    return [profile.model_dump(mode="json") for profile in profiles]


@app.post("/api/credential-profiles", status_code=201)
async def create_credential_profile(profile: CredentialProfileCreate) -> dict[str, Any]:
    created = config_manager.add_credential_profile(profile)
    return created.model_dump(mode="json")


@app.put("/api/credential-profiles/{profile_id}")
async def update_credential_profile(profile_id: str, profile: CredentialProfileUpdate) -> dict[str, Any]:
    try:
        updated = config_manager.update_credential_profile(profile_id, profile)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return updated.model_dump(mode="json")


@app.delete("/api/credential-profiles/{profile_id}", status_code=204)
async def delete_credential_profile(profile_id: str) -> Response:
    try:
        config_manager.delete_credential_profile(profile_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)


@app.get("/api/resources")
async def get_resources() -> dict[str, Any]:
    config = config_manager.get_config()
    servers = config.servers
    local_task = asyncio.create_task(asyncio.to_thread(collect_local_metrics))
    remote_task = asyncio.create_task(collect_remote_metrics(servers, config.credential_profiles))
    local_metrics, remote_metrics = await asyncio.gather(local_task, remote_task)
    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "local": local_metrics,
        "remote": remote_metrics,
    }


@app.get("/api/check")
async def run_check() -> dict[str, Any]:
    config = config_manager.get_config()

    # PRD requirement: timeout is fixed at exactly 2.0 seconds.
    timeout_seconds = 2.0
    port_task = asyncio.create_task(
        run_port_sweep(
            config.servers,
            timeout_seconds=timeout_seconds,
            default_retries=config.port_check_retries,
        )
    )
    local_task = asyncio.create_task(asyncio.to_thread(collect_local_metrics))
    remote_task = asyncio.create_task(collect_remote_metrics(config.servers, config.credential_profiles))
    service_task = asyncio.create_task(run_service_sweep(config.servers, config.credential_profiles))

    port_checks, local_metrics, remote_metrics, service_checks = await asyncio.gather(
        port_task,
        local_task,
        remote_task,
        service_task,
    )

    payload = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "timeout_seconds": timeout_seconds,
        "port_check_retries": config.port_check_retries,
        "summary": port_checks["summary"],
        "local_metrics": local_metrics,
        "remote_metrics": remote_metrics,
        "port_checks": port_checks,
        "service_checks": service_checks,
    }

    async with latest_check_lock:
        latest_check_snapshot.clear()
        latest_check_snapshot.update(payload)

    return payload


@app.get("/api/report/download")
async def download_report() -> StreamingResponse:
    async with latest_check_lock:
        snapshot = dict(latest_check_snapshot)

    if not snapshot:
        raise HTTPException(
            status_code=404,
            detail="No latest result. Run /api/check first.",
        )

    workbook = build_excel_report(snapshot)
    file_name = f"infrastructure-check-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
    headers = {"Content-Disposition": f'attachment; filename="{file_name}"'}
    return StreamingResponse(
        BytesIO(workbook),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
