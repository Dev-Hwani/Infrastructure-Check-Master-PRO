from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
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
from .services.history_store import HistoryStore
from .services.metrics import collect_local_metrics, collect_remote_metrics
from .services.port_checker import run_port_sweep
from .services.report import build_excel_report
from .services.windows_services import run_service_sweep

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config.json"
STATIC_DIR = BASE_DIR / "static"
HISTORY_DB_PATH = BASE_DIR / "data" / "history.sqlite3"

app = FastAPI(
    title="Infrastructure Check Master PRO",
    description="Async infrastructure check dashboard backend",
    version="1.1.0",
)

config_manager = ConfigManager(CONFIG_PATH)
history_store = HistoryStore(HISTORY_DB_PATH)
latest_check_lock = asyncio.Lock()
latest_check_snapshot: dict[str, Any] = {}


def _serialize_credential_profile(profile: Any) -> dict[str, Any]:
    return {
        "id": profile.id,
        "name": profile.name,
        "username": profile.username,
        "domain": profile.domain,
        "description": profile.description,
        "secret_provider": profile.secret_provider,
        "secret_ref": profile.secret_ref,
        "has_secret": bool(profile.encrypted_password or profile.secret_ref or profile.legacy_password),
    }


def _serialize_config(config: Any) -> dict[str, Any]:
    payload = config.model_dump(mode="json")
    payload["credential_profiles"] = [
        _serialize_credential_profile(profile) for profile in config.credential_profiles
    ]
    return payload


def _sse(event: str, payload: dict[str, Any]) -> str:
    data = json.dumps(payload, ensure_ascii=False)
    return f"event: {event}\ndata: {data}\n\n"


def _normalize_page(page: int, page_size: int, default_page_size: int) -> tuple[int, int, int]:
    safe_page = max(1, int(page))
    requested_size = int(page_size) if page_size > 0 else int(default_page_size)
    safe_size = max(20, min(requested_size, 1000))
    offset = (safe_page - 1) * safe_size
    return safe_page, safe_size, offset


def _filter_result_rows(
    rows: list[dict[str, Any]],
    *,
    status: str | None = None,
    transport: str | None = None,
    keyword: str | None = None,
) -> list[dict[str, Any]]:
    status_norm = status.strip().upper() if status else ""
    transport_norm = transport.strip().lower() if transport else ""
    keyword_norm = keyword.strip().lower() if keyword else ""

    filtered: list[dict[str, Any]] = []
    for row in rows:
        if status_norm and status_norm != "ALL":
            if str(row.get("status", "")).upper() != status_norm:
                continue
        if transport_norm and transport_norm != "all":
            if str(row.get("transport", "")).lower() != transport_norm:
                continue
        if keyword_norm:
            probe = row.get("probe_result") or {}
            text = " ".join(
                [
                    str(row.get("server_name", "")),
                    str(row.get("host", "")),
                    str(row.get("status", "")),
                    str(row.get("reason_code", "")),
                    str(row.get("detail", "")),
                    str(row.get("recommended_action", "")),
                    str(probe.get("probe_detail", "")),
                ]
            ).lower()
            if keyword_norm not in text:
                continue
        filtered.append(row)
    return filtered


async def _persist_history_snapshot(payload: dict[str, Any], retention_days: int) -> int:
    return await asyncio.to_thread(history_store.save_snapshot, payload, retention_days)


async def _execute_full_check(
    *,
    progress_callback: Any = None,
) -> dict[str, Any]:
    config = config_manager.get_config()

    # PRD requirement: socket connection timeout fixed to exactly 2.0s.
    timeout_seconds = 2.0
    probe_timeout = min(config.probe_timeout_seconds, timeout_seconds)

    port_task = asyncio.create_task(
        run_port_sweep(
            config.servers,
            timeout_seconds=timeout_seconds,
            probe_timeout_seconds=probe_timeout,
            default_retries=config.port_check_retries,
            max_concurrency=config.max_concurrency,
            batch_size=config.batch_size,
            retry_backoff_base_ms=config.retry_backoff_base_ms,
            retry_backoff_max_ms=config.retry_backoff_max_ms,
            flaky_threshold_percent=config.flaky_threshold_percent,
            status_priority_overrides=config.status_priority_overrides,
            retry_reason_allowlist=config.retry_reason_allowlist,
            retry_reason_denylist=config.retry_reason_denylist,
            udp_enforce_probe_on_open_or_filtered=config.udp_enforce_probe_on_open_or_filtered,
            progress_callback=progress_callback,
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
        "probe_timeout_seconds": probe_timeout,
        "port_check_retries": config.port_check_retries,
        "max_concurrency": config.max_concurrency,
        "batch_size": config.batch_size,
        "retry_backoff_base_ms": config.retry_backoff_base_ms,
        "retry_backoff_max_ms": config.retry_backoff_max_ms,
        "flaky_threshold_percent": config.flaky_threshold_percent,
        "retry_reason_allowlist": config.retry_reason_allowlist,
        "retry_reason_denylist": config.retry_reason_denylist,
        "udp_enforce_probe_on_open_or_filtered": config.udp_enforce_probe_on_open_or_filtered,
        "summary": port_checks["summary"],
        "local_metrics": local_metrics,
        "remote_metrics": remote_metrics,
        "port_checks": port_checks,
        "service_checks": service_checks,
    }

    if config.history_enabled:
        run_id = await _persist_history_snapshot(payload, config.history_retention_days)
        payload["history_run_id"] = run_id
    else:
        payload["history_run_id"] = None

    async with latest_check_lock:
        latest_check_snapshot.clear()
        latest_check_snapshot.update(payload)

    return payload


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
async def get_config() -> dict[str, Any]:
    config = config_manager.get_config()
    return _serialize_config(config)


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
    return [_serialize_credential_profile(profile) for profile in profiles]


@app.post("/api/credential-profiles", status_code=201)
async def create_credential_profile(profile: CredentialProfileCreate) -> dict[str, Any]:
    try:
        created = config_manager.add_credential_profile(profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_credential_profile(created)


@app.put("/api/credential-profiles/{profile_id}")
async def update_credential_profile(profile_id: str, profile: CredentialProfileUpdate) -> dict[str, Any]:
    try:
        updated = config_manager.update_credential_profile(profile_id, profile)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_credential_profile(updated)


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
    return await _execute_full_check()


@app.get("/api/check/stream")
async def run_check_stream(request: Request) -> StreamingResponse:
    queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()

    async def progress_callback(payload: dict[str, Any]) -> None:
        await queue.put(("progress", payload))

    async def worker() -> None:
        try:
            result = await _execute_full_check(progress_callback=progress_callback)
            await queue.put(("done", result))
        except Exception as exc:
            await queue.put(("error", {"message": str(exc)}))
        finally:
            await queue.put(("end", {"closed": True}))

    task = asyncio.create_task(worker())

    async def event_generator():
        yield _sse("start", {"started_at": datetime.now(timezone.utc).isoformat()})
        try:
            while True:
                if await request.is_disconnected():
                    task.cancel()
                    break
                try:
                    event_name, payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue

                if event_name == "end":
                    break
                yield _sse(event_name, payload)
        finally:
            if not task.done():
                task.cancel()
            with suppress(Exception):
                await task

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/check/results")
async def get_latest_check_results(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=20, le=1000),
    status: str | None = Query(default=None),
    transport: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
) -> dict[str, Any]:
    config = config_manager.get_config()
    safe_page, safe_size, offset = _normalize_page(page, page_size, config.default_page_size)

    async with latest_check_lock:
        snapshot = dict(latest_check_snapshot)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No latest result. Run /api/check first.")

    all_rows = (snapshot.get("port_checks") or {}).get("results") or []
    filtered = _filter_result_rows(
        all_rows,
        status=status,
        transport=transport,
        keyword=keyword,
    )
    items = filtered[offset : offset + safe_size]
    return {
        "checked_at": snapshot.get("checked_at"),
        "history_run_id": snapshot.get("history_run_id"),
        "total": len(filtered),
        "page": safe_page,
        "page_size": safe_size,
        "items": items,
    }


@app.get("/api/history/runs")
async def list_history_runs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    _, safe_size, offset = _normalize_page(page, page_size, default_page_size=20)
    payload = await asyncio.to_thread(history_store.list_runs, limit=safe_size, offset=offset)
    payload["page"] = page
    return payload


@app.get("/api/history/runs/{run_id}")
async def get_history_run(run_id: int) -> dict[str, Any]:
    run_data = await asyncio.to_thread(history_store.get_run, run_id)
    if run_data is None:
        raise HTTPException(status_code=404, detail=f"History run not found: {run_id}")
    return run_data


@app.get("/api/history/runs/{run_id}/results")
async def get_history_run_results(
    run_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=20, le=1000),
    status: str | None = Query(default=None),
    transport: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
) -> dict[str, Any]:
    config = config_manager.get_config()
    safe_page, safe_size, offset = _normalize_page(page, page_size, config.default_page_size)
    payload = await asyncio.to_thread(
        history_store.list_run_results,
        run_id=run_id,
        limit=safe_size,
        offset=offset,
        status=status,
        transport=transport,
        keyword=keyword,
    )
    payload["page"] = safe_page
    return payload


@app.get("/api/history/trends")
async def get_history_trends(
    days: int = Query(default=14, ge=1, le=365),
) -> dict[str, Any]:
    config = config_manager.get_config()
    return await asyncio.to_thread(
        history_store.get_run_trends,
        days=days,
        flaky_threshold_percent=config.flaky_threshold_percent,
    )


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
