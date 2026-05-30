from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class HistoryStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS check_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checked_at TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    total_checks INTEGER NOT NULL,
                    status_counts_json TEXT NOT NULL,
                    transport_counts_json TEXT NOT NULL,
                    probe_counts_json TEXT NOT NULL,
                    consistency_counts_json TEXT NOT NULL,
                    flaky_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    checked_at TEXT NOT NULL,
                    server_id TEXT,
                    server_name TEXT,
                    host TEXT,
                    port INTEGER,
                    transport TEXT,
                    probe_type TEXT,
                    status TEXT,
                    reason_code TEXT,
                    detail TEXT,
                    recommended_action TEXT,
                    consistency TEXT,
                    consistency_score REAL,
                    latency_ms REAL,
                    total_latency_ms REAL,
                    attempt_count INTEGER,
                    retry_count INTEGER,
                    attempts_json TEXT NOT NULL,
                    probe_json TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES check_runs(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_checked_at ON check_runs(checked_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_run_id ON check_results(run_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON check_results(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_host ON check_results(host)")

    def _purge_old(self, conn: sqlite3.Connection, retention_days: int) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
        conn.execute("DELETE FROM check_runs WHERE checked_at < ?", (cutoff.isoformat(),))

    def save_snapshot(self, payload: dict[str, Any], retention_days: int = 30) -> int:
        port_checks = payload.get("port_checks") or {}
        summary = payload.get("summary") or port_checks.get("summary") or {}
        results = port_checks.get("results") or []

        checked_at = str(payload.get("checked_at") or _utc_now_iso())
        duration_ms = float(summary.get("duration_ms") or 0.0)
        total_checks = int(summary.get("total_checks") or len(results))
        status_counts = summary.get("status_counts") or {}
        transport_counts = summary.get("transport_counts") or {}
        probe_counts = summary.get("probe_status_counts") or {}
        consistency_counts = summary.get("consistency_counts") or {}
        flaky_count = int(consistency_counts.get("FLAKY") or 0)
        error_count = int(
            (status_counts.get("ERROR") or 0)
            + (status_counts.get("TIMEOUT") or 0)
            + (status_counts.get("FILTERED") or 0)
            + (status_counts.get("NO_ROUTE") or 0)
        )

        metadata = {
            "timeout_seconds": payload.get("timeout_seconds"),
            "probe_timeout_seconds": payload.get("probe_timeout_seconds"),
            "port_check_retries": payload.get("port_check_retries"),
            "max_concurrency": payload.get("max_concurrency"),
            "batch_size": payload.get("batch_size"),
            "retry_backoff_base_ms": payload.get("retry_backoff_base_ms"),
            "retry_backoff_max_ms": payload.get("retry_backoff_max_ms"),
            "flaky_threshold_percent": payload.get("flaky_threshold_percent"),
            "retry_reason_allowlist": payload.get("retry_reason_allowlist"),
            "retry_reason_denylist": payload.get("retry_reason_denylist"),
            "udp_enforce_probe_on_open_or_filtered": payload.get(
                "udp_enforce_probe_on_open_or_filtered"
            ),
        }

        with self._lock, self._connect() as conn:
            self._purge_old(conn, retention_days)
            cursor = conn.execute(
                """
                INSERT INTO check_runs (
                    checked_at, duration_ms, total_checks,
                    status_counts_json, transport_counts_json, probe_counts_json, consistency_counts_json,
                    flaky_count, error_count, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checked_at,
                    duration_ms,
                    total_checks,
                    json.dumps(status_counts, ensure_ascii=False),
                    json.dumps(transport_counts, ensure_ascii=False),
                    json.dumps(probe_counts, ensure_ascii=False),
                    json.dumps(consistency_counts, ensure_ascii=False),
                    flaky_count,
                    error_count,
                    json.dumps(metadata, ensure_ascii=False),
                    _utc_now_iso(),
                ),
            )
            run_id = int(cursor.lastrowid)

            for row in results:
                probe_result = row.get("probe_result") or {}
                conn.execute(
                    """
                    INSERT INTO check_results (
                        run_id, checked_at, server_id, server_name, host, port, transport, probe_type,
                        status, reason_code, detail, recommended_action,
                        consistency, consistency_score, latency_ms, total_latency_ms,
                        attempt_count, retry_count, attempts_json, probe_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        str(row.get("checked_at") or checked_at),
                        row.get("server_id"),
                        row.get("server_name"),
                        row.get("host"),
                        int(row.get("port") or 0),
                        row.get("transport"),
                        row.get("probe_type"),
                        row.get("status"),
                        row.get("reason_code"),
                        row.get("detail"),
                        row.get("recommended_action"),
                        row.get("consistency"),
                        float(row.get("consistency_score") or 0.0),
                        float(row.get("latency_ms") or 0.0),
                        float(row.get("total_latency_ms") or 0.0),
                        int(row.get("attempt_count") or 0),
                        int(row.get("retry_count") or 0),
                        json.dumps(row.get("attempts") or [], ensure_ascii=False),
                        json.dumps(probe_result, ensure_ascii=False),
                    ),
                )
            return run_id

    @staticmethod
    def _parse_run_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "checked_at": row["checked_at"],
            "duration_ms": float(row["duration_ms"]),
            "total_checks": int(row["total_checks"]),
            "status_counts": json.loads(row["status_counts_json"]),
            "transport_counts": json.loads(row["transport_counts_json"]),
            "probe_status_counts": json.loads(row["probe_counts_json"]),
            "consistency_counts": json.loads(row["consistency_counts_json"]),
            "flaky_count": int(row["flaky_count"]),
            "error_count": int(row["error_count"]),
            "metadata": json.loads(row["metadata_json"]),
            "created_at": row["created_at"],
        }

    def list_runs(self, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        with self._lock, self._connect() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM check_runs").fetchone()[0])
            rows = conn.execute(
                "SELECT * FROM check_runs ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [self._parse_run_row(row) for row in rows],
        }

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM check_runs WHERE id = ?",
                (int(run_id),),
            ).fetchone()
        if row is None:
            return None
        return self._parse_run_row(row)

    @staticmethod
    def _parse_result_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "run_id": int(row["run_id"]),
            "checked_at": row["checked_at"],
            "server_id": row["server_id"],
            "server_name": row["server_name"],
            "host": row["host"],
            "port": int(row["port"]),
            "transport": row["transport"],
            "probe_type": row["probe_type"],
            "status": row["status"],
            "reason_code": row["reason_code"],
            "detail": row["detail"],
            "recommended_action": row["recommended_action"],
            "consistency": row["consistency"],
            "consistency_score": float(row["consistency_score"]),
            "latency_ms": float(row["latency_ms"]),
            "total_latency_ms": float(row["total_latency_ms"]),
            "attempt_count": int(row["attempt_count"]),
            "retry_count": int(row["retry_count"]),
            "attempts": json.loads(row["attempts_json"] or "[]"),
            "probe_result": json.loads(row["probe_json"] or "{}"),
        }

    def list_run_results(
        self,
        *,
        run_id: int,
        limit: int = 200,
        offset: int = 0,
        status: str | None = None,
        transport: str | None = None,
        keyword: str | None = None,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))

        where_clauses = ["run_id = ?"]
        params: list[Any] = [int(run_id)]
        if status:
            where_clauses.append("status = ?")
            params.append(status.upper().strip())
        if transport:
            where_clauses.append("LOWER(transport) = ?")
            params.append(transport.lower().strip())
        if keyword:
            key = f"%{keyword.strip().lower()}%"
            where_clauses.append(
                "(LOWER(server_name) LIKE ? OR LOWER(host) LIKE ? OR LOWER(reason_code) LIKE ? OR LOWER(detail) LIKE ?)"
            )
            params.extend([key, key, key, key])

        where_sql = " AND ".join(where_clauses)

        with self._lock, self._connect() as conn:
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM check_results WHERE {where_sql}",
                    params,
                ).fetchone()[0]
            )
            rows = conn.execute(
                f"""
                SELECT *
                FROM check_results
                WHERE {where_sql}
                ORDER BY id ASC
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

        return {
            "run_id": int(run_id),
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [self._parse_result_row(row) for row in rows],
        }

    def get_run_trends(self, *, days: int = 14, flaky_threshold_percent: float = 100.0) -> dict[str, Any]:
        days = max(1, min(int(days), 365))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, checked_at, total_checks, flaky_count, error_count, status_counts_json
                FROM check_runs
                WHERE checked_at >= ?
                ORDER BY checked_at ASC
                """,
                (cutoff.isoformat(),),
            ).fetchall()

        daily: dict[str, dict[str, Any]] = {}
        for row in rows:
            checked_at = _to_iso_datetime(row["checked_at"])
            if checked_at is None:
                continue
            day = checked_at.date().isoformat()
            item = daily.setdefault(
                day,
                {
                    "day": day,
                    "run_count": 0,
                    "total_checks": 0,
                    "flaky_count": 0,
                    "error_count": 0,
                },
            )
            item["run_count"] += 1
            item["total_checks"] += int(row["total_checks"])
            item["flaky_count"] += int(row["flaky_count"])
            item["error_count"] += int(row["error_count"])

        trend_items = sorted(daily.values(), key=lambda item: item["day"])
        for item in trend_items:
            total = max(1, int(item["total_checks"]))
            item["flaky_ratio"] = round((item["flaky_count"] / total) * 100, 2)
            item["error_ratio"] = round((item["error_count"] / total) * 100, 2)

        alerts: list[dict[str, Any]] = []
        if trend_items:
            flaky_alert_threshold = max(5.0, 100.0 - float(flaky_threshold_percent))
            for item in trend_items:
                if item["flaky_ratio"] >= flaky_alert_threshold:
                    alerts.append(
                        {
                            "type": "FLAKY_RATIO",
                            "severity": "warning" if item["flaky_ratio"] < flaky_alert_threshold + 10 else "critical",
                            "day": item["day"],
                            "message": f"Flaky ratio {item['flaky_ratio']}% exceeded threshold {flaky_alert_threshold}%.",
                        }
                    )
            if len(trend_items) >= 2:
                previous = trend_items[-2]
                current = trend_items[-1]
                delta = round(current["flaky_ratio"] - previous["flaky_ratio"], 2)
                if delta >= 10:
                    alerts.append(
                        {
                            "type": "FLAKY_SPIKE",
                            "severity": "critical",
                            "day": current["day"],
                            "message": f"Flaky ratio spiked by {delta}% vs previous day.",
                        }
                    )

        return {
            "days": days,
            "items": trend_items,
            "alerts": alerts,
        }
