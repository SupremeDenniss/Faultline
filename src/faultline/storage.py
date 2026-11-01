"""SQLite persistence boundary; callers depend only on this small store API."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from faultline.models import Detection, Event


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _incident_id(event: Event, rule_id: str) -> str:
    digest = hashlib.sha256(f"{event.identity}:{rule_id}".encode()).hexdigest()[:20]
    return f"inc-{digest}"


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_key TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                region TEXT,
                event_source TEXT NOT NULL,
                event_name TEXT NOT NULL,
                actor_type TEXT,
                actor_arn TEXT,
                principal_id TEXT,
                session_issuer_arn TEXT,
                resources_json TEXT NOT NULL,
                request_json TEXT NOT NULL,
                error_code TEXT,
                source_format TEXT NOT NULL,
                envelope_id TEXT,
                ingested_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS detections (
                incident_id TEXT PRIMARY KEY,
                event_key TEXT NOT NULL REFERENCES events(event_key),
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                resource TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                UNIQUE(event_key, rule_id)
            );
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY REFERENCES detections(incident_id),
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.connection.close()

    def save(self, event: Event, detections: tuple[Detection, ...]) -> tuple[bool, int]:
        now = _utc_now()
        with self.connection:
            cursor = self.connection.execute(
                """INSERT OR IGNORE INTO events VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.identity, event.event_id, event.account_id, event.occurred_at,
                    event.region, event.event_source, event.event_name, event.actor_type,
                    event.actor_arn, event.principal_id, event.session_issuer_arn,
                    json.dumps(event.resources), json.dumps(event.request, sort_keys=True),
                    event.error_code, event.source_format, event.envelope_id, now,
                ),
            )
            if cursor.rowcount == 0:
                return False, 0
            for detection in detections:
                incident_id = _incident_id(event, detection.rule_id)
                self.connection.execute(
                    "INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        incident_id, event.identity, detection.rule_id, detection.severity,
                        detection.title, detection.explanation, detection.resource,
                        json.dumps(detection.evidence, sort_keys=True),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO incidents VALUES (?, 'open', ?, ?)",
                    (incident_id, now, now),
                )
        return True, len(detections)

    def list_incidents(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT i.incident_id, i.status, i.created_at, d.rule_id, d.severity,
                      d.title, d.resource, e.account_id, e.event_id, e.occurred_at
               FROM incidents i JOIN detections d USING (incident_id)
               JOIN events e USING (event_key)
               ORDER BY e.occurred_at, i.incident_id"""
        )
        return [dict(row) for row in rows]

    def show_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT i.*, d.event_key AS event_reference, d.rule_id, d.severity,
                      d.title, d.explanation,
                      d.resource, d.evidence_json, e.event_id, e.account_id,
                      e.occurred_at, e.region, e.event_source, e.event_name,
                      e.actor_type, e.actor_arn, e.principal_id, e.session_issuer_arn,
                      e.resources_json, e.request_json, e.error_code,
                      e.source_format, e.envelope_id
               FROM incidents i JOIN detections d USING (incident_id)
               JOIN events e USING (event_key)
               WHERE i.incident_id = ?""",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        for key in ("evidence_json", "resources_json", "request_json"):
            result[key.removesuffix("_json")] = json.loads(result.pop(key))
        return result
