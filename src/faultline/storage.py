"""Transactional SQLite adapter and explicit Phase 1 schema migration."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from faultline.correlation import DetectionContext, correlate, detection_id
from faultline.models import Detection, Event
from faultline.rules import RULES, Rule

SCHEMA_VERSION = 2

_SCHEMA = (
    """CREATE TABLE events (
        event_key TEXT PRIMARY KEY, event_id TEXT NOT NULL, account_id TEXT NOT NULL,
        occurred_at TEXT NOT NULL, region TEXT, event_source TEXT NOT NULL,
        event_name TEXT NOT NULL, actor_type TEXT, actor_arn TEXT, principal_id TEXT,
        session_issuer_arn TEXT, resources_json TEXT NOT NULL, request_json TEXT NOT NULL,
        error_code TEXT, source_format TEXT NOT NULL, envelope_id TEXT,
        ingested_at TEXT NOT NULL, actor_account_id TEXT)""",
    """CREATE TABLE detections (
        detection_id TEXT PRIMARY KEY, event_key TEXT NOT NULL REFERENCES events(event_key),
        rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, severity TEXT NOT NULL,
        title TEXT NOT NULL, explanation TEXT NOT NULL, resource TEXT NOT NULL,
        evidence_json TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0, 1)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(event_key, rule_id))""",
    """CREATE TABLE incidents (
        incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, assessment TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        is_current INTEGER NOT NULL CHECK(is_current IN (0, 1)))""",
    """CREATE TABLE incident_detections (
        detection_id TEXT PRIMARY KEY REFERENCES detections(detection_id),
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id))""",
    """CREATE TABLE incident_links (
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        left_detection_id TEXT NOT NULL REFERENCES detections(detection_id),
        right_detection_id TEXT NOT NULL REFERENCES detections(detection_id),
        rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, explanation TEXT NOT NULL,
        PRIMARY KEY (incident_id, left_detection_id, right_detection_id, rule_id))""",
    """CREATE TABLE incident_history (
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        changed_at TEXT NOT NULL, action TEXT NOT NULL, details_json TEXT NOT NULL)""",
    """CREATE TABLE rule_evaluations (
        event_key TEXT NOT NULL REFERENCES events(event_key),
        rule_id TEXT NOT NULL, rule_version TEXT NOT NULL,
        matched INTEGER NOT NULL CHECK(matched IN (0, 1)),
        evaluated_at TEXT NOT NULL,
        PRIMARY KEY (event_key, rule_id, rule_version))""",
    """CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    "CREATE INDEX detections_active ON detections(active, event_key)",
    "CREATE INDEX events_time ON events(occurred_at, event_key)",
)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _event_from_row(row: sqlite3.Row) -> Event:
    return Event(
        event_id=row["event_id"], occurred_at=row["occurred_at"],
        account_id=row["account_id"], region=row["region"],
        event_source=row["event_source"], event_name=row["event_name"],
        actor_type=row["actor_type"], actor_arn=row["actor_arn"],
        principal_id=row["principal_id"], session_issuer_arn=row["session_issuer_arn"],
        actor_account_id=row["actor_account_id"],
        resources=tuple(json.loads(row["resources_json"])),
        request=json.loads(row["request_json"]), error_code=row["error_code"],
        source_format=row["source_format"], envelope_id=row["envelope_id"],
    )


def _detection_from_row(row: sqlite3.Row, event: Event) -> Detection:
    return Detection(
        rule_id=row["rule_id"], rule_version=row["rule_version"],
        severity=row["severity"], title=row["title"], explanation=row["explanation"],
        resource=row["resource"], event_reference=event.identity,
        evidence=json.loads(row["evidence_json"]),
    )


class SQLiteStore:
    """Local store contract: ingest, reprocess, list/show, and update assessment."""

    def __init__(self, path: Path, window_minutes: int | None = None) -> None:
        if window_minutes is not None and not 1 <= window_minutes <= 1440:
            raise ValueError("correlation window must be 1 to 1440 minutes")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA foreign_keys = ON")
        try:
            self._prepare_schema(window_minutes)
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("SQLite integrity check failed")
            if self.connection.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("database has invalid foreign keys")
            if self.connection.execute(
                """SELECT 1 FROM incidents i LEFT JOIN incident_detections m
                   USING (incident_id) WHERE i.is_current=1 AND m.detection_id IS NULL LIMIT 1"""
            ).fetchone():
                raise ValueError("current incident has no detection membership")
            configured = self.connection.execute(
                "SELECT value FROM settings WHERE key='window_minutes'"
            ).fetchone()
            if configured is None:
                raise ValueError("database is missing correlation window setting")
            stored_minutes = int(configured["value"])
            if window_minutes is not None and window_minutes != stored_minutes:
                raise ValueError(
                    f"database correlation window is {stored_minutes} minutes; "
                    "changing it requires a new database"
                )
        except Exception:
            self.connection.close()
            raise
        self.window = timedelta(minutes=stored_minutes)

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.connection.close()

    def _prepare_schema(self, requested_window: int | None) -> None:
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version != 0:
            raise ValueError(f"unsupported database schema version {version}")
        tables = {
            row["name"] for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not tables:
            with self.connection:
                for statement in _SCHEMA:
                    self.connection.execute(statement)
                self.connection.execute(
                    "INSERT INTO settings VALUES ('window_minutes', ?)",
                    (str(requested_window or 30),),
                )
                self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            return
        if tables != {"events", "detections", "incidents"}:
            raise ValueError("unrecognized schema; database left unchanged")
        self._migrate_phase1(requested_window or 30)

    def _migrate_phase1(self, window_minutes: int) -> None:
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(detections)")
        }
        if "incident_id" not in columns or "detection_id" in columns:
            raise ValueError("unrecognized Phase 1 schema; database left unchanged")
        self.connection.execute("PRAGMA foreign_keys = OFF")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            for name in ("events", "detections", "incidents"):
                self.connection.execute(f"ALTER TABLE {name} RENAME TO legacy_{name}")
            for statement in _SCHEMA:
                self.connection.execute(statement)
            self.connection.execute(
                """INSERT INTO events SELECT event_key, event_id, account_id, occurred_at,
                   region, event_source, event_name, actor_type, actor_arn, principal_id,
                   session_issuer_arn, resources_json, request_json, error_code,
                   source_format, envelope_id, ingested_at, NULL FROM legacy_events"""
            )
            legacy = self.connection.execute(
                """SELECT d.*, i.status, i.created_at, i.updated_at
                   FROM legacy_detections d JOIN legacy_incidents i USING (incident_id)"""
            ).fetchall()
            detection_count = self.connection.execute(
                "SELECT COUNT(*) FROM legacy_detections"
            ).fetchone()[0]
            incident_count = self.connection.execute(
                "SELECT COUNT(*) FROM legacy_incidents"
            ).fetchone()[0]
            if len(legacy) != detection_count or len(legacy) != incident_count:
                raise ValueError("inconsistent Phase 1 detection/incident relationships")
            for row in legacy:
                identity = row["event_key"]
                digest_id = detection_id(
                    _event_from_row(self.connection.execute(
                        "SELECT * FROM events WHERE event_key=?", (identity,)
                    ).fetchone()), row["rule_id"]
                )
                self.connection.execute(
                    """INSERT INTO detections VALUES (?, ?, ?, '1.0.0', ?, ?, ?, ?, ?, 1, ?, ?)""",
                    (digest_id, identity, row["rule_id"], row["severity"], row["title"],
                     row["explanation"], row["resource"], row["evidence_json"],
                     row["created_at"], row["updated_at"]),
                )
                self.connection.execute(
                    "INSERT INTO incidents VALUES (?, ?, NULL, ?, ?, 1)",
                    (row["incident_id"], row["status"], row["created_at"], row["updated_at"]),
                )
                self.connection.execute(
                    "INSERT INTO incident_detections VALUES (?, ?)",
                    (digest_id, row["incident_id"]),
                )
                self.connection.execute(
                    "INSERT INTO rule_evaluations VALUES (?, ?, '1.0.0', 1, ?)",
                    (identity, row["rule_id"], row["created_at"]),
                )
                self._history(row["incident_id"], _now(), "migrated_from_phase1",
                              {"detection_id": digest_id})
            self.connection.execute("INSERT INTO settings VALUES ('window_minutes', ?)",
                                    (str(window_minutes),))
            for name in ("incidents", "detections", "events"):
                self.connection.execute(f"DROP TABLE legacy_{name}")
            if self.connection.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("migration produced invalid foreign keys")
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            self.connection.execute("PRAGMA foreign_keys = ON")

    def _history(self, incident_id: str, at: str, action: str, details: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO incident_history (incident_id, changed_at, action, details_json) "
            "VALUES (?, ?, ?, ?)",
            (incident_id, at, action, json.dumps(details, sort_keys=True)),
        )

    def _insert_event(self, event: Event, now: str) -> bool:
        cursor = self.connection.execute(
            """INSERT OR IGNORE INTO events VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event.identity, event.event_id, event.account_id, event.occurred_at,
             event.region, event.event_source, event.event_name, event.actor_type,
             event.actor_arn, event.principal_id, event.session_issuer_arn,
             json.dumps(event.resources), json.dumps(event.request, sort_keys=True),
             event.error_code, event.source_format, event.envelope_id, now,
             event.actor_account_id),
        )
        return cursor.rowcount == 1

    def _record_evaluation(
        self, event: Event, rule_id: str, version: str,
        detection: Detection | None, now: str
    ) -> bool:
        existing = self.connection.execute(
            "SELECT 1 FROM rule_evaluations WHERE event_key=? AND rule_id=? AND rule_version=?",
            (event.identity, rule_id, version),
        ).fetchone()
        if existing:
            return False
        self.connection.execute(
            "INSERT INTO rule_evaluations VALUES (?, ?, ?, ?, ?)",
            (event.identity, rule_id, version, int(detection is not None), now),
        )
        if detection is None:
            self.connection.execute(
                "UPDATE detections SET active=0, updated_at=? WHERE event_key=? AND rule_id=? "
                "AND active=1",
                (now, event.identity, rule_id),
            )
            return False
        identifier = detection_id(event, rule_id)
        self.connection.execute(
            """INSERT INTO detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
               ON CONFLICT(event_key, rule_id) DO UPDATE SET
               rule_version=excluded.rule_version, severity=excluded.severity,
               title=excluded.title, explanation=excluded.explanation,
               resource=excluded.resource, evidence_json=excluded.evidence_json,
               active=1, updated_at=excluded.updated_at""",
            (identifier, event.identity, rule_id, version, detection.severity,
             detection.title, detection.explanation, detection.resource,
             json.dumps(detection.evidence, sort_keys=True), now, now),
        )
        return True

    def ingest_batch(
        self, events: list[Event], rules: tuple[Rule, ...] = RULES
    ) -> list[tuple[bool, int]]:
        now = _now()
        outcomes = []
        with self.connection:
            for event in events:
                if not self._insert_event(event, now):
                    outcomes.append((False, 0))
                    continue
                matches = 0
                for rule in rules:
                    matches += int(self._record_evaluation(
                        event, rule.rule_id, rule.version, rule.match(event), now
                    ))
                outcomes.append((True, matches))
            self._reconcile(now)
        return outcomes

    def save(self, event: Event, detections: tuple[Detection, ...]) -> tuple[bool, int]:
        """Phase 1 compatible single-event save, using supplied pure-rule results."""
        now = _now()
        with self.connection:
            if not self._insert_event(event, now):
                return False, 0
            for detection in detections:
                self._record_evaluation(
                    event, detection.rule_id, detection.rule_version, detection, now
                )
            self._reconcile(now)
        return True, len(detections)

    def reprocess(self, rules: tuple[Rule, ...] = RULES) -> dict[str, int]:
        """Evaluate previously stored events for rule versions not yet evaluated."""
        now = _now()
        evaluated = matched = 0
        affected: set[str] = set()
        with self.connection:
            for row in self.connection.execute(
                "SELECT * FROM events ORDER BY occurred_at, event_key"
            ):
                event = _event_from_row(row)
                for rule in rules:
                    if self.connection.execute(
                        "SELECT 1 FROM rule_evaluations WHERE event_key=? AND rule_id=? "
                        "AND rule_version=?",
                        (event.identity, rule.rule_id, rule.version),
                    ).fetchone():
                        continue
                    evaluated += 1
                    prior = self.connection.execute(
                        "SELECT 1 FROM detections WHERE event_key=? AND rule_id=? AND active=1",
                        (event.identity, rule.rule_id),
                    ).fetchone()
                    finding = rule.match(event)
                    matched += int(self._record_evaluation(
                        event, rule.rule_id, rule.version, finding, now
                    ))
                    if prior or finding:
                        affected.add(detection_id(event, rule.rule_id))
            changed = self._reconcile(now)
            affected_incidents: dict[str, list[str]] = {}
            for identifier in affected:
                row = self.connection.execute(
                    "SELECT m.incident_id FROM incident_detections m "
                    "JOIN incidents i USING (incident_id) "
                    "WHERE m.detection_id=? AND i.is_current=1", (identifier,)
                ).fetchone()
                if row:
                    affected_incidents.setdefault(row["incident_id"], []).append(identifier)
            for incident_id, identifiers in sorted(affected_incidents.items()):
                self.connection.execute(
                    "UPDATE incidents SET updated_at=? WHERE incident_id=?", (now, incident_id)
                )
                self._history(incident_id, now, "rule_reprocessed",
                              {"detection_ids": sorted(identifiers)})
            changed = max(changed, len(affected_incidents))
        return {"evaluations": evaluated, "matches": matched, "incidents_changed": changed}

    def _reconcile(self, now: str) -> int:
        rows = self.connection.execute(
            """SELECT d.*, e.event_id, e.account_id, e.occurred_at, e.region,
                      e.event_source, e.event_name, e.actor_type, e.actor_arn,
                      e.principal_id, e.session_issuer_arn, e.actor_account_id,
                      e.resources_json, e.request_json, e.error_code,
                      e.source_format, e.envelope_id
               FROM detections d JOIN events e USING (event_key)
               WHERE d.active=1 ORDER BY e.occurred_at, d.detection_id"""
        ).fetchall()
        contexts = [DetectionContext(_event_from_row(row), _detection_from_row(
            row, _event_from_row(row))) for row in rows]
        groups = correlate(contexts, self.window)
        old_meta = {
            row["incident_id"]: dict(row)
            for row in self.connection.execute("SELECT * FROM incidents WHERE is_current=1")
        }
        old_members: dict[str, set[str]] = {key: set() for key in old_meta}
        for row in self.connection.execute("SELECT * FROM incident_detections"):
            if row["incident_id"] in old_members:
                old_members[row["incident_id"]].add(row["detection_id"])
        old_links: dict[str, set[tuple[str, str, str, str]]] = {
            key: set() for key in old_meta
        }
        for row in self.connection.execute("SELECT * FROM incident_links"):
            if row["incident_id"] in old_links:
                old_links[row["incident_id"]].add((
                    row["left_detection_id"], row["right_detection_id"],
                    row["rule_id"], row["rule_version"],
                ))
        desired = {group.incident_id: group for group in groups}
        unchanged = len(desired) == len(old_meta) and all(
            group.incident_id in old_meta
            and set(group.detection_ids) == old_members[group.incident_id]
            and {(link.left_detection_id, link.right_detection_id,
                  link.rule_id, link.rule_version) for link in group.links}
            == old_links[group.incident_id]
            for group in groups
        )
        if unchanged:
            return 0
        self.connection.execute("DELETE FROM incident_links")
        self.connection.execute("DELETE FROM incident_detections")
        self.connection.execute("UPDATE incidents SET is_current=0 WHERE is_current=1")
        changed = 0
        for group in groups:
            identifier = group.incident_id
            member_set = set(group.detection_ids)
            overlap = sorted(
                (meta for key, meta in old_meta.items() if old_members[key] & member_set),
                key=lambda meta: (meta["created_at"], meta["incident_id"]),
            )
            prior = old_meta.get(identifier)
            archived = self.connection.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (identifier,)
            ).fetchone()
            source = prior or (overlap[0] if overlap else archived)
            status = source["status"] if source else "open"
            assessment = source["assessment"] if source else None
            created_at = source["created_at"] if source else now
            link_set = {(link.left_detection_id, link.right_detection_id,
                         link.rule_id, link.rule_version) for link in group.links}
            changed_group = (
                prior is None or old_members[identifier] != member_set
                or old_links[identifier] != link_set
            )
            updated_at = now if changed_group else prior["updated_at"]
            self.connection.execute(
                """INSERT INTO incidents VALUES (?, ?, ?, ?, ?, 1)
                   ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status,
                   assessment=excluded.assessment, created_at=excluded.created_at,
                   updated_at=excluded.updated_at, is_current=1""",
                (identifier, status, assessment, created_at, updated_at),
            )
            for detection in group.detection_ids:
                self.connection.execute(
                    "INSERT INTO incident_detections VALUES (?, ?)", (detection, identifier)
                )
            for link in group.links:
                self.connection.execute(
                    "INSERT INTO incident_links VALUES (?, ?, ?, ?, ?, ?)",
                    (identifier, link.left_detection_id, link.right_detection_id,
                     link.rule_id, link.rule_version, link.explanation),
                )
            if changed_group:
                action = (
                    "membership_changed" if overlap else
                    "reactivated" if archived else "created"
                )
                self._history(identifier, now, action,
                              {"detection_ids": list(group.detection_ids),
                               "correlation_rule_ids": sorted({
                                   link.rule_id for link in group.links
                               }),
                               "replaced_incident_ids": [meta["incident_id"] for meta in overlap
                                                         if meta["incident_id"] != identifier]})
                changed += 1
        for identifier in old_meta.keys() - desired.keys():
            self._history(identifier, now, "superseded",
                          {"replacement_incident_ids": sorted(
                              group.incident_id for group in groups
                              if old_members[identifier] & set(group.detection_ids)
                          )})
        return changed

    def update_incident(
        self, incident_id: str, *, status: str | None = None,
        assessment: str | None = None
    ) -> bool:
        if status is not None and status not in {"open", "investigating", "closed"}:
            raise ValueError("status must be open, investigating, or closed")
        if assessment is not None and (
            not assessment or len(assessment) > 1000
            or not assessment.isprintable()
        ):
            raise ValueError("assessment must be 1-1000 printable characters")
        with self.connection:
            row = self.connection.execute(
                "SELECT * FROM incidents WHERE incident_id=? AND is_current=1", (incident_id,)
            ).fetchone()
            if row is None:
                return False
            new_status = status if status is not None else row["status"]
            new_assessment = assessment if assessment is not None else row["assessment"]
            if new_status == row["status"] and new_assessment == row["assessment"]:
                return True
            now = _now()
            self.connection.execute(
                "UPDATE incidents SET status=?, assessment=?, updated_at=? WHERE incident_id=?",
                (new_status, new_assessment, now, incident_id),
            )
            action = (
                "assessment_updated" if new_assessment != row["assessment"]
                else "status_updated"
            )
            self._history(incident_id, now, action,
                          {"previous_status": row["status"], "status": new_status,
                           "previous_assessment": row["assessment"],
                           "assessment": new_assessment})
        return True

    def list_incidents(self) -> list[dict[str, Any]]:
        identifiers = self.connection.execute(
            "SELECT incident_id FROM incidents WHERE is_current=1 ORDER BY incident_id"
        ).fetchall()
        return [self._report(row["incident_id"], include_detail=False) for row in identifiers]

    def show_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT 1 FROM incidents WHERE incident_id=? AND is_current=1", (incident_id,)
        ).fetchone()
        return self._report(incident_id, include_detail=True) if row else None

    def incident_history(self, incident_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            return None
        entries = [
            {"changed_at": item["changed_at"], "action": item["action"],
             "details": json.loads(item["details_json"])}
            for item in self.connection.execute(
                "SELECT changed_at, action, details_json FROM incident_history "
                "WHERE incident_id=? ORDER BY history_id", (incident_id,)
            )
        ]
        return {
            "incident_id": incident_id, "is_current": bool(row["is_current"]),
            "status": row["status"], "assessment": row["assessment"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "history": entries,
        }

    def _report(self, incident_id: str, *, include_detail: bool) -> dict[str, Any]:
        incident = self.connection.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        rows = self.connection.execute(
            """SELECT d.*, e.event_id, e.account_id, e.occurred_at, e.region,
                      e.event_source, e.event_name, e.actor_type, e.actor_arn,
                      e.principal_id, e.session_issuer_arn, e.actor_account_id,
                      e.resources_json, e.request_json, e.error_code,
                      e.source_format, e.envelope_id
               FROM incident_detections m JOIN detections d USING (detection_id)
               JOIN events e USING (event_key) WHERE m.incident_id=?
               ORDER BY e.occurred_at, e.event_key, d.rule_id""",
            (incident_id,),
        ).fetchall()
        links = [dict(row) for row in self.connection.execute(
            "SELECT left_detection_id, right_detection_id, rule_id, rule_version, explanation "
            "FROM incident_links WHERE incident_id=? "
            "ORDER BY left_detection_id, right_detection_id, rule_id", (incident_id,)
        )]
        severity = "high" if any(row["severity"] == "high" for row in rows) else "medium"
        correlation_ids = sorted({link["rule_id"] for link in links})
        if "FLT-CORR-IAM-001" in correlation_ids:
            title = "AdministratorAccess attachment followed by AssumeRole API activity"
            resource = next(row["resource"] for row in rows if row["rule_id"] == "FLT-STS-001")
        elif "FLT-CORR-CT-001" in correlation_ids:
            title = "CloudTrail StopLogging followed by DeleteTrail API activity"
            resource = next(row["resource"] for row in rows if row["rule_id"] == "FLT-CT-001")
        else:
            title, resource = rows[0]["title"], rows[0]["resource"]
        summary = {
            "incident_id": incident_id, "status": incident["status"],
            "assessment": incident["assessment"], "severity": severity,
            "title": title, "account_id": rows[0]["account_id"], "resource": resource,
            "first_seen": rows[0]["occurred_at"], "last_seen": rows[-1]["occurred_at"],
            "created_at": incident["created_at"], "updated_at": incident["updated_at"],
            "detection_count": len(rows),
            "event_count": len({row["event_key"] for row in rows}),
            "rule_ids": sorted({row["rule_id"] for row in rows}),
            "correlation_rule_ids": correlation_ids,
        }
        if not include_detail:
            return summary
        timeline = []
        seen_events = set()
        detections = []
        for row in rows:
            event = _event_from_row(row)
            if event.identity not in seen_events:
                seen_events.add(event.identity)
                timeline.append({
                    "event_reference": event.identity, "occurred_at": event.occurred_at,
                    "account_id": event.account_id, "region": event.region,
                    "event_source": event.event_source, "event_name": event.event_name,
                    "actor": {"type": event.actor_type, "arn": event.actor_arn,
                              "principal_id": event.principal_id,
                              "account_id": event.actor_account_id,
                              "session_issuer_arn": event.session_issuer_arn},
                    "resources": list(event.resources), "request": event.request,
                    "error_code": event.error_code, "source_format": event.source_format,
                    "envelope_id": event.envelope_id,
                })
            detections.append({
                "detection_id": row["detection_id"], "event_reference": event.identity,
                "rule_id": row["rule_id"], "rule_version": row["rule_version"],
                "severity": row["severity"], "title": row["title"],
                "description": row["explanation"], "resource": row["resource"],
                "evidence": json.loads(row["evidence_json"]),
            })
        unknowns = [
            "Authorization and intent are not established by these API events.",
            "Resulting AWS configuration state has not been verified.",
        ]
        if any(not item["actor"]["principal_id"] or not item["actor"]["arn"]
               for item in timeline):
            unknowns.append("At least one caller identity is incomplete.")
        if "FLT-IAM-001" in summary["rule_ids"] and not correlation_ids:
            unknowns.append(
                "Role ARN or matching identity evidence may be unavailable for linkage."
            )
        steps = [
            "Confirm the change against approved maintenance or access requests.",
            "Review adjacent CloudTrail activity and independently verify current AWS state.",
        ]
        if "FLT-CORR-IAM-001" in correlation_ids:
            steps.append(
                "Review the role trust policy and the assumed session's subsequent actions."
            )
        if "FLT-CORR-CT-001" in correlation_ids:
            steps.append(
                "Check trail status, retained log delivery, and other trails in the account."
            )
        history = [
            {"changed_at": row["changed_at"], "action": row["action"],
             "details": json.loads(row["details_json"])}
            for row in self.connection.execute(
                "SELECT changed_at, action, details_json FROM incident_history "
                "WHERE incident_id=? ORDER BY history_id", (incident_id,)
            )
        ]
        return {
            **summary,
            "observed_timeline": timeline,
            "detections": detections,
            "evidence": detections[0]["evidence"],
            "correlation_conclusions": links,
            "unknowns": unknowns,
            "unverified_possibilities": [
                "The same sequence can occur during legitimate administration."
            ],
            "investigation_steps": steps,
            "history": history,
        }
