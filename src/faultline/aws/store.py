"""Bounded DynamoDB persistence for the Phase 2 event and correlation contracts.

This adapter intentionally reconciles one evidence scope at a time. It never scans a
table or rewrites every incident. Ordinary retries resume after partial preparation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from faultline.aws.gateway import ConflictError, Gateway, Put
from faultline.correlation import (
    DetectionContext,
    correlate,
    correlation_scope,
    detection_id,
)
from faultline.models import Detection, Event, IncidentGroup
from faultline.rules import RULES, Rule

MAX_CONTEXTS = 16
MAX_CONTEXT_BYTES = 16 * 1024
MAX_RETRIES = 6
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class CloudCapacityError(RuntimeError):
    """An evidence scope exceeded the deliberately bounded cloud workflow."""


class UnsupportedReprocess(RuntimeError):
    """A rule change needs offline/manual rebuild rather than in-place cloud removal."""


class CloudIntegrityError(RuntimeError):
    """Persisted relationships are incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class IngestOutcome:
    inserted: bool
    detection_ids: tuple[str, ...]
    incident_ids: tuple[str, ...]


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _event_data(event: Event) -> dict[str, Any]:
    data = asdict(event)
    data["resources"] = list(event.resources)
    return data


def _event_from(data: dict[str, Any]) -> Event:
    return Event(**{**data, "resources": tuple(data["resources"])})


def _context(item: dict[str, Any]) -> DetectionContext:
    return DetectionContext(_event_from(item["event"]), Detection(**item["detection"]))


def _micros(value: str) -> int:
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    delta = instant - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _index_sk(event: Event, identifier: str) -> str:
    return f"DET#{_micros(event.occurred_at):020d}#{identifier}"


def _scope_pk(context: DetectionContext) -> str:
    identity = correlation_scope(context)
    if identity is None:
        return f"SOLO#{context.id}"
    encoded = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return "SCOPE#" + hashlib.sha256(encoded.encode()).hexdigest()


def _version(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise ValueError(f"invalid rule version {value!r}") from exc


class DynamoStore:
    """Cloud store: strongly consistent scope queries plus conditional transactions."""

    def __init__(
        self, gateway: Gateway, event_table: str, incident_table: str,
        *, window_minutes: int = 30
    ) -> None:
        if not 1 <= window_minutes <= 1440:
            raise ValueError("correlation window must be 1 to 1440 minutes")
        self.gateway = gateway
        self.event_table = event_table
        self.incident_table = incident_table
        self.window = timedelta(minutes=window_minutes)

    def ingest(self, incoming: Event, rules: tuple[Rule, ...] = RULES) -> IngestOutcome:
        event_pk = f"EVENT#{incoming.identity}"
        new_event = {"pk": event_pk, "sk": "META", "event": _event_data(incoming)}
        self._check_size(new_event)
        inserted = self.gateway.put_if_absent(self.event_table, new_event)
        stored = new_event if inserted else self.gateway.get(self.event_table, event_pk, "META")
        if stored is None:
            raise CloudIntegrityError("deduplicated event could not be read")
        event = _event_from(stored["event"])
        detection_ids = []
        incident_ids = []
        for rule in rules:
            finding = rule.match(event)
            identifier = detection_id(event, rule.rule_id)
            existing = self.gateway.get(self.event_table, f"DETECTION#{identifier}", "META")
            if existing and finding is None and _version(rule.version) > _version(
                existing["detection"]["rule_version"]
            ):
                raise UnsupportedReprocess(
                    "cloud reprocessing cannot deactivate a prior detection"
                )
            evaluation = {
                "pk": event_pk, "sk": f"EVAL#{rule.rule_id}#{rule.version}",
                "rule_id": rule.rule_id, "rule_version": rule.version,
                "matched": finding is not None, "evaluated_at": _now(),
            }
            self.gateway.put_if_absent(self.event_table, evaluation)
            if finding is None:
                continue
            context = DetectionContext(event, finding)
            scope_pk, index_sk = self._persist_detection(context, existing)
            detection_ids.append(identifier)
            incident_ids.extend(self._reconcile(scope_pk, index_sk, event.occurred_at))
        return IngestOutcome(inserted, tuple(detection_ids), tuple(sorted(set(incident_ids))))

    def reprocess_event(
        self, account_id: str, event_id: str, rules: tuple[Rule, ...] = RULES
    ) -> IngestOutcome:
        """Re-evaluate one stored event; no table scan or automatic bulk replay."""
        stored = self.gateway.get(self.event_table, f"EVENT#{account_id}:{event_id}", "META")
        if stored is None:
            raise KeyError("stored event not found")
        return self.ingest(_event_from(stored["event"]), rules)

    @staticmethod
    def _check_size(value: dict[str, Any]) -> None:
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_CONTEXT_BYTES:
            raise CloudCapacityError("normalized cloud record exceeds 16 KiB")

    def _persist_detection(
        self, context: DetectionContext, existing: dict[str, Any] | None
    ) -> tuple[str, str]:
        identifier = context.id
        scope_pk = _scope_pk(context)
        index_sk = _index_sk(context.event, identifier)
        base = {"event": _event_data(context.event), "detection": asdict(context.detection)}
        self._check_size(base)
        meta = {
            "pk": f"DETECTION#{identifier}", "sk": "META", **base,
            "scope_pk": scope_pk, "scope_sk": index_sk, "revision": 0,
        }
        index = {
            "pk": scope_pk, "sk": index_sk, **base,
            "detection_id": identifier, "incident_id": None, "revision": 0,
        }
        if existing is None:
            self.gateway.put_if_absent(self.event_table, meta)
            existing = self.gateway.get(self.event_table, meta["pk"], "META")
        if existing is None:
            raise CloudIntegrityError("detection metadata could not be read")
        if existing["scope_pk"] != scope_pk or existing["scope_sk"] != index_sk:
            raise UnsupportedReprocess("cloud reprocessing cannot move a detection scope")
        self.gateway.put_if_absent(self.event_table, index)
        old_version = existing["detection"]["rule_version"]
        new_version = context.detection.rule_version
        if _version(new_version) < _version(old_version):
            raise UnsupportedReprocess("cloud rule version downgrade is unsupported")
        if new_version == old_version:
            return scope_pk, index_sk
        for _attempt in range(MAX_RETRIES):
            current_meta = self.gateway.get(self.event_table, meta["pk"], "META")
            current_index = self.gateway.get(self.event_table, scope_pk, index_sk)
            if current_meta is None or current_index is None:
                raise CloudIntegrityError("detection version update found a missing item")
            if _version(current_meta["detection"]["rule_version"]) >= _version(new_version):
                return scope_pk, index_sk
            new_meta = {**current_meta, **base, "revision": int(current_meta["revision"]) + 1}
            new_index = {**current_index, **base,
                         "revision": int(current_index["revision"]) + 1}
            try:
                self.gateway.transact([
                    Put(self.event_table, new_meta, int(current_meta["revision"])),
                    Put(self.event_table, new_index, int(current_index["revision"])),
                ])
                return scope_pk, index_sk
            except ConflictError:
                continue
        raise ConflictError("detection version update exceeded retry limit")

    def _collect(self, scope_pk: str, index_sk: str, occurred_at: str) -> dict[str, dict]:
        offset = int(self.window.total_seconds() * 1_000_000)
        items: dict[str, dict] = {}
        pending_times = [occurred_at]
        visited_times: set[str] = set()
        visited_incidents = set()
        while pending_times:
            timestamp = pending_times.pop()
            if timestamp in visited_times:
                continue
            visited_times.add(timestamp)
            center = _micros(timestamp)
            lower = f"DET#{max(0, center - offset):020d}#"
            upper = f"DET#{center + offset:020d}#~"
            neighbors = self.gateway.query_range(
                self.event_table, scope_pk, lower, upper, MAX_CONTEXTS + 1
            )
            if len(neighbors) > MAX_CONTEXTS:
                raise CloudCapacityError("correlation scope exceeds 16 nearby detections")
            for item in neighbors:
                if item["detection_id"] not in items:
                    items[item["detection_id"]] = item
                    pending_times.append(item["event"]["occurred_at"])
            if len(items) > MAX_CONTEXTS:
                raise CloudCapacityError("correlation closure exceeds 16 detections")
            pending = {
                item["incident_id"] for item in items.values()
                if item.get("incident_id") and item["incident_id"] not in visited_incidents
            }
            for incident_id in sorted(pending):
                visited_incidents.add(incident_id)
                incident = self.get_incident(incident_id)
                if incident is None:
                    raise CloudIntegrityError("scope references a missing incident")
                for member in incident["members"]:
                    if member in items:
                        continue
                    meta = self.gateway.get(self.event_table, f"DETECTION#{member}", "META")
                    if meta is None or meta["scope_pk"] != scope_pk:
                        raise CloudIntegrityError("incident member has no matching scope")
                    indexed = self.gateway.get(self.event_table, scope_pk, meta["scope_sk"])
                    if indexed is None:
                        raise CloudIntegrityError("incident member has no scope index")
                    items[member] = indexed
                    pending_times.append(indexed["event"]["occurred_at"])
                    if len(items) > MAX_CONTEXTS:
                        raise CloudCapacityError("incident closure exceeds 16 detections")
        if not any(item["sk"] == index_sk for item in items.values()):
            raise CloudIntegrityError("current detection missing from scope query")
        return items

    def _reconcile(self, scope_pk: str, index_sk: str, occurred_at: str) -> list[str]:
        for _attempt in range(MAX_RETRIES):
            items = self._collect(scope_pk, index_sk, occurred_at)
            contexts = [_context(item) for item in items.values()]
            groups = correlate(contexts, self.window)
            desired = {group.incident_id: group for group in groups}
            assignment = {
                identifier: group.incident_id for group in groups
                for identifier in group.detection_ids
            }
            old_ids = {item["incident_id"] for item in items.values() if item.get("incident_id")}
            prior = {
                identifier: self.get_incident(identifier)
                for identifier in old_ids | desired.keys()
            }
            changed = any(
                item.get("incident_id") != assignment[identifier]
                for identifier, item in items.items()
            ) or any(
                self._group_changed(group, prior[group.incident_id], items)
                for group in groups
            ) or any(
                prior[identifier] and prior[identifier].get("is_current")
                for identifier in old_ids - desired.keys()
            )
            if not changed:
                return sorted(desired)
            lock = self.gateway.get(self.event_table, scope_pk, "LOCK")
            lock_revision = int(lock["revision"]) if lock else 0
            now = _now()
            actions = [Put(
                self.event_table,
                {"pk": scope_pk, "sk": "LOCK", "revision": lock_revision + 1},
                lock_revision if lock else None,
            )]
            for identifier, item in sorted(items.items()):
                actions.append(Put(
                    self.event_table,
                    {**item, "incident_id": assignment[identifier],
                     "revision": int(item["revision"]) + 1},
                    int(item["revision"]),
                ))
            for group in groups:
                incident_id = group.incident_id
                existing = prior[incident_id]
                overlaps = sorted(
                    (prior[old] for old in old_ids if prior[old]
                     and prior[old].get("is_current")
                     and set(prior[old]["members"]) & set(group.detection_ids)),
                    key=lambda value: (value["created_at"], value["pk"]),
                )
                source = (existing if existing and existing.get("is_current") else
                          overlaps[0] if overlaps else existing)
                projection = self._projection(group, items, source, now)
                revision = int(existing["revision"]) if existing else 0
                projection["revision"] = revision + 1
                actions.append(Put(
                    self.incident_table, projection, revision if existing else None
                ))
                if self._group_changed(group, existing, items):
                    action = "membership_changed" if overlaps else (
                        "reactivated" if existing else "created"
                    )
                    actions.append(self._history_put(
                        incident_id, scope_pk, lock_revision + 1, now, action,
                        {"detection_ids": list(group.detection_ids),
                         "correlation_rule_ids": sorted({link.rule_id for link in group.links}),
                         "replaced_incident_ids": sorted(
                             old["pk"].removeprefix("INCIDENT#") for old in overlaps
                             if old["pk"] != f"INCIDENT#{incident_id}"
                         )},
                    ))
            for identifier in sorted(old_ids - desired.keys()):
                old = prior[identifier]
                if old is None or not old.get("is_current"):
                    continue
                actions.append(Put(
                    self.incident_table,
                    {**old, "is_current": False, "updated_at": now,
                     "revision": int(old["revision"]) + 1},
                    int(old["revision"]),
                ))
                actions.append(self._history_put(
                    identifier, scope_pk, lock_revision + 1, now, "superseded",
                    {"replacement_incident_ids": sorted(
                        group.incident_id for group in groups
                        if set(old["members"]) & set(group.detection_ids)
                    )},
                ))
            if len(actions) > 100:
                raise CloudCapacityError("correlation transaction exceeds 100 actions")
            try:
                self.gateway.transact(actions)
                return sorted(desired)
            except ConflictError:
                continue
        raise ConflictError("scope reconciliation exceeded retry limit")

    @staticmethod
    def _group_changed(
        group: IncidentGroup, existing: dict[str, Any] | None,
        items: dict[str, dict]
    ) -> bool:
        if existing is None or not existing.get("is_current"):
            return True
        links = [asdict(link) for link in group.links]
        versions = {identifier: items[identifier]["detection"]["rule_version"]
                    for identifier in group.detection_ids}
        return (
            existing["members"] != list(group.detection_ids)
            or existing["links"] != links
            or existing["detection_versions"] != versions
        )

    @staticmethod
    def _projection(
        group: IncidentGroup, items: dict[str, dict],
        source: dict[str, Any] | None, now: str
    ) -> dict[str, Any]:
        ordered = [_context(items[identifier]) for identifier in group.detection_ids]
        rules = {context.detection.rule_id for context in ordered}
        if "FLT-IAM-001" in rules and "FLT-STS-001" in rules:
            title = "AdministratorAccess attachment followed by AssumeRole API activity"
            resource = next(context.detection.resource for context in ordered
                            if context.detection.rule_id == "FLT-STS-001")
        elif "FLT-CT-001" in rules and "FLT-CT-002" in rules:
            title = "CloudTrail StopLogging followed by DeleteTrail API activity"
            resource = next(context.detection.resource for context in ordered
                            if context.detection.rule_id == "FLT-CT-001")
        else:
            title, resource = ordered[0].detection.title, ordered[0].detection.resource
        incident_id = group.incident_id
        return {
            "pk": f"INCIDENT#{incident_id}", "sk": "META", "incident_id": incident_id,
            "account_id": ordered[0].event.account_id,
            "gsi1pk": f"ACCOUNT#{ordered[0].event.account_id}",
            "gsi1sk": f"TIME#{ordered[0].event.occurred_at}#{incident_id}",
            "members": list(group.detection_ids),
            "links": [asdict(link) for link in group.links],
            "detection_versions": {
                identifier: items[identifier]["detection"]["rule_version"]
                for identifier in group.detection_ids
            },
            "status": source["status"] if source else "open",
            "assessment": source.get("assessment") if source else None,
            "created_at": source["created_at"] if source else now,
            "updated_at": now,
            "is_current": True,
            "first_seen": ordered[0].event.occurred_at,
            "last_seen": ordered[-1].event.occurred_at,
            "title": title, "resource": resource,
            "severity": "high" if any(
                context.detection.severity == "high" for context in ordered
            ) else "medium",
        }

    def _history_put(
        self, incident_id: str, scope_pk: str, revision: int,
        now: str, action: str, details: dict[str, Any]
    ) -> Put:
        return Put(self.incident_table, {
            "pk": f"INCIDENT#{incident_id}",
            "sk": f"HIST#{scope_pk}#{revision:012d}",
            "changed_at": now, "action": action, "details": details,
        })

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self.gateway.get(self.incident_table, f"INCIDENT#{incident_id}", "META")

    def list_account_incidents(self, account_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Bounded, eventually consistent discovery with current-state rechecks."""
        if not (len(account_id) == 12 and account_id.isascii() and account_id.isdigit()):
            raise ValueError("account ID must be twelve digits")
        if not 1 <= limit <= 100:
            raise ValueError("incident limit must be 1-100")
        candidates = self.gateway.query_account(self.incident_table, account_id, limit)
        current = [self.get_incident(item["incident_id"]) for item in candidates]
        return [item for item in current if item and item["is_current"]]

    def get_history(self, incident_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("history limit must be 1-100")
        return self.gateway.query_range(
            self.incident_table, f"INCIDENT#{incident_id}", "HIST#", "HIST#~", limit
        )

    def update_incident(
        self, incident_id: str, *, status: str | None = None,
        assessment: str | None = None
    ) -> bool:
        if status is not None and status not in {"open", "investigating", "closed"}:
            raise ValueError("invalid incident status")
        if assessment is not None and (
            not assessment or len(assessment) > 1000 or not assessment.isprintable()
        ):
            raise ValueError("invalid incident assessment")
        for _attempt in range(MAX_RETRIES):
            current = self.get_incident(incident_id)
            if current is None or not current["is_current"]:
                return False
            new_status = status or current["status"]
            new_assessment = assessment if assessment is not None else current.get("assessment")
            if new_status == current["status"] and new_assessment == current.get("assessment"):
                return True
            revision = int(current["revision"])
            now = _now()
            updated = {
                **current, "status": new_status, "assessment": new_assessment,
                "revision": revision + 1, "updated_at": now,
            }
            history = Put(self.incident_table, {
                "pk": f"INCIDENT#{incident_id}",
                "sk": f"HIST#ASSESSMENT#{revision + 1:012d}",
                "changed_at": now, "action": "assessment_updated",
                "details": {"previous_status": current["status"], "status": new_status,
                            "previous_assessment": current.get("assessment"),
                            "assessment": new_assessment},
            })
            try:
                self.gateway.transact([
                    Put(self.incident_table, updated, revision), history
                ])
                return True
            except ConflictError:
                continue
        raise ConflictError("incident update exceeded retry limit")
