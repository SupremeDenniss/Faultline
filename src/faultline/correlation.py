"""Pure event-time correlation with explicit actor and resource equality."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from faultline.models import CorrelationLink, Detection, Event, IncidentGroup

IAM_SEQUENCE_ID = "FLT-CORR-IAM-001"
TRAIL_SEQUENCE_ID = "FLT-CORR-CT-001"
CORRELATION_VERSION = "1.0.0"

_ROLE_ARN = re.compile(r"^arn:aws:iam::([0-9]{12}):role/(.+)$")
_TRAIL_ARN = re.compile(r"^arn:aws:cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/([A-Za-z0-9._-]+)$")
_TRAIL_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def detection_id(event: Event, rule_id: str) -> str:
    digest = hashlib.sha256(f"{event.identity}:{rule_id}".encode()).hexdigest()[:20]
    return f"det-{digest}"


def incident_id(event: Event, rule_id: str) -> str:
    digest = hashlib.sha256(f"{event.identity}:{rule_id}".encode()).hexdigest()[:20]
    return f"inc-{digest}"


@dataclass(frozen=True, slots=True)
class DetectionContext:
    event: Event
    detection: Detection

    @property
    def id(self) -> str:
        return detection_id(self.event, self.detection.rule_id)


def _actor(event: Event) -> tuple[str, str, str, str | None, str | None] | None:
    if not event.principal_id or not event.actor_arn or not event.actor_type:
        return None
    return (
        event.actor_type, event.principal_id, event.actor_arn,
        event.actor_account_id, event.session_issuer_arn,
    )


def _role_identity(context: DetectionContext) -> str | None:
    event = context.event
    if context.detection.rule_id == "FLT-STS-001":
        arn = event.request.get("roleArn")
        match = _ROLE_ARN.fullmatch(arn or "")
        return arn if match and match.group(1) == event.account_id else None
    if context.detection.rule_id != "FLT-IAM-001":
        return None
    role_name = event.request.get("roleName")
    if not role_name:
        return None
    matches = {
        resource for resource in event.resources
        if (match := _ROLE_ARN.fullmatch(resource))
        and match.group(1) == event.account_id
        and match.group(2).rsplit("/", 1)[-1] == role_name
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _trail_identity(context: DetectionContext) -> str | None:
    event = context.event
    name = event.request.get("name")
    if name is None or event.region is None:
        return None
    if name.startswith("arn:"):
        match = _TRAIL_ARN.fullmatch(name)
        if not match or match.group(1) != event.region or match.group(2) != event.account_id:
            return None
    elif not _TRAIL_NAME.fullmatch(name):
        return None
    return name


def _key(context: DetectionContext) -> tuple[str | None, ...] | None:
    actor = _actor(context.event)
    if actor is None:
        return None
    rule_id = context.detection.rule_id
    resource = (
        _role_identity(context) if rule_id in ("FLT-IAM-001", "FLT-STS-001")
        else _trail_identity(context)
    )
    if resource is None:
        return None
    return (context.event.account_id, *actor, resource)


def correlation_scope(context: DetectionContext) -> tuple[str | None, ...] | None:
    """Stable evidence scope shared by the local and bounded cloud correlators."""
    rule_id = context.detection.rule_id
    if rule_id not in {"FLT-IAM-001", "FLT-STS-001", "FLT-CT-001", "FLT-CT-002"}:
        return None
    key = _key(context)
    if key is None:
        return None
    family = "iam" if rule_id in ("FLT-IAM-001", "FLT-STS-001") else "trail"
    return (family, *key)


def _time(event: Event) -> datetime:
    return datetime.fromisoformat(event.occurred_at.replace("Z", "+00:00"))


def correlate(
    contexts: list[DetectionContext], window: timedelta = timedelta(minutes=30)
) -> tuple[IncidentGroup, ...]:
    """Link only ordered event pairs with identical account, actor, and resource evidence.

    Sorting by event time makes the projection independent of delivery order. A later event
    links to the latest matching precursor, then groups are capped to one window in span.
    """
    if window <= timedelta(0):
        raise ValueError("correlation window must be positive")
    by_id = {context.id: context for context in contexts}
    if len(by_id) != len(contexts):
        raise ValueError("duplicate detection identity")
    starts = {"FLT-IAM-001", "FLT-CT-001"}
    ordered = sorted(
        contexts,
        key=lambda item: (_time(item.event), item.detection.rule_id not in starts, item.id),
    )
    latest: dict[tuple[str, tuple[str | None, ...]], DetectionContext] = {}
    candidates: list[CorrelationLink] = []
    for context in ordered:
        rule_id = context.detection.rule_id
        if rule_id not in {"FLT-IAM-001", "FLT-STS-001", "FLT-CT-001", "FLT-CT-002"}:
            continue
        scope = correlation_scope(context)
        if scope is None:
            continue
        family = scope[0]
        lookup = (family, scope[1:])
        if rule_id in starts:
            latest[lookup] = context
            continue
        precursor = latest.get(lookup)
        if precursor is None or _time(context.event) - _time(precursor.event) > window:
            continue
        correlation_rule = IAM_SEQUENCE_ID if family == "iam" else TRAIL_SEQUENCE_ID
        explanation = (
            "Same recipient account, caller principal and ARN, and explicit role ARN; "
            "policy attachment preceded role assumption within the configured window."
            if family == "iam" else
            "Same recipient account, caller principal and ARN, region, and exact trail name; "
            "StopLogging preceded DeleteTrail within the configured window."
        )
        candidates.append(
            CorrelationLink(
                precursor.id, context.id, correlation_rule, CORRELATION_VERSION, explanation
            )
        )

    parent = {context.id: context.id for context in contexts}
    minimum = {context.id: _time(context.event) for context in contexts}
    maximum = minimum.copy()

    def root(identifier: str) -> str:
        while parent[identifier] != identifier:
            parent[identifier] = parent[parent[identifier]]
            identifier = parent[identifier]
        return identifier

    accepted = []
    for link in candidates:
        left, right = root(link.left_detection_id), root(link.right_detection_id)
        low, high = min(minimum[left], minimum[right]), max(maximum[left], maximum[right])
        if high - low > window:
            continue
        if left != right:
            parent[right] = left
            minimum[left], maximum[left] = low, high
        accepted.append(link)

    members: dict[str, list[str]] = {}
    for context in contexts:
        members.setdefault(root(context.id), []).append(context.id)
    links_by_root: dict[str, list[CorrelationLink]] = {}
    for link in accepted:
        links_by_root.setdefault(root(link.left_detection_id), []).append(link)
    result = []
    for group_root, ids in members.items():
        ids.sort(key=lambda identifier: (
            _time(by_id[identifier].event), by_id[identifier].detection.rule_id, identifier
        ))
        anchor = by_id[ids[0]]
        group_links = tuple(links_by_root.get(group_root, ()))
        result.append(IncidentGroup(
            incident_id(anchor.event, anchor.detection.rule_id), tuple(ids), group_links
        ))
    return tuple(sorted(result, key=lambda group: group.incident_id))
