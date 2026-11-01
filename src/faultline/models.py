"""Small immutable contracts shared by normalization, rules, and storage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    occurred_at: str
    account_id: str
    region: str | None
    event_source: str
    event_name: str
    actor_type: str | None
    actor_arn: str | None
    principal_id: str | None
    session_issuer_arn: str | None
    actor_account_id: str | None
    resources: tuple[str, ...]
    request: dict[str, str]
    error_code: str | None
    source_format: str
    envelope_id: str | None

    @property
    def identity(self) -> str:
        return f"{self.account_id}:{self.event_id}"


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    rule_version: str
    severity: str
    title: str
    explanation: str
    resource: str
    event_reference: str
    evidence: dict[str, str]


@dataclass(frozen=True, slots=True)
class CorrelationLink:
    left_detection_id: str
    right_detection_id: str
    rule_id: str
    rule_version: str
    explanation: str


@dataclass(frozen=True, slots=True)
class IncidentGroup:
    incident_id: str
    detection_ids: tuple[str, ...]
    links: tuple[CorrelationLink, ...]


@dataclass(frozen=True, slots=True)
class RecordResult:
    status: Literal["supported", "ignored", "invalid"]
    diagnostic: str
    event: Event | None = None


@dataclass(frozen=True, slots=True)
class InputRecord:
    label: str
    value: Any
    error: str | None = None
