"""SQS Lambda entry point with per-message acknowledgement and safe diagnostics."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import Counter
from collections.abc import Callable
from typing import Any

from faultline.aws.gateway import Boto3Gateway, ConflictError
from faultline.aws.store import (
    CloudCapacityError,
    CloudIntegrityError,
    DynamoStore,
    UnsupportedReprocess,
)
from faultline.normalize import normalize_record

_LOG = logging.getLogger(__name__)
_LOG.setLevel(logging.INFO)
_MAX_BODY_BYTES = 256 * 1024
_OPERATIONS = {
    "aws.iam": ("iam.amazonaws.com", {"AttachRolePolicy"}),
    "aws.sts": ("sts.amazonaws.com", {"AssumeRole"}),
    "aws.cloudtrail": ("cloudtrail.amazonaws.com", {"StopLogging", "DeleteTrail"}),
}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-standard JSON number")


def process_sqs_batch(
    event: dict[str, Any], store_factory: Callable[[], DynamoStore]
) -> dict[str, list[dict[str, str]]]:
    """Return only failed message IDs; malformed payloads are acknowledged and counted."""
    records = event.get("Records")
    if not isinstance(records, list) or len(records) > 10:
        raise ValueError("expected at most ten SQS records")
    failures: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    store: DynamoStore | None = None
    for record in records:
        if not isinstance(record, dict):
            counts["invalid"] += 1
            continue
        message_id = record.get("messageId")
        body = record.get("body")
        if not isinstance(message_id, str) or not message_id:
            counts["invalid"] += 1
            continue
        if not isinstance(body, str):
            counts["invalid"] += 1
            continue
        try:
            if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
                counts["invalid"] += 1
                continue
            value = json.loads(
                body, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant
            )
        except (ValueError, UnicodeError, RecursionError):
            counts["invalid"] += 1
            continue
        if not isinstance(value, dict) or "detail" not in value:
            counts["invalid"] += 1
            continue
        if value.get("detail-type") != "AWS API Call via CloudTrail":
            counts["ignored"] += 1
            continue
        source = value.get("source")
        if not isinstance(source, str):
            counts["invalid"] += 1
            continue
        expected = _OPERATIONS.get(source)
        if expected is None:
            counts["ignored"] += 1
            continue
        detail = value.get("detail")
        if not isinstance(detail, dict) or detail.get("eventSource") != expected[0]:
            counts["invalid"] += 1
            continue
        event_name = detail.get("eventName")
        if not isinstance(event_name, str):
            counts["invalid"] += 1
            continue
        if event_name not in expected[1]:
            counts["ignored"] += 1
            continue
        result = normalize_record(value)
        if result.status != "supported":
            counts[result.status] += 1
            continue
        try:
            if store is None:
                store = store_factory()
            outcome = store.ingest(result.event)
            outcome_name = "inserted" if outcome.inserted else "duplicate"
            counts[outcome_name] += 1
            event_ref = hashlib.sha256(result.event.identity.encode()).hexdigest()[:16]
            _LOG.info("Faultline event outcome=%s event_ref=%s", outcome_name, event_ref)
        except Exception as exc:
            # The original SQS message is retried and eventually moved to the DLQ.
            # Never log exception text: providers can place source values in it.
            if isinstance(exc, CloudCapacityError):
                category = "capacity"
            elif isinstance(exc, UnsupportedReprocess):
                category = "unsupported_reprocess"
            elif isinstance(exc, CloudIntegrityError):
                category = "integrity"
            elif isinstance(exc, ConflictError):
                category = "conflict"
            else:
                category = "infrastructure"
            reference = hashlib.sha256(message_id.encode()).hexdigest()[:12]
            _LOG.warning("Faultline ingestion failure category=%s message_ref=%s",
                         category, reference)
            failures.append({"itemIdentifier": message_id})
            counts[f"failed_{category}"] += 1
    _LOG.info("Faultline SQS batch counts: %s", dict(counts))
    return {"batchItemFailures": failures}


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    def factory() -> DynamoStore:
        import boto3

        return DynamoStore(
            Boto3Gateway(boto3.client("dynamodb")),
            os.environ["FAULTLINE_EVENT_TABLE"],
            os.environ["FAULTLINE_INCIDENT_TABLE"],
            window_minutes=int(os.environ.get("FAULTLINE_WINDOW_MINUTES", "30")),
        )

    return process_sqs_batch(event, factory)
