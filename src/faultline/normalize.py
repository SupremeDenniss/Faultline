"""Conservative CloudTrail normalization. No source payload is retained."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from faultline.models import Event, RecordResult

_EVENT_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_API_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,127}$")
_SOURCE = re.compile(r"^[A-Za-z0-9.-]{1,128}$")


def _clean(value: Any, limit: int = 512) -> str | None:
    if not isinstance(value, str) or not value or len(value) > limit:
        return None
    if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        return None
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_record(value: Any) -> RecordResult:
    if not isinstance(value, dict):
        return RecordResult("invalid", "record must be a JSON object")
    envelope = "detail" in value
    if envelope:
        detail = value.get("detail")
        if not isinstance(detail, dict):
            return RecordResult("invalid", "EventBridge detail must be an object")
        if value.get("detail-type") != "AWS API Call via CloudTrail":
            return RecordResult("ignored", "unrelated EventBridge detail type")
        raw = detail
    else:
        raw = value

    event_id = _clean(raw.get("eventID"), 256)
    account = _clean(raw.get("recipientAccountId"), 12)
    envelope_account = _clean(value.get("account"), 12) if envelope else None
    if account and envelope_account and account != envelope_account:
        return RecordResult("invalid", "CloudTrail and envelope account disagree")
    account = account or envelope_account
    occurred_at = _timestamp(raw.get("eventTime"))
    source = _clean(raw.get("eventSource"), 128)
    name = _clean(raw.get("eventName"), 128)
    if event_id is None or not _EVENT_ID.fullmatch(event_id):
        return RecordResult("invalid", "missing or malformed eventID")
    if account is None or not _ACCOUNT.fullmatch(account):
        return RecordResult("invalid", "missing or malformed recipient account")
    if occurred_at is None:
        return RecordResult("invalid", "missing or malformed eventTime (UTC offset required)")
    if source is None or not _SOURCE.fullmatch(source):
        return RecordResult("invalid", "missing or malformed eventSource")
    if name is None or not _API_NAME.fullmatch(name):
        return RecordResult("invalid", "missing or malformed eventName")

    request_raw = raw.get("requestParameters")
    if request_raw is not None and not isinstance(request_raw, dict):
        return RecordResult("invalid", "requestParameters must be an object or null")
    error_raw = raw.get("errorCode")
    if error_raw is not None and _clean(error_raw, 128) is None:
        return RecordResult("invalid", "errorCode must be a nonempty string or null")
    identity_raw = raw.get("userIdentity")
    if identity_raw is not None and not isinstance(identity_raw, dict):
        return RecordResult("invalid", "userIdentity must be an object or null")
    resources_raw = raw.get("resources")
    if resources_raw is not None and not isinstance(resources_raw, list):
        return RecordResult("invalid", "resources must be an array or null")

    identity = _object(identity_raw)
    session_issuer = _object(_object(identity.get("sessionContext")).get("sessionIssuer"))
    request = _object(request_raw)
    selected_request = {
        key: cleaned
        for key in ("roleName", "policyArn", "name")
        if (cleaned := _clean(request.get(key), 512)) is not None
    }
    resources = []
    for resource in (resources_raw or [])[:100]:
        item = _object(resource)
        cleaned = _clean(item.get("ARN")) or _clean(item.get("resourceName"))
        if cleaned:
            resources.append(cleaned)
    region = _clean(raw.get("awsRegion"), 128)
    envelope_region = _clean(value.get("region"), 128) if envelope else None
    if region and envelope_region and region != envelope_region:
        return RecordResult("invalid", "CloudTrail and envelope region disagree")
    event = Event(
        event_id=event_id,
        occurred_at=occurred_at,
        account_id=account,
        region=region or envelope_region,
        event_source=source,
        event_name=name,
        actor_type=_clean(identity.get("type"), 128),
        actor_arn=_clean(identity.get("arn")),
        principal_id=_clean(identity.get("principalId")),
        session_issuer_arn=_clean(session_issuer.get("arn")),
        resources=tuple(resources),
        request=selected_request,
        error_code=_clean(error_raw, 128),
        source_format="eventbridge" if envelope else "cloudtrail",
        envelope_id=_clean(value.get("id"), 256) if envelope else None,
    )
    return RecordResult("supported", "CloudTrail event normalized", event)
