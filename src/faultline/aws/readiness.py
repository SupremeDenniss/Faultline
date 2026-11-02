"""Read-only AWS deployment preflight with injectable sessions for offline tests."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_STACK = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_REQUIRED = (
    ("iam.amazonaws.com", False),
    ("sts.amazonaws.com", True),
    ("cloudtrail.amazonaws.com", False),
)
_DEPLOY_ACTIONS = (
    "cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet",
    "iam:CreateRole", "iam:PassRole", "events:PutRule", "sqs:CreateQueue",
    "lambda:CreateFunction", "dynamodb:CreateTable", "logs:CreateLogGroup",
    "s3:PutObject",
)


def _field_matches(selector: dict[str, Any], value: str) -> bool:
    if "Equals" in selector and value not in selector["Equals"]:
        return False
    if "NotEquals" in selector and value in selector["NotEquals"]:
        return False
    if "StartsWith" in selector and not any(value.startswith(v) for v in selector["StartsWith"]):
        return False
    if "NotStartsWith" in selector and any(value.startswith(v) for v in selector["NotStartsWith"]):
        return False
    if "EndsWith" in selector and not any(value.endswith(v) for v in selector["EndsWith"]):
        return False
    if "NotEndsWith" in selector and any(value.endswith(v) for v in selector["NotEndsWith"]):
        return False
    return not (set(selector) - {
        "Field", "Equals", "NotEquals", "StartsWith", "NotStartsWith",
        "EndsWith", "NotEndsWith",
    })


def selector_covers(selectors: dict[str, Any], source: str, read_only: bool) -> bool:
    """Conservatively evaluate basic or advanced trail management selectors."""
    if "AdvancedEventSelectors" in selectors:
        for group in selectors["AdvancedEventSelectors"]:
            fields = {item["Field"]: item for item in group.get("FieldSelectors", [])}
            category = fields.get("eventCategory")
            if category is None or not _field_matches(category, "Management"):
                continue
            if ("eventSource" in fields
                    and not _field_matches(fields["eventSource"], source)):
                continue
            if ("readOnly" in fields
                    and not _field_matches(fields["readOnly"], str(read_only).lower())):
                continue
            if set(fields) - {"eventCategory", "eventSource", "readOnly"}:
                continue
            return True
        return False
    for selector in selectors.get("EventSelectors", []):
        if not selector.get("IncludeManagementEvents", True):
            continue
        mode = selector.get("ReadWriteType", "All")
        if mode != "All" and mode != ("ReadOnly" if read_only else "WriteOnly"):
            continue
        if source in selector.get("ExcludeManagementEventSources", []):
            continue
        return True
    return False


def _check(name: str, passed: bool | None, detail: str) -> dict[str, str]:
    return {"name": name, "status": "pass" if passed is True else
            "fail" if passed is False else "unverified", "detail": detail}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", "AWS_ERROR"))
    return type(exc).__name__


def run_preflight(
    session: Any, *, profile: str, region: str, expected_account: str,
    stack_name: str, bucket: str,
) -> dict[str, Any]:
    """Use only AWS read APIs. Never include provider exception text in the report."""
    if not profile or not _REGION.fullmatch(region) or not _ACCOUNT.fullmatch(expected_account):
        raise ValueError("profile, Region, and twelve-digit expected account are required")
    if not _STACK.fullmatch(stack_name) or not bucket:
        raise ValueError("valid stack name and artifact bucket are required")
    checks: list[dict[str, str]] = []
    report: dict[str, Any] = {
        "kind": "read_only_preflight", "timestamp": datetime.now(UTC).isoformat(),
        "profile": profile, "region": region, "expected_account": expected_account,
        "stack_name": stack_name, "artifact_bucket": bucket, "checks": checks,
        "limitations": [
            "IAM simulation cannot prove SCP, boundary, resource policy, or deployment success"
        ],
    }
    configured = getattr(session, "region_name", None)
    checks.append(_check("profile_region", configured in (None, region),
                         "profile Region matches requested Region" if configured == region
                         else "profile has no Region; explicit Region used" if configured is None
                         else "profile Region differs from requested Region"))
    if configured not in (None, region):
        report["status"] = "fail"
        return report
    try:
        identity = session.client("sts", region_name=region).get_caller_identity()
        actual = identity["Account"]
        checks.append(_check("account", actual == expected_account,
                             "caller account matches expected account" if actual == expected_account
                             else "caller account differs from expected account"))
    except Exception as exc:
        checks.append(_check("session", False, f"STS identity check failed: {_error_code(exc)}"))
        report["status"] = "fail"
        return report
    if actual != expected_account:
        report["status"] = "fail"
        return report
    try:
        session.client("cloudformation", region_name=region).describe_stacks(
            StackName=stack_name
        )
        checks.append(_check("stack_name", False, "stack name already exists"))
    except Exception as exc:
        code = _error_code(exc)
        message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
        missing = code == "ValidationError" and "does not exist" in message.lower()
        checks.append(_check("stack_name", missing,
                             "stack name is available" if missing else
                             f"stack availability unconfirmed: {code}"))
    try:
        cloudtrail = session.client("cloudtrail", region_name=region)
        trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
        covered: set[tuple[str, bool]] = set()
        active = 0
        for trail in trails:
            arn = trail.get("TrailARN", "")
            if f":{actual}:trail/" not in arn:
                continue
            if not (trail.get("IsMultiRegionTrail") or trail.get("HomeRegion") == region):
                continue
            status = cloudtrail.get_trail_status(Name=arn)
            if not status.get("IsLogging"):
                continue
            active += 1
            selectors = cloudtrail.get_event_selectors(TrailName=arn)
            for source, read_only in _REQUIRED:
                if source in {"iam.amazonaws.com", "sts.amazonaws.com"} and not trail.get(
                    "IncludeGlobalServiceEvents"
                ):
                    continue
                if selector_covers(selectors, source, read_only):
                    covered.add((source, read_only))
        checks.append(_check("active_trail", active > 0,
                             f"{active} active relevant management-event trail(s)"))
        for source, read_only in _REQUIRED:
            checks.append(_check(f"coverage_{source.split('.')[0]}",
                                 (source, read_only) in covered,
                                 "required management-event selector covered" if
                                 (source, read_only) in covered else
                                 "required management-event selector not confirmed"))
        checks.append(_check("global_service_region", region == "us-east-1",
                             "global IAM/STS validation requires us-east-1" if
                             region != "us-east-1" else
                             "global IAM/STS events are logged in us-east-1"))
        report["limitations"].append(
            "Regional STS endpoints log in their own Region; one stack cannot prove all Regions"
        )
    except Exception as exc:
        checks.append(_check("cloudtrail", False,
                             f"CloudTrail coverage check failed: {_error_code(exc)}"))
    try:
        s3 = session.client("s3", region_name=region)
        s3.head_bucket(Bucket=bucket, ExpectedBucketOwner=actual)
        location = s3.get_bucket_location(Bucket=bucket, ExpectedBucketOwner=actual).get(
            "LocationConstraint"
        )
        bucket_region = "us-east-1" if location is None else (
            "eu-west-1" if location == "EU" else location
        )
        checks.append(_check("artifact_bucket", bucket_region == region,
                             "bucket exists in deployment Region" if bucket_region == region
                             else "bucket Region differs from deployment Region"))
    except Exception as exc:
        checks.append(_check("artifact_bucket", False,
                             f"bucket ownership or location unconfirmed: {_error_code(exc)}"))
    _permission_advice(session, region, identity.get("Arn", ""), checks)
    report["status"] = "pass" if all(c["status"] != "fail" for c in checks) else "fail"
    return report


def _permission_advice(
    session: Any, region: str, caller_arn: str, checks: list[dict[str, str]]
) -> None:
    try:
        iam = session.client("iam", region_name=region)
        principal = caller_arn
        if ":assumed-role/" in caller_arn:
            role_name = caller_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
            principal = iam.get_role(RoleName=role_name)["Role"]["Arn"]
        if ":role/" not in principal and ":user/" not in principal:
            raise ValueError("unsupported principal type")
        response = iam.simulate_principal_policy(
            PolicySourceArn=principal, ActionNames=list(_DEPLOY_ACTIONS), ResourceArns=["*"],
        )
        decisions = {item["EvalActionName"]: item["EvalDecision"] for item in
                     response.get("EvaluationResults", [])}
        allowed = all(decisions.get(action) == "allowed" for action in _DEPLOY_ACTIONS)
        checks.append(_check("permission_simulation", None,
                             "advisory IAM simulation allows sampled actions" if allowed else
                             "advisory IAM simulation did not allow every sampled action"))
    except Exception as exc:
        checks.append(_check("permission_simulation", None,
                             f"advisory permission simulation unavailable: {_error_code(exc)}"))
