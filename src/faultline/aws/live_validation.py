"""Post-deployment inspection and controlled direct-SQS validation primitives."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any

from faultline.correlation import detection_id, incident_id
from faultline.normalize import normalize_record

RULE_OUTPUTS = {"IamRuleArn": "ENABLED", "StsRuleArn":
                "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS",
                "CloudTrailRuleArn": "ENABLED"}
RULE_PATTERNS = {
    "IamRuleArn": ("aws.iam", "iam.amazonaws.com", {"AttachRolePolicy"}),
    "StsRuleArn": ("aws.sts", "sts.amazonaws.com", {"AssumeRole"}),
    "CloudTrailRuleArn": (
        "aws.cloudtrail", "cloudtrail.amazonaws.com", {"StopLogging", "DeleteTrail"}
    ),
}
REQUIRED_OUTPUTS = (
    "IngestQueueUrl", "IngestQueueArn", "DeadLetterQueueUrl", "DeadLetterQueueArn",
    "EventTableName", "IncidentTableName", "LambdaArn", *RULE_OUTPUTS,
)


def _check(checks: list[dict[str, str]], name: str, okay: bool | None, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if okay is True else
                   "fail" if okay is False else "unverified", "detail": detail})


def _client(session: Any, name: str, region: str) -> Any:
    return session.client(name, region_name=region)


def _identity(session: Any, region: str, expected_account: str) -> str:
    if getattr(session, "region_name", None) not in (None, region):
        raise ValueError("profile Region differs from requested Region")
    actual = _client(session, "sts", region).get_caller_identity()["Account"]
    if actual != expected_account:
        raise ValueError("AWS account differs from explicit expected account")
    return actual


def inspect_stack(
    session: Any, *, region: str, expected_account: str, stack_name: str,
) -> dict[str, Any]:
    """Read-only checks; exceptions are reported by category without provider messages."""
    checks: list[dict[str, str]] = []
    report: dict[str, Any] = {
        "kind": "deployed_stack_inspection", "timestamp": datetime.now(UTC).isoformat(),
        "account": expected_account, "region": region, "stack": stack_name,
        "checks": checks, "unverified": [], "metrics": {},
    }
    try:
        _identity(session, region, expected_account)
    except Exception as exc:
        _check(checks, "identity", False, type(exc).__name__)
        report["status"] = "fail"
        return report
    _check(checks, "identity", True, "expected account and Region confirmed")
    try:
        stack = _client(session, "cloudformation", region).describe_stacks(
            StackName=stack_name
        )["Stacks"][0]
        outputs = {entry["OutputKey"]: entry["OutputValue"] for entry in
                   stack.get("Outputs", [])}
        status = stack["StackStatus"]
        _check(checks, "stack", status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, status)
        termination_protection = stack.get("EnableTerminationProtection")
        _check(checks, "termination_protection", termination_protection is False if
               termination_protection is not None else None,
               "stack termination protection disabled" if termination_protection is False
               else "stack termination protection enabled or unknown")
        _check(checks, "outputs", all(key in outputs for key in REQUIRED_OUTPUTS),
               "required stack outputs present" if all(key in outputs for key in
                                                      REQUIRED_OUTPUTS) else
               "required stack outputs missing")
        if any(key not in outputs for key in REQUIRED_OUTPUTS):
            report["status"] = "fail"
            return report
    except Exception as exc:
        _check(checks, "stack", False, f"inspection failed: {type(exc).__name__}")
        report["status"] = "fail"
        return report
    try:
        events = _client(session, "events", region)
        for key, expected_state in RULE_OUTPUTS.items():
            name = outputs[key].rsplit("/", 1)[-1]
            rule = events.describe_rule(Name=name, EventBusName="default")
            targets = events.list_targets_by_rule(Rule=name, EventBusName="default")
            pattern = json.loads(rule.get("EventPattern", "{}"))
            source, event_source, operations = RULE_PATTERNS[key]
            pattern_ok = (
                pattern.get("source") == [source]
                and pattern.get("detail-type") == ["AWS API Call via CloudTrail"]
                and pattern.get("detail", {}).get("eventSource") == [event_source]
                and set(pattern.get("detail", {}).get("eventName", [])) == operations
            )
            okay = rule.get("State") == expected_state and pattern_ok and any(
                target.get("Arn") == outputs["IngestQueueArn"] for target in
                targets.get("Targets", [])
            )
            _check(checks, key, okay, "state, pattern, and queue target match" if okay else
                   "rule state, pattern, or queue target differs")
    except Exception as exc:
        _check(checks, "eventbridge", False, f"inspection failed: {type(exc).__name__}")
    try:
        sqs = _client(session, "sqs", region)
        queue = sqs.get_queue_attributes(QueueUrl=outputs["IngestQueueUrl"],
                                         AttributeNames=["All"])["Attributes"]
        dlq = sqs.get_queue_attributes(QueueUrl=outputs["DeadLetterQueueUrl"],
                                       AttributeNames=["All"])["Attributes"]
        redrive = json.loads(queue.get("RedrivePolicy", "{}"))
        queue_ok = (int(queue.get("VisibilityTimeout", 0)) >= 180
                    and redrive.get("deadLetterTargetArn") == outputs["DeadLetterQueueArn"]
                    and int(redrive.get("maxReceiveCount", 0)) >= 5
                    and queue.get("SqsManagedSseEnabled") == "true"
                    and dlq.get("SqsManagedSseEnabled") == "true")
        _check(checks, "queues", queue_ok, "visibility, redrive, and SSE match" if
               queue_ok else "queue configuration differs")
        policy = json.loads(queue.get("Policy", "{}"))
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        policy_ok = any(
            entry.get("Principal") == {"Service": "events.amazonaws.com"}
            and entry.get("Action") == "sqs:SendMessage"
            and entry.get("Resource") == outputs["IngestQueueArn"]
            and entry.get("Condition", {}).get("StringEquals", {}).get(
                "aws:SourceAccount"
            ) == expected_account
            and set(entry.get("Condition", {}).get("ArnEquals", {}).get(
                "aws:SourceArn", []
            )) == {outputs[key] for key in RULE_OUTPUTS}
            for entry in statements
        )
        _check(checks, "queue_policy", policy_ok,
               "EventBridge sender restricted to stack rules and account" if policy_ok else
               "queue resource policy differs")
        report["dlq_messages_observed"] = int(dlq.get("ApproximateNumberOfMessages", 0))
    except Exception as exc:
        _check(checks, "queues", False, f"inspection failed: {type(exc).__name__}")
    try:
        lam = _client(session, "lambda", region)
        function = lam.get_function_configuration(FunctionName=outputs["LambdaArn"])
        mappings = lam.list_event_source_mappings(FunctionName=outputs["LambdaArn"])
        mapping_ok = any(
            item.get("EventSourceArn") == outputs["IngestQueueArn"]
            and item.get("State") == "Enabled"
            and "ReportBatchItemFailures" in item.get("FunctionResponseTypes", [])
            for item in mappings.get("EventSourceMappings", [])
        )
        function_ok = (function.get("Runtime") == "python3.12"
                       and function.get("Handler") == "faultline.aws.handler.lambda_handler"
                       and function.get("Architectures", ["x86_64"]) == ["x86_64"])
        _check(checks, "lambda", function_ok and mapping_ok,
               "runtime, handler, architecture, and SQS mapping match" if
               function_ok and mapping_ok else "Lambda or mapping configuration differs")
        role_arn = function["Role"]
    except Exception as exc:
        _check(checks, "lambda", False, f"inspection failed: {type(exc).__name__}")
        role_arn = None
    try:
        if role_arn is None:
            raise ValueError("Lambda execution role unavailable")
        role_name = role_arn.rsplit("/", 1)[-1]
        iam = _client(session, "iam", region)
        role = iam.get_role(RoleName=role_name)["Role"]
        policy_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        attached = iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        )
        policy = iam.get_role_policy(RoleName=role_name, PolicyName="FaultlineIngest")[
            "PolicyDocument"
        ]
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        expected_tables = {f"arn:aws:dynamodb:{region}:{expected_account}:table/"
                           f"{outputs[key]}" for key in ("EventTableName", "IncidentTableName")}
        resource_values = {value for statement in statements for value in
                           (statement.get("Resource", []) if isinstance(
                               statement.get("Resource", []), list
                           ) else [statement.get("Resource")])}
        actions = {action for statement in statements for action in
                   (statement.get("Action", []) if isinstance(
                       statement.get("Action", []), list
                   ) else [statement.get("Action")])}
        iam_ok = (role["Arn"] == role_arn and policy_names == ["FaultlineIngest"]
                  and not attached
                  and "*" not in actions and expected_tables.issubset(resource_values)
                  and outputs["IngestQueueArn"] in resource_values)
        _check(checks, "lambda_role", iam_ok, "inline policy inspected" if iam_ok else
               "execution role or policy differs")
        report["unverified"].append(
            "Role inspection does not establish effective permissions under SCPs or boundaries"
        )
    except Exception as exc:
        _check(checks, "lambda_role", None,
               f"role inspection unavailable: {type(exc).__name__}")
    try:
        dynamodb = _client(session, "dynamodb", region)
        for output in ("EventTableName", "IncidentTableName"):
            table = dynamodb.describe_table(TableName=outputs[output])["Table"]
            indexes = table.get("GlobalSecondaryIndexes", [])
            okay = table.get("TableStatus") == "ACTIVE"
            if output == "IncidentTableName":
                okay = okay and any(index["IndexName"] == "AccountTime"
                                     and index["IndexStatus"] == "ACTIVE" for index in indexes)
            _check(checks, output, okay, "table and required index active" if okay else
                   "table or index not active")
            protection = table.get("DeletionProtectionEnabled")
            _check(checks, f"cleanup_{output}", protection is False if
                   protection is not None else None,
                   "DynamoDB deletion protection disabled" if protection is False else
                   "DynamoDB deletion protection enabled or unknown")
    except Exception as exc:
        _check(checks, "dynamodb", False, f"inspection failed: {type(exc).__name__}")
    try:
        logs = _client(session, "logs", region)
        groups = logs.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{stack_name}-ingest")
        okay = any(group["logGroupName"] == f"/aws/lambda/{stack_name}-ingest"
                   and group.get("retentionInDays") == 7 for group in groups.get("logGroups", []))
        _check(checks, "log_retention", okay, "seven-day log group present" if okay else
               "log group or retention differs")
        cloudwatch = _client(session, "cloudwatch", region)
        end = datetime.now(UTC)
        for metric in ("Invocations", "Errors", "Throttles"):
            points = cloudwatch.get_metric_statistics(
                Namespace="AWS/Lambda", MetricName=metric,
                Dimensions=[{"Name": "FunctionName", "Value": f"{stack_name}-ingest"}],
                StartTime=end - timedelta(hours=1), EndTime=end, Period=300,
                Statistics=["Sum"],
            ).get("Datapoints", [])
            report["metrics"][metric] = sum(point["Sum"] for point in points) if points else None
        report["unverified"].append("CloudWatch metrics may be delayed or absent")
    except Exception as exc:
        _check(checks, "metrics", None, f"metrics unavailable: {type(exc).__name__}")
    report["status"] = "pass" if all(item["status"] != "fail" for item in checks) else "fail"
    report["resources"] = {"queue": outputs["IngestQueueUrl"],
                           "event_table": outputs["EventTableName"],
                           "incident_table": outputs["IncidentTableName"],
                           "lambda": outputs["LambdaArn"],
                           "dlq": outputs["DeadLetterQueueUrl"]}
    report["cleanup_readiness"] = (
        "Review evidence export and S3 object versions before stack deletion"
    )
    return report


def synthetic_envelopes(test_id: str, account: str, region: str) -> list[dict[str, Any]]:
    """Generate four sanitized, stable events; no fixture response credentials survive."""
    if not test_id or len(test_id) > 40 or not all(c.isalnum() or c in "-_" for c in test_id):
        raise ValueError("test ID must be 1-40 letters, digits, hyphens, or underscores")
    now = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    records: list[dict[str, Any]] = []
    for filename in ("demo-iam.jsonl", "demo-trail.jsonl"):
        raw_lines = resources.files("faultline.fixtures").joinpath(filename).read_text(
            encoding="utf-8"
        ).splitlines()[:2]
        for source_line in raw_lines:
            source = json.loads(source_line)
            detail = source.get("detail", source)
            original_account = detail["recipientAccountId"]
            index = len(records)
            event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"faultline:{test_id}:{index}"))

            def replace_account(value: str, source_account: str = original_account) -> str:
                return value.replace(source_account, account)

            identity = detail["userIdentity"]
            selected_identity = {key: replace_account(identity[key]) for key in
                                 ("type", "principalId", "arn", "accountId")
                                 if key in identity}
            request = detail.get("requestParameters") or {}
            selected_request = {key: replace_account(request[key]) for key in
                                ("roleName", "policyArn", "roleArn", "name")
                                if isinstance(request.get(key), str)}
            event_time = now + timedelta(minutes=5 if index % 2 else 0)
            clean_detail = {
                "eventVersion": "1.09", "eventID": event_id,
                "eventTime": event_time.isoformat().replace("+00:00", "Z"),
                "eventSource": detail["eventSource"], "eventName": detail["eventName"],
                "awsRegion": region, "recipientAccountId": account,
                "userIdentity": selected_identity, "requestParameters": selected_request,
                "resources": [{"ARN": replace_account(item["ARN"])} for item in
                              detail.get("resources", []) if "ARN" in item],
            }
            service = clean_detail["eventSource"].split(".", 1)[0]
            records.append({
                "version": "0", "id": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                      f"faultline-envelope:{test_id}:{index}")),
                "detail-type": "AWS API Call via CloudTrail", "source": f"aws.{service}",
                "account": account, "region": region, "time": clean_detail["eventTime"],
                "detail": clean_detail,
            })
    return records


def _ddb_item(client: Any, table: str, pk: str, sk: str = "META") -> dict[str, Any] | None:
    from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

    serializer, deserializer = TypeSerializer(), TypeDeserializer()
    response = client.get_item(
        TableName=table, Key={"pk": serializer.serialize(pk), "sk": serializer.serialize(sk)},
        ConsistentRead=True,
    )
    item = response.get("Item")
    return {key: deserializer.deserialize(value) for key, value in item.items()} if item else None


def _history_count(client: Any, table: str, incident: str) -> int:
    from boto3.dynamodb.types import TypeSerializer

    serializer = TypeSerializer()
    params: dict[str, Any] = {
        "TableName": table, "KeyConditionExpression": "#pk = :pk AND #sk BETWEEN :a AND :b",
        "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
        "ExpressionAttributeValues": {
            ":pk": serializer.serialize(f"INCIDENT#{incident}"),
            ":a": serializer.serialize("HIST#"), ":b": serializer.serialize("HIST#~"),
        },
        "ConsistentRead": True, "Select": "COUNT",
    }
    total = 0
    while True:
        page = client.query(**params)
        total += page["Count"]
        if not page.get("LastEvaluatedKey"):
            return total
        params["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _log_events(client: Any, group: str, start: int, pattern: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    token = None
    for _ in range(100):
        params: dict[str, Any] = {
            "logGroupName": group, "startTime": start, "filterPattern": pattern,
        }
        if token:
            params["nextToken"] = token
        page = client.filter_log_events(**params)
        entries.extend(page.get("events", []))
        next_token = page.get("nextToken")
        if not next_token or next_token == token:
            return entries
        token = next_token
    raise RuntimeError("CloudWatch log pagination exceeded 100 pages")


def smoke_test(
    session: Any, *, region: str, expected_account: str, stack_name: str,
    confirmed_account: str, test_id: str, send: bool, poll_seconds: int = 120,
) -> dict[str, Any]:
    """Mutation is gated by both explicit --send and matching account confirmation."""
    if not send or confirmed_account != expected_account:
        raise ValueError("--send and matching --confirm-account are required")
    report = inspect_stack(session, region=region, expected_account=expected_account,
                           stack_name=stack_name)
    report["kind"] = "direct_sqs_smoke"
    report["test_id"] = test_id
    report["test_events_submitted"] = 0
    report["duplicate_messages_submitted"] = 0
    report["events_persisted"] = 0
    report["detections_persisted"] = 0
    report["incidents_persisted"] = 0
    report["duplicate_suppression"] = "unverified"
    report["processing_failures_observed"] = None
    report["delivery_boundary"] = "direct SQS to Lambda to DynamoDB only"
    if report["status"] != "pass":
        return report
    envelopes = synthetic_envelopes(test_id, expected_account, region)
    resources_out = report["resources"]
    sqs = _client(session, "sqs", region)
    dynamodb = _client(session, "dynamodb", region)
    normalized = [normalize_record(item).event for item in envelopes]
    if any(_ddb_item(dynamodb, resources_out["event_table"], f"EVENT#{item.identity}")
           for item in normalized):
        _check(report["checks"], "test_id", False,
               "test ID already exists; choose a fresh identifier")
        report["status"] = "fail"
        return report
    for envelope in envelopes:
        try:
            sqs.send_message(QueueUrl=resources_out["queue"], MessageBody=json.dumps(envelope))
            report["test_events_submitted"] += 1
        except Exception as exc:
            _check(report["checks"], "send", False,
                   f"synthetic submission failed: {type(exc).__name__}")
            report["status"] = "fail"
            return report
    expected_rules = ("FLT-IAM-001", "FLT-STS-001", "FLT-CT-001", "FLT-CT-002")
    expected_incidents = [incident_id(normalized[i], expected_rules[i]) for i in (0, 2)]
    deadline = time.monotonic() + poll_seconds
    while time.monotonic() < deadline:
        try:
            events = sum(bool(_ddb_item(dynamodb, resources_out["event_table"],
                                        f"EVENT#{item.identity}")) for item in normalized)
            detections = sum(bool(_ddb_item(dynamodb, resources_out["event_table"],
                                            f"DETECTION#{detection_id(item, rule)}"))
                             for item, rule in zip(normalized, expected_rules, strict=True))
            incidents = [_ddb_item(dynamodb, resources_out["incident_table"],
                                   f"INCIDENT#{identifier}") for identifier in expected_incidents]
        except Exception as exc:
            _check(report["checks"], "persistence", False,
                   f"DynamoDB inspection failed: {type(exc).__name__}")
            report["status"] = "fail"
            return report
        valid_incidents = sum(bool(item and item.get("is_current") and
                                   len(item.get("members", [])) == 2 and
                                   len(item.get("links", [])) == 1) for item in incidents)
        report.update(events_persisted=events, detections_persisted=detections,
                      incidents_persisted=valid_incidents)
        if events == 4 and detections == 4 and valid_incidents == 2:
            break
        time.sleep(3)
    if report["incidents_persisted"] != 2:
        report["status"] = "fail"
        report["checks"].append({"name": "persistence", "status": "fail",
                                 "detail": "expected persisted records not observed"})
        return report
    history_before = [_history_count(dynamodb, resources_out["incident_table"], item)
                      for item in expected_incidents]
    log_start = int(datetime.now(UTC).timestamp() * 1000)
    for envelope in envelopes:
        try:
            sqs.send_message(QueueUrl=resources_out["queue"], MessageBody=json.dumps(envelope))
            report["duplicate_messages_submitted"] += 1
        except Exception as exc:
            _check(report["checks"], "replay_send", False,
                   f"replay submission failed: {type(exc).__name__}")
            report["status"] = "fail"
            return report
    event_refs = {hashlib.sha256(item.identity.encode()).hexdigest()[:16]
                  for item in normalized}
    logs = _client(session, "logs", region)
    duplicate_refs: set[str] = set()
    deadline = time.monotonic() + poll_seconds
    while time.monotonic() < deadline:
        try:
            entries = _log_events(logs, f"/aws/lambda/{stack_name}-ingest", log_start,
                                  '"Faultline event outcome=duplicate"')
        except Exception as exc:
            _check(report["checks"], "replay_logs", None,
                   f"duplicate log inspection unavailable: {type(exc).__name__}")
            break
        for entry in entries:
            for reference in event_refs:
                if f"event_ref={reference}" in entry.get("message", ""):
                    duplicate_refs.add(reference)
        if duplicate_refs == event_refs:
            break
        time.sleep(3)
    history_after = [_history_count(dynamodb, resources_out["incident_table"], item)
                     for item in expected_incidents]
    unchanged = history_after == history_before
    confirmed = duplicate_refs == event_refs and unchanged
    report["duplicate_suppression"] = "pass" if confirmed else "unverified"
    _check(report["checks"], "replay", True if confirmed else None,
           "all replay messages observed and incident history unchanged" if confirmed else
           "replay processing or unchanged history could not be confirmed")
    report["unverified"].append("Direct SQS test does not prove CloudTrail to EventBridge delivery")
    report["unverified"].append("CloudWatch log delivery is eventual")
    try:
        dlq = sqs.get_queue_attributes(
            QueueUrl=resources_out["dlq"],
            AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]
        report["dlq_messages_observed"] = int(dlq["ApproximateNumberOfMessages"])
        failures = _log_events(logs, f"/aws/lambda/{stack_name}-ingest", log_start,
                               '"Faultline ingestion failure"')
        report["processing_failures_observed"] = len(failures)
        report["unverified"].append(
            "Failure log count may include other traffic and may omit delayed log delivery"
        )
    except Exception as exc:
        _check(report["checks"], "post_test_metrics", None,
               f"post-test metrics unavailable: {type(exc).__name__}")
    return report
