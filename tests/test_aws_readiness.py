"""Readiness checks are exercised with fakes; CI never creates AWS clients."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from faultline.aws.live_validation import inspect_stack, smoke_test, synthetic_envelopes
from faultline.aws.readiness import run_preflight, selector_covers
from faultline.normalize import normalize_record
from faultline.rules import RULES

ROOT = Path(__file__).resolve().parents[1]


class ApiError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeSession:
    def __init__(self, *, account: str = "123456789012", region: str = "us-east-1",
                 read_write: str = "All", expired: bool = False,
                 stack_exists: bool = False, bucket_region: str = "us-east-1") -> None:
        self.region_name = region
        self.account = account
        self.read_write = read_write
        self.expired = expired
        self.stack_exists = stack_exists
        self.bucket_region = bucket_region
        self.calls: list[tuple[str, str]] = []

    def client(self, name: str, *, region_name: str):
        self.calls.append((name, region_name))
        return self

    def get_caller_identity(self):
        if self.expired:
            raise ApiError("ExpiredToken")
        return {"Account": self.account,
                "Arn": f"arn:aws:iam::{self.account}:user/TestOperator"}

    def describe_stacks(self, **_kwargs):
        if self.stack_exists:
            return {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
        raise ApiError("ValidationError", "Stack with id demo does not exist")

    def describe_trails(self, **_kwargs):
        return {"trailList": [{
            "TrailARN": f"arn:aws:cloudtrail:us-east-1:{self.account}:trail/test",
            "HomeRegion": "us-east-1", "IsMultiRegionTrail": True,
            "IncludeGlobalServiceEvents": True,
        }]}

    def get_trail_status(self, **_kwargs):
        return {"IsLogging": True}

    def get_event_selectors(self, **_kwargs):
        return {"EventSelectors": [{"IncludeManagementEvents": True,
                                    "ReadWriteType": self.read_write}]}

    def head_bucket(self, **_kwargs):
        return {}

    def get_bucket_location(self, **_kwargs):
        return {"LocationConstraint": None if self.bucket_region == "us-east-1"
                else self.bucket_region}

    def simulate_principal_policy(self, **_kwargs):
        raise ApiError("AccessDenied")


def preflight(session: FakeSession, *, region: str = "us-east-1") -> dict:
    return run_preflight(session, profile="test", region=region,
                         expected_account="123456789012", stack_name="faultline-demo",
                         bucket="dedicated-artifacts")


def test_read_only_preflight_valid_and_explicit_scoping() -> None:
    session = FakeSession()
    result = preflight(session)
    assert result["status"] == "pass"
    assert {check["name"] for check in result["checks"] if check["status"] == "pass"} >= {
        "account", "stack_name", "coverage_iam", "coverage_sts", "coverage_cloudtrail",
        "artifact_bucket",
    }
    assert all(region == "us-east-1" for _service, region in session.calls)
    assert "AccessDenied" in json.dumps(result)
    assert "SecretAccessKey" not in json.dumps(result)


@pytest.mark.parametrize("session,region,expected", [
    (FakeSession(account="999900001111"), "us-east-1", "account"),
    (FakeSession(region="us-west-2"), "us-east-1", "profile_region"),
    (FakeSession(expired=True), "us-east-1", "session"),
    (FakeSession(stack_exists=True), "us-east-1", "stack_name"),
    (FakeSession(read_write="WriteOnly"), "us-east-1", "coverage_sts"),
    (FakeSession(bucket_region="us-west-2"), "us-east-1", "artifact_bucket"),
    (FakeSession(region="us-west-2"), "us-west-2", "global_service_region"),
])
def test_preflight_fails_closed(session: FakeSession, region: str, expected: str) -> None:
    result = preflight(session, region=region)
    assert result["status"] == "fail"
    assert any(check["name"] == expected and check["status"] == "fail" for check in
               result["checks"])
    if expected in {"account", "profile_region", "session"}:
        assert not any(name == "s3" for name, _region in session.calls)


def test_advanced_cloudtrail_selector_coverage() -> None:
    selectors = {"AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["sts.amazonaws.com"]},
        {"Field": "readOnly", "Equals": ["true"]},
    ]}]}
    assert selector_covers(selectors, "sts.amazonaws.com", True)
    assert not selector_covers(selectors, "sts.amazonaws.com", False)
    assert not selector_covers(selectors, "iam.amazonaws.com", True)


def test_synthetic_events_are_unique_sanitized_and_rule_compatible() -> None:
    records = synthetic_envelopes("test-123", "123456789012", "us-east-1")
    assert len(records) == 4
    assert len({item["detail"]["eventID"] for item in records}) == 4
    assert all(item["account"] == "123456789012" for item in records)
    assert "secretAccessKey" not in json.dumps(records)
    assert "responseElements" not in json.dumps(records)
    normalized = [normalize_record(item) for item in records]
    assert all(item.status == "supported" for item in normalized)
    assert [sum(bool(rule.match(item.event)) for rule in RULES) for item in normalized] == [
        1, 1, 1, 1,
    ]


def test_smoke_requires_two_explicit_gates_before_aws_access() -> None:
    with pytest.raises(ValueError):
        smoke_test(None, region="us-east-1", expected_account="123456789012",
                   stack_name="demo", confirmed_account="123456789012",
                   test_id="unique", send=False)
    with pytest.raises(ValueError):
        smoke_test(None, region="us-east-1", expected_account="123456789012",
                   stack_name="demo", confirmed_account="999900001111",
                   test_id="unique", send=True)


class FakeDeployed(FakeSession):
    def __init__(self) -> None:
        super().__init__()
        account = self.account
        self.queue_arn = f"arn:aws:sqs:us-east-1:{account}:demo-ingest"
        self.dlq_arn = f"arn:aws:sqs:us-east-1:{account}:demo-dlq"
        self.rule_arns = {name: f"arn:aws:events:us-east-1:{account}:rule/demo-{name}"
                          for name in ("Iam", "Sts", "CloudTrail")}
        self.outputs = {
            "IngestQueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/demo-ingest",
            "IngestQueueArn": self.queue_arn,
            "DeadLetterQueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/demo-dlq",
            "DeadLetterQueueArn": self.dlq_arn,
            "EventTableName": "demo-events", "IncidentTableName": "demo-incidents",
            "LambdaArn": f"arn:aws:lambda:us-east-1:{account}:function:demo-ingest",
            "IamRuleArn": self.rule_arns["Iam"],
            "StsRuleArn": self.rule_arns["Sts"],
            "CloudTrailRuleArn": self.rule_arns["CloudTrail"],
        }

    def describe_stacks(self, **_kwargs):
        return {"Stacks": [{"StackStatus": "CREATE_COMPLETE",
                            "EnableTerminationProtection": False, "Outputs": [
            {"OutputKey": key, "OutputValue": value} for key, value in self.outputs.items()
        ]}]}

    def describe_rule(self, *, Name: str, **_kwargs):
        source, event_source, operations = {
            "demo-Iam": ("aws.iam", "iam.amazonaws.com", ["AttachRolePolicy"]),
            "demo-Sts": ("aws.sts", "sts.amazonaws.com", ["AssumeRole"]),
            "demo-CloudTrail": (
                "aws.cloudtrail", "cloudtrail.amazonaws.com", ["StopLogging", "DeleteTrail"]
            ),
        }[Name]
        return {"State": "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" if
                Name == "demo-Sts" else "ENABLED", "EventPattern": json.dumps({
                    "source": [source], "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventSource": [event_source], "eventName": operations},
                })}

    def list_targets_by_rule(self, **_kwargs):
        return {"Targets": [{"Arn": self.queue_arn}]}

    def get_queue_attributes(self, *, QueueUrl: str, **_kwargs):
        if QueueUrl.endswith("demo-dlq"):
            return {"Attributes": {"SqsManagedSseEnabled": "true",
                                   "ApproximateNumberOfMessages": "0"}}
        policy = {"Statement": [{
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": self.queue_arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": self.account},
                          "ArnEquals": {"aws:SourceArn": list(self.rule_arns.values())}},
        }]}
        return {"Attributes": {
            "VisibilityTimeout": "180", "SqsManagedSseEnabled": "true",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": self.dlq_arn,
                                         "maxReceiveCount": 5}),
            "Policy": json.dumps(policy),
        }}

    def get_function_configuration(self, **_kwargs):
        return {"Runtime": "python3.12", "Handler": "faultline.aws.handler.lambda_handler",
                "Architectures": ["x86_64"],
                "Role": f"arn:aws:iam::{self.account}:role/demo-role"}

    def list_event_source_mappings(self, **_kwargs):
        return {"EventSourceMappings": [{"EventSourceArn": self.queue_arn,
                                        "State": "Enabled",
                                        "FunctionResponseTypes": ["ReportBatchItemFailures"]}]}

    def get_role(self, **_kwargs):
        return {"Role": {"Arn": f"arn:aws:iam::{self.account}:role/demo-role"}}

    def list_role_policies(self, **_kwargs):
        return {"PolicyNames": ["FaultlineIngest"]}

    def list_attached_role_policies(self, **_kwargs):
        return {"AttachedPolicies": []}

    def get_role_policy(self, **_kwargs):
        resources = [self.queue_arn] + [
            f"arn:aws:dynamodb:us-east-1:{self.account}:table/{name}"
            for name in ("demo-events", "demo-incidents")
        ]
        return {"PolicyDocument": {"Statement": [
            {"Action": ["sqs:ReceiveMessage", "dynamodb:PutItem"],
             "Resource": resources}
        ]}}

    def describe_table(self, *, TableName: str):
        return {"Table": {"TableStatus": "ACTIVE", "DeletionProtectionEnabled": False,
                          "GlobalSecondaryIndexes": [
            {"IndexName": "AccountTime", "IndexStatus": "ACTIVE"}
        ] if TableName == "demo-incidents" else []}}

    def describe_log_groups(self, **_kwargs):
        return {"logGroups": [{"logGroupName": "/aws/lambda/demo-ingest",
                               "retentionInDays": 7}]}

    def get_metric_statistics(self, **_kwargs):
        return {"Datapoints": []}


def test_deployed_inspection_is_read_only_and_keeps_absent_metrics_unknown() -> None:
    session = FakeDeployed()
    result = inspect_stack(session, region="us-east-1",
                           expected_account="123456789012", stack_name="demo")
    assert result["status"] == "pass"
    assert all(value is None for value in result["metrics"].values())
    assert result["dlq_messages_observed"] == 0
    assert not any(name == "send_message" for name, _region in session.calls)


def _verifier():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "verify_lambda", ROOT / "scripts/verify_lambda.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _zip_with(extra: dict[str, bytes] | None = None, omit: str | None = None) -> bytes:
    verifier = _verifier()
    extra = extra or {}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in verifier.REQUIRED:
            if name == omit:
                continue
            default = (b"def lambda_handler(event, context): pass\n" if
                       name == "faultline/aws/handler.py" else b"pass\n")
            archive.writestr(name, extra.get(name, default))
        archive.writestr("boto3-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\nTag: py3-none-any\n")
        for name, data in extra.items():
            if name not in verifier.REQUIRED:
                archive.writestr(name, data)
    return output.getvalue()


def test_artifact_verification_detects_missing_and_unsafe_files(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "artifact.zip"
    path.write_bytes(_zip_with())
    assert len(verifier.verify_zip(path)) == 64
    path.write_bytes(_zip_with({"secret.env": b"AWS_SECRET_ACCESS_KEY=unsafe"}))
    with pytest.raises(ValueError):
        verifier.verify_zip(path)
    path.write_bytes(_zip_with({"module.pyd": b"windows-native"}))
    with pytest.raises(ValueError):
        verifier.verify_zip(path)
    path.write_bytes(_zip_with(omit="faultline/aws/handler.py"))
    with pytest.raises(ValueError):
        verifier.verify_zip(path)
    path.write_bytes(_zip_with(omit="urllib3/__init__.py"))
    with pytest.raises(ValueError, match="required_runtime_file_missing"):
        verifier.verify_zip(path)
    path.write_bytes(_zip_with({"extra.txt": b"AKIA1234567890123456"}))
    with pytest.raises(ValueError):
        verifier.verify_zip(path)


def test_vendor_examples_pruned_only_with_matching_wheel_records(tmp_path: Path) -> None:
    import base64
    import hashlib

    verifier = _verifier()
    stage = tmp_path / "package"
    examples = {
        "boto3/examples/cloudfront.rst": b"Public example " + b"AKIA" + b"A" * 16,
        "botocore/data/iam/2010-05-08/examples-1.json": (
            b"Example " + b"-----BEGIN " + b"PRIVATE KEY-----"
        ),
        "botocore/data/sts/2011-06-15/examples-1.json": b"Public example",
    }
    for name, data in examples.items():
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    service_model = stage / "botocore/data/dynamodb/2012-08-10/service-2.json.gz"
    service_model.parent.mkdir(parents=True, exist_ok=True)
    service_model.write_bytes(b"required runtime model")
    for vendor in ("boto3", "botocore"):
        manifest = stage / f"{vendor}-1.43.30.dist-info/RECORD"
        manifest.parent.mkdir(parents=True)
        rows = []
        for name, data in examples.items():
            if name.startswith(vendor + "/"):
                digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip(
                    "="
                )
                rows.append(f"{name},sha256={digest},{len(data)}")
        manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert set(verifier.prune_verified_vendor_examples(stage)) == set(examples)
    assert all(not (stage / name).exists() for name in examples)
    assert service_model.exists()


def test_vendor_example_tamper_blocks_pruning(tmp_path: Path) -> None:
    verifier = _verifier()
    example = tmp_path / "boto3/examples/cloudfront.rst"
    example.parent.mkdir(parents=True)
    example.write_bytes(b"tampered vendor example")
    manifest = tmp_path / "boto3-1.43.30.dist-info/RECORD"
    manifest.parent.mkdir()
    manifest.write_text("boto3/examples/cloudfront.rst,sha256=wrong,23\n", encoding="utf-8")
    with pytest.raises(ValueError, match="vendor_example_provenance_mismatch"):
        verifier.prune_verified_vendor_examples(tmp_path)
    assert example.exists()


@pytest.mark.parametrize("member,content,category", [
    ("faultline/aws/handler.py", b"# " + b"AKIA" + b"B" * 16 + b"\n"
     b"def lambda_handler(event, context): pass\n", "aws_access_key_pattern"),
    ("unexpected_dependency.py", b"# -----BEGIN PRIVATE KEY-----\n", "pem_private_key_header"),
])
def test_unexpected_credentials_still_fail_with_safe_member_diagnostics(
    tmp_path: Path, member: str, content: bytes, category: str,
) -> None:
    verifier = _verifier()
    path = tmp_path / "artifact.zip"
    path.write_bytes(_zip_with({member: content}))
    with pytest.raises(ValueError) as error:
        verifier.verify_zip(path)
    message = str(error.value)
    assert f"member={member!r}" in message
    assert f"category={category}" in message
    assert "AKIA" not in message and "PRIVATE KEY" not in message


def test_unpruned_vendor_example_is_rejected(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "artifact.zip"
    path.write_bytes(_zip_with({"boto3/examples/cloudfront.rst": b"public example"}))
    with pytest.raises(ValueError, match="unpruned_vendor_example"):
        verifier.verify_zip(path)


def test_assume_role_probe_requires_explicit_run_and_matching_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "aws_assume_role_probe", ROOT / "scripts/aws_assume_role_probe.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base = ["probe", "--profile", "test", "--region", "us-east-1",
            "--expected-account", "123456789012", "--confirm-account", "999900001111",
            "--role-arn", "arn:aws:iam::123456789012:role/Sandbox"]
    monkeypatch.setattr(sys, "argv", base + ["--run"])
    with pytest.raises(SystemExit):
        module.main()
