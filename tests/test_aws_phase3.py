"""Offline SQS-to-incident simulations; no AWS calls or credentials."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from faultline.aws.gateway import ConflictError, Page, Put
from faultline.aws.handler import process_sqs_batch
from faultline.aws.live_validation import synthetic_envelopes
from faultline.aws.store import CloudCapacityError, DynamoStore, UnsupportedReprocess
from faultline.normalize import normalize_record
from faultline.rules import AttachAdministratorPolicy

FIXTURES = Path(__file__).resolve().parents[1] / "src" / "faultline" / "fixtures"


class MemoryGateway:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str, str], dict] = {}
        self.fail_once = False
        self.conflict_once = False

    @staticmethod
    def key(table: str, item: dict) -> tuple[str, str, str]:
        return table, item["pk"], item["sk"]

    def get(self, table: str, pk: str, sk: str) -> dict | None:
        item = self.items.get((table, pk, sk))
        return copy.deepcopy(item) if item is not None else None

    def put_if_absent(self, table: str, item: dict) -> bool:
        key = self.key(table, item)
        if key in self.items:
            return False
        self.items[key] = copy.deepcopy(item)
        if self.fail_once and item["pk"].startswith("EVENT#") and item["sk"] == "META":
            self.fail_once = False
            raise RuntimeError("simulated interruption after event write")
        return True

    def query_range(
        self, table: str, pk: str, start: str, end: str, limit: int
    ) -> list[dict]:
        return [
            copy.deepcopy(item)
            for (item_table, item_pk, sk), item in sorted(self.items.items())
            if item_table == table and item_pk == pk and start <= sk <= end
        ][:limit]

    def query_account(self, table: str, account_id: str, limit: int) -> list[dict]:
        return [
            copy.deepcopy(item) for item in sorted(
                (item for (item_table, _pk, sk), item in self.items.items()
                 if item_table == table and sk == "META"
                 and item.get("gsi1pk") == f"ACCOUNT#{account_id}"),
                key=lambda item: item["gsi1sk"], reverse=True,
            )
        ][:limit]

    def query_range_page(
        self, table: str, pk: str, start: str, end: str, limit: int,
        cursor: dict | None = None,
    ) -> Page:
        items = self.query_range(table, pk, start, end, 10_000)
        offset = int(cursor["offset"]) if cursor else 0
        end_offset = offset + limit
        return Page(items[offset:end_offset], {"offset": end_offset}
                    if end_offset < len(items) else None)

    def query_account_page(
        self, table: str, account_id: str, limit: int,
        cursor: dict | None = None,
    ) -> Page:
        items = self.query_account(table, account_id, 10_000)
        offset = int(cursor["offset"]) if cursor else 0
        end_offset = offset + limit
        return Page(items[offset:end_offset], {"offset": end_offset}
                    if end_offset < len(items) else None)

    def transact(self, puts: list[Put]) -> None:
        if self.conflict_once:
            self.conflict_once = False
            raise ConflictError("simulated competing writer")
        for put in puts:
            old = self.items.get(self.key(put.table, put.item))
            if put.expected_revision is None:
                if old is not None:
                    raise ConflictError("item exists")
            elif old is None or old.get("revision") != put.expected_revision:
                raise ConflictError("revision changed")
        for put in puts:
            self.items[self.key(put.table, put.item)] = copy.deepcopy(put.item)


def fixture(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines()]


def envelope(raw: dict) -> dict:
    if "detail" in raw:
        return raw
    service = raw["eventSource"].split(".", 1)[0]
    return {
        "detail-type": "AWS API Call via CloudTrail",
        "source": f"aws.{service}",
        "account": raw["recipientAccountId"],
        "detail": raw,
    }


def message(identifier: str, value: dict) -> dict:
    return {"messageId": identifier, "body": json.dumps(envelope(value))}


def current_incidents(gateway: MemoryGateway) -> list[dict]:
    return [
        item for (table, _pk, sk), item in gateway.items.items()
        if table == "incidents" and sk == "META" and item["is_current"]
    ]


def test_sqs_batch_replay_and_durable_incidents() -> None:
    gateway = MemoryGateway()
    events = fixture("demo-iam.jsonl") + fixture("demo-trail.jsonl")
    batch = {"Records": [message(str(i), value) for i, value in enumerate(events)]}
    result = process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents"))
    assert result == {"batchItemFailures": []}
    incidents = current_incidents(gateway)
    assert len(incidents) == 2
    assert sorted(len(item["members"]) for item in incidents) == [2, 2]
    assert all(len(item["links"]) == 1 for item in incidents)
    assert all(item["status"] == "open" for item in incidents)
    assert len(DynamoStore(gateway, "events", "incidents").list_account_incidents(
        "111122223333"
    )) == 1
    initial = copy.deepcopy(gateway.items)
    assert process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": []
    }
    assert gateway.items == initial
    assert "SYNTHETIC-DO-NOT-STORE" not in json.dumps(list(gateway.items.values()))


def test_out_of_order_retry_and_independent_batches() -> None:
    gateway = MemoryGateway()
    iam = fixture("demo-iam.jsonl")
    store = DynamoStore(gateway, "events", "incidents")
    gateway.fail_once = True
    second = {"Records": [
        message("sts", iam[1]), {"messageId": "bad", "body": '{"x":1}'},
    ]}
    assert process_sqs_batch(second, lambda: store) == {
        "batchItemFailures": [{"itemIdentifier": "sts"}]
    }
    gateway.conflict_once = True
    assert process_sqs_batch(second, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": []
    }
    original_incident_id = current_incidents(gateway)[0]["incident_id"]
    assert process_sqs_batch(
        {"Records": [message("iam", iam[0])]}, lambda: store
    ) == {"batchItemFailures": []}
    assert len(current_incidents(gateway)) == 1
    assert len(current_incidents(gateway)[0]["members"]) == 2
    assert current_incidents(gateway)[0]["incident_id"] != original_incident_id
    assert store.get_incident(original_incident_id)["is_current"] is False
    assert any(item["action"] == "superseded" for item in store.get_history(original_incident_id))


def test_malformed_and_duplicate_json_are_acknowledged() -> None:
    gateway = MemoryGateway()
    batch = {"Records": [
        {"messageId": "broken", "body": "{"},
        {"messageId": "duplicate", "body": '{"detail":1,"detail":2}'},
        {"messageId": "raw", "body": json.dumps(fixture("demo-iam.jsonl")[0])},
        {"messageId": "wrong-source-type", "body": json.dumps({
            **envelope(fixture("demo-iam.jsonl")[0]), "source": ["aws.iam"]
        })},
        message("good", fixture("demo-iam.jsonl")[0]),
    ]}
    assert process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": []
    }
    assert len(current_incidents(gateway)) == 1


def test_bounded_operational_failure_isolated_from_valid_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    gateway = MemoryGateway()
    large = copy.deepcopy(fixture("demo-iam.jsonl")[0])
    large["eventID"] = "large-event"
    large["resources"] = [{"ARN": "arn:aws:iam::111122223333:role/" + str(i) + "x" * 478}
                          for i in range(40)]
    batch = {"Records": [message("large", large), message("valid", fixture("demo-iam.jsonl")[0])]}
    assert process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": [{"itemIdentifier": "large"}]
    }
    assert "category=capacity" in caplog.text
    assert "arn:aws:iam" not in caplog.text
    assert len(current_incidents(gateway)) == 1


def test_account_or_actor_mismatch_prevents_link() -> None:
    gateway = MemoryGateway()
    iam = fixture("demo-iam.jsonl")
    mismatched = copy.deepcopy(iam[1])
    mismatched["userIdentity"]["principalId"] = "OTHERPRINCIPAL"
    for raw in (iam[0], mismatched):
        result = normalize_record(envelope(raw))
        assert result.status == "supported"
        DynamoStore(gateway, "events", "incidents").ingest(result.event)
    assert len(current_incidents(gateway)) == 2
    assert all(not item["links"] for item in current_incidents(gateway))


def test_incident_assessment_survives_new_member() -> None:
    gateway = MemoryGateway()
    iam = fixture("demo-iam.jsonl")
    store = DynamoStore(gateway, "events", "incidents")
    first = normalize_record(iam[0]).event
    second = normalize_record(iam[1]).event
    store.ingest(first)
    incident_id = current_incidents(gateway)[0]["incident_id"]
    assert store.update_incident(incident_id, status="investigating", assessment="Reviewed")
    store.ingest(second)
    current = current_incidents(gateway)[0]
    assert current["status"] == "investigating"
    assert current["assessment"] == "Reviewed"
    assert any(item["action"] == "assessment_updated" for item in store.get_history(incident_id))


def test_explicit_additive_rule_reprocess_and_deactivation_limit() -> None:
    class V2(AttachAdministratorPolicy):
        version = "2.0.0"

        def match(self, event):  # type: ignore[no-untyped-def]
            detection = super().match(event)
            return replace(detection, explanation="Updated rule explanation") if detection else None

    class V3(V2):
        version = "3.0.0"

        def match(self, event):  # type: ignore[no-untyped-def]
            return None

    gateway = MemoryGateway()
    store = DynamoStore(gateway, "events", "incidents")
    event = normalize_record(fixture("demo-iam.jsonl")[0]).event
    store.ingest(event, rules=(AttachAdministratorPolicy(),))
    incident_id = current_incidents(gateway)[0]["incident_id"]
    store.reprocess_event(event.account_id, event.event_id, rules=(V2(),))
    assert current_incidents(gateway)[0]["incident_id"] == incident_id
    assert set(current_incidents(gateway)[0]["detection_versions"].values()) == {"2.0.0"}
    assert any(key[2] == "EVAL#FLT-IAM-001#2.0.0" for key in gateway.items)
    with pytest.raises(UnsupportedReprocess):
        store.reprocess_event(event.account_id, event.event_id, rules=(V3(),))
    blocks = store.get_reprocess_blocks(event.account_id, event.event_id)
    assert len(blocks) == 1
    assert blocks[0]["reason_code"] == "DEACTIVATION_UNSUPPORTED"
    assert store.get_incident(incident_id)["reprocess_blocks"][0]["reason_code"] == (
        "DEACTIVATION_UNSUPPORTED"
    )
    assert any(item["action"] == "rule_reprocess_blocked" for item in
               store.get_history(incident_id))


def test_paginated_account_and_history_reads_are_explicit() -> None:
    gateway = MemoryGateway()
    store = DynamoStore(gateway, "events", "incidents")
    raw = fixture("demo-iam.jsonl")[0]
    for i in range(3):
        event = copy.deepcopy(raw)
        event["eventID"] = f"paged-{i}"
        store.ingest(normalize_record(event).event)
    first = store.list_account_incidents_page("111122223333", limit=2)
    assert len(first.items) == 2 and first.cursor is not None
    second = store.list_account_incidents_page("111122223333", limit=2,
                                               cursor=first.cursor)
    assert len(second.items) == 1 and second.cursor is None
    with pytest.raises(CloudCapacityError):
        store.list_account_incidents("111122223333", limit=2)
    incident_id = first.items[0]["incident_id"]
    assert store.update_incident(incident_id, status="investigating")
    history_first = store.get_history_page(incident_id, limit=1)
    assert history_first.cursor is not None
    history_second = store.get_history_page(incident_id, limit=1,
                                            cursor=history_first.cursor)
    assert history_second.cursor is None
    with pytest.raises(CloudCapacityError):
        store.get_history(incident_id, limit=1)


def test_scope_capacity_boundary_and_recovery_marker() -> None:
    gateway = MemoryGateway()
    store = DynamoStore(gateway, "events", "incidents")
    raw = fixture("demo-iam.jsonl")[0]
    for i in range(16):
        event = copy.deepcopy(raw)
        event["eventID"] = f"scope-{i}"
        store.ingest(normalize_record(event).event)
    extra = copy.deepcopy(raw)
    extra["eventID"] = "scope-overflow"
    with pytest.raises(CloudCapacityError):
        store.ingest(normalize_record(extra).event)
    assert gateway.get("events", "EVENT#111122223333:scope-overflow", "META") is not None
    assert len(current_incidents(gateway)) == 16


def test_concurrent_assessment_retry_preserves_history() -> None:
    gateway = MemoryGateway()
    store = DynamoStore(gateway, "events", "incidents")
    store.ingest(normalize_record(fixture("demo-iam.jsonl")[0]).event)
    identifier = current_incidents(gateway)[0]["incident_id"]
    gateway.conflict_once = True
    assert store.update_incident(identifier, status="investigating", assessment="Approved review")
    history = store.get_history(identifier)
    assert [item["action"] for item in history].count("assessment_updated") == 1
    assert store.get_incident(identifier)["assessment"] == "Approved review"


def test_phase3b_synthetic_envelopes_through_lambda_path(caplog: pytest.LogCaptureFixture) -> None:
    gateway = MemoryGateway()
    events = synthetic_envelopes("offline-validation", "123456789012", "us-east-1")
    batch = {"Records": [message(str(i), item) for i, item in enumerate(events)]}
    assert process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": []
    }
    incidents = current_incidents(gateway)
    assert len(incidents) == 2
    assert all(len(item["members"]) == 2 for item in incidents)
    gateway.fail_once = False
    assert process_sqs_batch(batch, lambda: DynamoStore(gateway, "events", "incidents")) == {
        "batchItemFailures": []
    }
    assert len(current_incidents(gateway)) == 2
    assert "responseElements" not in json.dumps(list(gateway.items.values()))
    assert "secretAccessKey" not in caplog.text


@pytest.mark.parametrize("change", ["account", "principal"])
def test_isolation(change: str) -> None:
    gateway = MemoryGateway()
    iam = fixture("demo-iam.jsonl")
    modified = copy.deepcopy(iam[1])
    if change == "account":
        modified["recipientAccountId"] = "999900001111"
        modified["userIdentity"]["accountId"] = "999900001111"
    else:
        modified["userIdentity"]["principalId"] = "OTHERPRINCIPAL"
    store = DynamoStore(gateway, "events", "incidents")
    for raw in (iam[0], modified):
        store.ingest(normalize_record(raw).event)
    assert len(current_incidents(gateway)) == 2
    assert all(not incident["links"] for incident in current_incidents(gateway))


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CloudFormationLoader.add_multi_constructor("!", _tag)


def test_cloudformation_routing_permissions_and_retry_contract() -> None:
    path = FIXTURES.parents[2] / "infra/cloudformation/faultline.yaml"
    template = yaml.load(path.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)
    resources = template["Resources"]
    expected = {
        "IamApiRule": ("aws.iam", "iam.amazonaws.com", ["AttachRolePolicy"]),
        "StsApiRule": ("aws.sts", "sts.amazonaws.com", ["AssumeRole"]),
        "CloudTrailApiRule": (
            "aws.cloudtrail", "cloudtrail.amazonaws.com", ["StopLogging", "DeleteTrail"]
        ),
    }
    for name, (source, event_source, operations) in expected.items():
        pattern = resources[name]["Properties"]["EventPattern"]
        assert pattern["source"] == [source]
        assert pattern["detail-type"] == ["AWS API Call via CloudTrail"]
        assert pattern["detail"]["eventSource"] == [event_source]
        assert pattern["detail"]["eventName"] == operations
        assert resources[name]["Properties"]["EventBusName"] == "default"
        assert resources[name]["Properties"]["Targets"][0]["Arn"] == "IngestQueue.Arn"
    assert resources["StsApiRule"]["Properties"]["State"] == (
        "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    )
    queue = resources["IngestQueue"]["Properties"]
    function = resources["IngestFunction"]["Properties"]
    assert queue["VisibilityTimeout"] >= 6 * function["Timeout"]
    assert queue["RedrivePolicy"]["maxReceiveCount"] == 5
    assert resources["QueueMapping"]["Properties"]["FunctionResponseTypes"] == [
        "ReportBatchItemFailures"
    ]
    assert resources["QueueMapping"]["Properties"]["BatchSize"] == 10
    policy = resources["EventBridgeQueuePolicy"]["Properties"]["PolicyDocument"]
    statement = policy["Statement"][0]
    assert statement["Principal"] == {"Service": "events.amazonaws.com"}
    assert statement["Action"] == "sqs:SendMessage"
    assert statement["Resource"] == "IngestQueue.Arn"
    assert set(statement["Condition"]["ArnEquals"]["aws:SourceArn"]) == {
        "IamApiRule.Arn", "StsApiRule.Arn", "CloudTrailApiRule.Arn"
    }
    assert statement["Condition"]["StringEquals"]["aws:SourceAccount"] == (
        "AWS::AccountId"
    )
    assert policy["Statement"][1]["Condition"]["Bool"]["aws:SecureTransport"] == "false"
    assert resources["DeadLetterQueuePolicy"]["Properties"]["PolicyDocument"][
        "Statement"
    ][0]["Condition"]["Bool"]["aws:SecureTransport"] == "false"
    statements = resources["LambdaRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"
    ]
    assert all("*" not in statement["Action"] for statement in statements)
    assert statements[0]["Resource"] == "IngestQueue.Arn"
    assert statements[1]["Resource"] == [
        "EventTable.Arn", "IncidentTable.Arn", "${IncidentTable.Arn}/index/AccountTime"
    ]
    assert resources["FunctionLogGroup"]["Properties"]["RetentionInDays"] == 7
    assert all(resources[name]["Properties"]["SqsManagedSseEnabled"] for name in (
        "IngestQueue", "DeadLetterQueue"
    ))
