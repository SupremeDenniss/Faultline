from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from faultline.cli import main
from faultline.input import InputError, read_records
from faultline.normalize import normalize_record
from faultline.rules import ADMIN_POLICY_ARN, detect
from faultline.storage import SQLiteStore


def event(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "eventID": "test-event-1",
        "eventTime": "2026-01-15T10:00:00-05:00",
        "recipientAccountId": "111122223333",
        "awsRegion": "us-east-1",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachRolePolicy",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE:session",
            "arn": "arn:aws:sts::111122223333:assumed-role/Admin/session",
            "sessionContext": {
                "sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/Admin"}
            },
        },
        "requestParameters": {"roleName": "Worker", "policyArn": ADMIN_POLICY_ARN},
    }
    value.update(overrides)
    return value


def normalized(value: object):
    result = normalize_record(value)
    assert result.status == "supported"
    assert result.event is not None
    return result.event


def test_raw_normalization_canonical_utc_and_identity() -> None:
    result = normalized(event())
    assert result.occurred_at == "2026-01-15T15:00:00Z"
    assert result.identity == "111122223333:test-event-1"
    assert result.actor_type == "AssumedRole"
    assert result.principal_id == "AROAEXAMPLE:session"
    assert result.session_issuer_arn == "arn:aws:iam::111122223333:role/Admin"


def test_eventbridge_normalization_and_source_reference() -> None:
    detail = event(eventID="eventbridge-event")
    envelope = {
        "detail-type": "AWS API Call via CloudTrail",
        "id": "envelope-1",
        "account": "111122223333",
        "region": "us-east-1",
        "detail": detail,
    }
    result = normalized(envelope)
    assert result.source_format == "eventbridge"
    assert result.envelope_id == "envelope-1"
    assert normalize_record({**envelope, "detail-type": "AWS Health Event"}).status == "ignored"


@pytest.mark.parametrize(
    "change, diagnostic",
    [
        ({"eventTime": None}, "eventTime"),
        ({"eventTime": "2026-01-15T10:00:00"}, "eventTime"),
        ({"eventTime": "not-a-date"}, "eventTime"),
        ({"eventID": ""}, "eventID"),
        ({"recipientAccountId": None}, "account"),
        ({"requestParameters": "bad"}, "requestParameters"),
        ({"errorCode": ["AccessDenied"]}, "errorCode"),
    ],
)
def test_malformed_required_or_security_relevant_fields(
    change: dict[str, object], diagnostic: str
) -> None:
    result = normalize_record(event(**change))
    assert result.status == "invalid"
    assert diagnostic in result.diagnostic


def test_missing_optional_fields_are_not_invented() -> None:
    result = normalized(event(userIdentity=None, resources=None, awsRegion=None))
    assert result.actor_arn is None
    assert result.principal_id is None
    assert result.resources == ()
    assert result.region is None


def test_rules_match_exact_operations_and_stable_ids() -> None:
    iam = detect(normalized(event()))
    trail = detect(
        normalized(
            event(
                eventSource="cloudtrail.amazonaws.com",
                eventName="StopLogging",
                requestParameters={"name": "demo-trail"},
            )
        )
    )
    assert [finding.rule_id for finding in iam] == ["FLT-IAM-001"]
    assert [finding.rule_id for finding in trail] == ["FLT-CT-001"]
    assert iam[0].resource == "Worker"
    assert iam[0].event_reference == "111122223333:test-event-1"
    assert trail[0].resource == "demo-trail"
    assert "may be authorized" in iam[0].explanation


@pytest.mark.parametrize(
    "change",
    [
        {"eventName": "ListRoles"},
        {"eventName": "AttachUserPolicy"},
        {"eventSource": "not-iam.amazonaws.com"},
        {"requestParameters": {"roleName": "Worker", "policyArn": "another-policy"}},
        {"requestParameters": {"policyArn": ADMIN_POLICY_ARN}},
        {"errorCode": "AccessDenied"},
    ],
)
def test_benign_nonmatching_or_failed_iam_events_do_not_detect(change: dict[str, object]) -> None:
    assert detect(normalized(event(**change))) == ()


def test_failed_or_unidentified_stop_logging_does_not_detect() -> None:
    base = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "requestParameters": {"name": "demo-trail"},
    }
    assert detect(normalized(event(**base, errorCode="AccessDeniedException"))) == ()
    assert detect(normalized(event(**{**base, "requestParameters": None}))) == ()


def test_input_formats_and_bad_json_line(tmp_path: Path) -> None:
    path = tmp_path / "events.json"
    path.write_text(json.dumps(event()), encoding="utf-8")
    assert len(read_records(path)) == 1
    path.write_text(json.dumps([event(), event(eventID="second")]), encoding="utf-8")
    assert len(read_records(path)) == 2
    path.write_text(json.dumps(event()) + "\n{broken\n" + json.dumps(event()), encoding="utf-8")
    records = read_records(path)
    assert len(records) == 3
    assert records[1].error == "invalid JSON"


def test_input_file_limit_and_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff")
    with pytest.raises(InputError, match="UTF-8"):
        read_records(path)
    path.write_bytes(b" " * (10 * 1024 * 1024 + 1))
    with pytest.raises(InputError, match="exceeds"):
        read_records(path)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ambiguous.jsonl"
    path.write_text(
        json.dumps(event()).removesuffix("}")
        + ',"errorCode":"AccessDenied","errorCode":null}',
        encoding="utf-8",
    )
    records = read_records(path)
    assert len(records) == 1
    assert records[0].error == "invalid JSON"


def test_escaped_surrogate_is_reported_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "surrogate.json"
    path.write_text(json.dumps(event(eventID="\ud800")), encoding="utf-8")
    records = read_records(path)
    assert records[0].error == "invalid JSON structure"


def test_storage_replay_keeps_status_and_created_time(tmp_path: Path) -> None:
    item = normalized(event())
    db = tmp_path / "incidents.db"
    with SQLiteStore(db) as store:
        assert store.save(item, detect(item)) == (True, 1)
        first = store.list_incidents()
        incident_id = first[0]["incident_id"]
        store.connection.execute(
            "UPDATE incidents SET status='reviewing' WHERE incident_id=?", (incident_id,)
        )
        store.connection.commit()
        assert store.save(item, detect(item)) == (False, 0)
        shown = store.show_incident(incident_id)
        assert shown is not None
        assert shown["status"] == "reviewing"
        assert shown["created_at"] == first[0]["created_at"]
        assert len(store.list_incidents()) == 1
        assert shown["evidence"]["policyArn"] == ADMIN_POLICY_ARN


def test_storage_omits_secret_and_raw_payload(tmp_path: Path) -> None:
    raw = event(
        requestParameters={
            "roleName": "Worker",
            "policyArn": ADMIN_POLICY_ARN,
            "secretAccessKey": "DO-NOT-STORE-THIS-SECRET",
        },
        responseElements={"token": "DO-NOT-STORE-THIS-TOKEN"},
    )
    item = normalized(raw)
    db = tmp_path / "safe.db"
    with SQLiteStore(db) as store:
        store.save(item, detect(item))
    data = db.read_bytes()
    assert b"DO-NOT-STORE-THIS-SECRET" not in data
    assert b"DO-NOT-STORE-THIS-TOKEN" not in data


def test_cli_demo_replay_and_show(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "demo.db"
    args = ["--db", str(db), "demo"]
    assert main(args) == 0
    output = capsys.readouterr().out
    assert "2 new incidents" in output
    assert "1 duplicates" in output
    assert "1 invalid" in output
    assert "benign/no matching rule" in output
    assert "failed API call" in output
    assert main(args) == 0
    assert "0 new incidents" in capsys.readouterr().out
    with SQLiteStore(db) as store:
        assert len(store.list_incidents()) == 2
        incident_id = store.list_incidents()[0]["incident_id"]
    assert main(["--db", str(db), "incidents", "list"]) == 0
    assert incident_id in capsys.readouterr().out
    assert main(["--db", str(db), "incidents", "show", incident_id]) == 0
    assert "evidence:" in capsys.readouterr().out


def test_cli_invalid_input_does_not_corrupt_existing_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "events.db"
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(event()) + "\n{broken", encoding="utf-8")
    assert main(["--db", str(db), "ingest", "--file", str(source)]) == 1
    assert "1 invalid" in capsys.readouterr().out
    with SQLiteStore(db) as store:
        assert len(store.list_incidents()) == 1
    source.write_bytes(b"\xff")
    assert main(["--db", str(db), "ingest", "--file", str(source)]) == 2
    with SQLiteStore(db) as store:
        assert len(store.list_incidents()) == 1


def test_bundled_fixture_is_synthetic_and_contains_required_cases() -> None:
    path = resources.files("faultline").joinpath("fixtures/demo.jsonl")
    with resources.as_file(path) as file:
        records = read_records(file)
    assert len(records) == 7
    assert [normalize_record(record.value).status for record in records].count("invalid") == 1
