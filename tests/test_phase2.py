from __future__ import annotations

import json
import sqlite3
from importlib import resources
from pathlib import Path

import pytest

from faultline.cli import main
from faultline.correlation import IAM_SEQUENCE_ID, TRAIL_SEQUENCE_ID
from faultline.input import read_records
from faultline.normalize import normalize_record
from faultline.rules import ADMIN_POLICY_ARN, AttachAdministratorPolicy, detect
from faultline.storage import SQLiteStore


def fixture(name: str) -> list[dict]:
    resource = resources.files("faultline").joinpath(f"fixtures/demo-{name}.jsonl")
    with resources.as_file(resource) as path:
        return [record.value for record in read_records(path)]


def normalized(raw: dict):
    result = normalize_record(raw)
    assert result.status == "supported" and result.event is not None
    return result.event


def _detail(raw: dict) -> dict:
    return raw["detail"] if "detail" in raw else raw


def _change(raw: dict, **changes: object) -> dict:
    result = json.loads(json.dumps(raw))
    _detail(result).update(changes)
    return result


@pytest.mark.parametrize("scenario,correlation_id", [
    ("iam", IAM_SEQUENCE_ID), ("trail", TRAIL_SEQUENCE_ID)
])
def test_correlated_incident_has_evidence_and_ordered_timeline(
    tmp_path: Path, scenario: str, correlation_id: str
) -> None:
    raw = fixture(scenario)
    with SQLiteStore(tmp_path / "events.db") as store:
        results = store.ingest_batch([normalized(item) for item in raw])
        assert results == [(True, 1), (True, 1), (True, 0)]
        listed = store.list_incidents()
        assert len(listed) == 1
        assert listed[0]["detection_count"] == 2
        assert listed[0]["event_count"] == 2
        assert listed[0]["correlation_rule_ids"] == [correlation_id]
        report = store.show_incident(listed[0]["incident_id"])
        assert report is not None
        assert len(report["correlation_conclusions"]) == 1
        assert report["correlation_conclusions"][0]["rule_version"] == "1.0.0"
        times = [item["occurred_at"] for item in report["observed_timeline"]]
        assert times == sorted(times)
        assert report["unknowns"]
        assert report["unverified_possibilities"]
        assert report["investigation_steps"]


@pytest.mark.parametrize("scenario", ["iam", "trail"])
def test_order_replay_and_restart_are_idempotent(tmp_path: Path, scenario: str) -> None:
    events = [normalized(item) for item in fixture(scenario)[:2]]
    views = []
    for index, order in enumerate((events, list(reversed(events)))):
        db = tmp_path / f"order-{index}.db"
        with SQLiteStore(db) as store:
            for item in order:
                store.save(item, detect(item))
        with SQLiteStore(db) as store:
            listed = store.list_incidents()
            assert len(listed) == 1
            assert store.ingest_batch(events) == [(False, 0), (False, 0)]
            assert len(store.list_incidents()) == 1
            report = store.show_incident(listed[0]["incident_id"])
            views.append((listed[0]["incident_id"], listed[0]["rule_ids"],
                          [item["event_reference"] for item in report["observed_timeline"]]))
    assert views[0] == views[1]


def test_iam_correlation_requires_exact_role_arn_and_actor(tmp_path: Path) -> None:
    base = fixture("iam")
    attach = normalized(base[0])
    variants = [
        _change(base[1], eventID="different-path", requestParameters={
            "roleArn": "arn:aws:iam::111122223333:role/other/AuditWorker"}),
        _change(base[1], eventID="different-actor", userIdentity={
            "type": "IAMUser", "principalId": "AIDADIFFERENT",
            "arn": "arn:aws:iam::111122223333:user/Other", "accountId": "111122223333"}),
        _change(base[1], eventID="different-account", recipientAccountId="444455556666"),
        _change(base[1], eventID="outside-window", eventTime="2026-01-15T11:00:01Z"),
        _change(base[1], eventID="failed-assume", errorCode="AccessDenied"),
    ]
    for index, raw in enumerate(variants):
        with SQLiteStore(tmp_path / f"negative-{index}.db") as store:
            store.ingest_batch([attach, normalized(raw)])
            assert len(store.list_incidents()) >= 1
            assert all(item["detection_count"] == 1 for item in store.list_incidents())
    no_arn = _change(base[0], resources=[])
    with SQLiteStore(tmp_path / "no-arn.db") as store:
        store.ingest_batch([normalized(no_arn), normalized(base[1])])
        assert all(item["detection_count"] == 1 for item in store.list_incidents())


def test_missing_identity_prevents_linkage(tmp_path: Path) -> None:
    raw = fixture("trail")
    stop = normalized(_change(raw[0], userIdentity=None))
    delete = normalized(_change(raw[1], userIdentity=None))
    with SQLiteStore(tmp_path / "missing.db") as store:
        store.ingest_batch([stop, delete])
        assert len(store.list_incidents()) == 2
        assert all(not item["correlation_rule_ids"] for item in store.list_incidents())
        report = store.show_incident(store.list_incidents()[0]["incident_id"])
        assert report["observed_timeline"][0]["actor"]["arn"] is None
        assert "At least one caller identity is incomplete." in report["unknowns"]


def test_ambiguous_role_path_and_session_context_prevent_linkage(tmp_path: Path) -> None:
    raw = fixture("iam")
    ambiguous = _change(raw[0], resources=[
        {"ARN": "arn:aws:iam::111122223333:role/team/AuditWorker"},
        {"ARN": "arn:aws:iam::111122223333:role/other/AuditWorker"},
    ])
    with SQLiteStore(tmp_path / "ambiguous.db") as store:
        store.ingest_batch([normalized(ambiguous), normalized(raw[1])])
        assert all(item["detection_count"] == 1 for item in store.list_incidents())
    identity = {
        "type": "AssumedRole", "principalId": "AROAEXAMPLE:session",
        "arn": "arn:aws:sts::111122223333:assumed-role/Operator/session",
        "accountId": "111122223333",
        "sessionContext": {"sessionIssuer": {
            "arn": "arn:aws:iam::111122223333:role/Operator"
        }},
    }
    other_identity = json.loads(json.dumps(identity))
    other_identity["sessionContext"]["sessionIssuer"]["arn"] = (
        "arn:aws:iam::111122223333:role/Other"
    )
    with SQLiteStore(tmp_path / "session.db") as store:
        store.ingest_batch([
            normalized(_change(raw[0], userIdentity=identity)),
            normalized(_change(raw[1], userIdentity=other_identity)),
        ])
        assert all(item["detection_count"] == 1 for item in store.list_incidents())


def test_late_earlier_event_rekeys_and_preserves_assessment(tmp_path: Path) -> None:
    attach, assume = [normalized(item) for item in fixture("iam")[:2]]
    db = tmp_path / "late.db"
    with SQLiteStore(db) as store:
        store.ingest_batch([assume])
        original = store.list_incidents()[0]["incident_id"]
        store.update_incident(original, status="investigating", assessment="Checking access")
    with SQLiteStore(db) as store:
        store.ingest_batch([attach])
        current = store.list_incidents()
        assert len(current) == 1
        assert current[0]["incident_id"] != original
        report = store.show_incident(current[0]["incident_id"])
        assert report["status"] == "investigating"
        assert report["assessment"] == "Checking access"
        assert report["history"][-1]["details"]["replaced_incident_ids"] == [original]
        assert store.show_incident(original) is None
        archive = store.incident_history(original)
        assert archive["is_current"] is False
        assert archive["history"][-1]["action"] == "superseded"
        assert store.connection.execute(
            "SELECT is_current FROM incidents WHERE incident_id=?", (original,)
        ).fetchone()[0] == 0


def test_duplicate_eventbridge_delivery_has_one_detection(tmp_path: Path) -> None:
    raw = fixture("trail")[1]
    repeated = json.loads(json.dumps(raw))
    repeated["id"] = "another-delivery-id"
    with SQLiteStore(tmp_path / "deliveries.db") as store:
        assert store.ingest_batch([normalized(raw), normalized(repeated)]) == [
            (True, 1), (False, 0)
        ]
        assert len(store.list_incidents()) == 1


def test_similar_sequences_in_separate_accounts_remain_separate(tmp_path: Path) -> None:
    original = fixture("iam")[:2]
    other = [
        json.loads(json.dumps(item).replace("111122223333", "444455556666"))
        for item in original
    ]
    with SQLiteStore(tmp_path / "accounts.db") as store:
        store.ingest_batch([normalized(item) for item in original + other])
        listed = store.list_incidents()
        assert len(listed) == 2
        assert {item["account_id"] for item in listed} == {"111122223333", "444455556666"}
        assert all(item["detection_count"] == 2 for item in listed)


def test_trail_correlation_requires_exact_name_region_actor_and_window(tmp_path: Path) -> None:
    raw = fixture("trail")
    different_region = _change(raw[1], eventID="different-region", awsRegion="us-west-2")
    different_region["region"] = "us-west-2"
    variants = [
        _change(raw[1], eventID="different-name", requestParameters={
            "name": "arn:aws:cloudtrail:us-east-1:444455556666:trail/other"}),
        different_region,
        _change(raw[1], eventID="different-actor", userIdentity={
            "type": "IAMUser", "principalId": "AIDAOTHER",
            "arn": "arn:aws:iam::444455556666:user/Other", "accountId": "444455556666"}),
        _change(raw[1], eventID="too-late", eventTime="2026-01-15T11:31:00Z"),
        _change(raw[1], eventID="failed-delete", errorCode="AccessDenied"),
    ]
    for index, variant in enumerate(variants):
        with SQLiteStore(tmp_path / f"trail-negative-{index}.db") as store:
            store.ingest_batch([normalized(raw[0]), normalized(variant)])
            assert all(item["detection_count"] == 1 for item in store.list_incidents())


def test_configured_window_is_persisted_and_enforced(tmp_path: Path) -> None:
    db = tmp_path / "window.db"
    events = [normalized(item) for item in fixture("iam")[:2]]
    with SQLiteStore(db, window_minutes=3) as store:
        store.ingest_batch(events)
        assert len(store.list_incidents()) == 2
    with SQLiteStore(db) as store:
        assert store.window.total_seconds() == 180
        assert len(store.list_incidents()) == 2
    with pytest.raises(ValueError, match="changing it requires a new database"):
        SQLiteStore(db, window_minutes=30)


def _phase1_database(path: Path) -> str:
    item = normalized(fixture("iam")[0])
    incident_id = "inc-phase1-preserved"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE events (
            event_key TEXT PRIMARY KEY, event_id TEXT NOT NULL, account_id TEXT NOT NULL,
            occurred_at TEXT NOT NULL, region TEXT, event_source TEXT NOT NULL,
            event_name TEXT NOT NULL, actor_type TEXT, actor_arn TEXT, principal_id TEXT,
            session_issuer_arn TEXT, resources_json TEXT NOT NULL, request_json TEXT NOT NULL,
            error_code TEXT, source_format TEXT NOT NULL, envelope_id TEXT,
            ingested_at TEXT NOT NULL);
        CREATE TABLE detections (
            incident_id TEXT PRIMARY KEY, event_key TEXT NOT NULL REFERENCES events(event_key),
            rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
            explanation TEXT NOT NULL, resource TEXT NOT NULL, evidence_json TEXT NOT NULL,
            UNIQUE(event_key, rule_id));
        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY REFERENCES detections(incident_id),
            status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL);
    """)
    connection.execute(
        "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (item.identity, item.event_id, item.account_id, item.occurred_at, item.region,
         item.event_source, item.event_name, item.actor_type, item.actor_arn,
         item.principal_id, item.session_issuer_arn, json.dumps(item.resources),
         json.dumps(item.request), item.error_code, item.source_format, item.envelope_id,
         "2026-01-20T00:00:00Z"),
    )
    detection = detect(item)[0]
    connection.execute(
        "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?)",
        (incident_id, item.identity, detection.rule_id, detection.severity,
         detection.title, detection.explanation, detection.resource,
         json.dumps(detection.evidence)),
    )
    connection.execute("INSERT INTO incidents VALUES (?, 'investigating', ?, ?)",
                       (incident_id, "2026-01-20T00:00:00Z", "2026-01-21T00:00:00Z"))
    connection.commit()
    connection.close()
    return incident_id


def test_phase1_migration_preserves_data_and_status(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    incident_id = _phase1_database(db)
    with SQLiteStore(db) as store:
        report = store.show_incident(incident_id)
        assert report is not None
        assert report["status"] == "investigating"
        assert report["created_at"] == "2026-01-20T00:00:00Z"
        assert report["detections"][0]["rule_version"] == "1.0.0"
        assert report["history"][0]["action"] == "migrated_from_phase1"
        assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert store.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    with SQLiteStore(db) as store:
        assert store.show_incident(incident_id)["status"] == "investigating"


def test_bad_schema_is_not_reset(tmp_path: Path) -> None:
    db = tmp_path / "bad.db"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE unrelated (value TEXT)")
    connection.execute("INSERT INTO unrelated VALUES ('keep-me')")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="unrecognized schema"):
        SQLiteStore(db)
    connection = sqlite3.connect(db)
    assert connection.execute("SELECT value FROM unrelated").fetchone()[0] == "keep-me"
    connection.close()


def test_inconsistent_current_membership_is_rejected(tmp_path: Path) -> None:
    db = tmp_path / "missing-member.db"
    with SQLiteStore(db) as store:
        store.ingest_batch([normalized(fixture("iam")[0])])
        incident_id = store.list_incidents()[0]["incident_id"]
        store.connection.execute(
            "DELETE FROM incident_detections WHERE incident_id=?", (incident_id,)
        )
        store.connection.commit()
    with pytest.raises(ValueError, match="no detection membership"):
        SQLiteStore(db)


def test_inconsistent_phase1_relationships_roll_back(tmp_path: Path) -> None:
    db = tmp_path / "inconsistent.db"
    _phase1_database(db)
    connection = sqlite3.connect(db)
    connection.execute("DELETE FROM incidents")
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="inconsistent Phase 1"):
        SQLiteStore(db)
    connection = sqlite3.connect(db)
    names = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    assert {"events", "detections", "incidents"} <= names
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1
    connection.close()


def test_rule_version_reprocessing_and_assessment_history(tmp_path: Path) -> None:
    class VersionTwo(AttachAdministratorPolicy):
        version = "2.0.0"

    db = tmp_path / "versions.db"
    item = normalized(fixture("iam")[0])
    with SQLiteStore(db) as store:
        store.ingest_batch([item])
        incident_id = store.list_incidents()[0]["incident_id"]
        assert store.update_incident(incident_id, status="investigating",
                                     assessment="Approved change pending verification")
        first = store.reprocess((VersionTwo(),))
        assert first["evaluations"] == 1
        assert first["matches"] == 1
        assert store.reprocess((VersionTwo(),))["evaluations"] == 0
        report = store.show_incident(incident_id)
        assert report["detections"][0]["rule_version"] == "2.0.0"
        assert report["status"] == "investigating"
        assert report["assessment"] == "Approved change pending verification"
        assert any(entry["action"] == "assessment_updated" for entry in report["history"])
        assert any(entry["action"] == "rule_reprocessed" for entry in report["history"])
        assert store.connection.execute(
            "SELECT COUNT(*) FROM rule_evaluations WHERE event_key=? AND rule_id=?",
            (item.identity, "FLT-IAM-001"),
        ).fetchone()[0] == 2
    with SQLiteStore(db) as store:
        assert store.show_incident(incident_id)["detections"][0]["rule_version"] == "2.0.0"


def test_new_rule_version_can_deactivate_prior_match(tmp_path: Path) -> None:
    class NoLongerMatches(AttachAdministratorPolicy):
        version = "2.0.0"

        def match(self, event):
            return None

    with SQLiteStore(tmp_path / "deactivated.db") as store:
        store.ingest_batch([normalized(fixture("iam")[0])])
        original = store.list_incidents()[0]["incident_id"]
        assert store.reprocess((NoLongerMatches(),))["evaluations"] == 1
        assert store.list_incidents() == []
        assert store.connection.execute(
            "SELECT is_current FROM incidents WHERE incident_id=?", (original,)
        ).fetchone()[0] == 0
        assert store.connection.execute(
            "SELECT active FROM detections WHERE rule_id='FLT-IAM-001'"
        ).fetchone()[0] == 0


def test_reactivated_incident_preserves_assessment(tmp_path: Path) -> None:
    class NoMatch(AttachAdministratorPolicy):
        version = "2.0.0"

        def match(self, event):
            return None

    class MatchAgain(AttachAdministratorPolicy):
        version = "3.0.0"

    with SQLiteStore(tmp_path / "reactivate.db") as store:
        store.ingest_batch([normalized(fixture("iam")[0])])
        incident_id = store.list_incidents()[0]["incident_id"]
        store.update_incident(incident_id, status="investigating", assessment="Keep context")
        store.reprocess((NoMatch(),))
        assert not store.list_incidents()
        store.reprocess((MatchAgain(),))
        report = store.show_incident(incident_id)
        assert report["status"] == "investigating"
        assert report["assessment"] == "Keep context"
        assert any(entry["action"] == "reactivated" for entry in report["history"])


def test_sensitive_sts_response_and_json_cli_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "json.db"
    args = ["--db", str(db), "--json", "demo", "--scenario", "iam"]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["new_incidents"] == 1
    assert len(result["records"]) == 3
    assert main(["--db", str(db), "--json", "incidents", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)["incidents"]
    assert len(listed) == 1
    assert main(["--db", str(db), "--json", "incidents", "show",
                 listed[0]["incident_id"]]) == 0
    report = json.loads(capsys.readouterr().out)["incident"]
    assert (
        report["observed_timeline"][0]["occurred_at"]
        < report["observed_timeline"][1]["occurred_at"]
    )
    assert report["correlation_conclusions"][0]["rule_id"] == IAM_SEQUENCE_ID
    assert report["observed_timeline"][0]["actor"]["arn"] is not None
    assert b"SYNTHETIC-DO-NOT-STORE" not in db.read_bytes()
    assert b"review-session" not in db.read_bytes()
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["new_incidents"] == 0


def test_json_cli_update_and_reprocess(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.db"
    base = ["--db", str(db), "--json"]
    assert main([*base, "demo", "--scenario", "trail"]) == 0
    capsys.readouterr()
    assert main([*base, "incidents", "list"]) == 0
    incident_id = json.loads(capsys.readouterr().out)["incidents"][0]["incident_id"]
    assert main([*base, "incidents", "update", incident_id,
                 "--status", "investigating", "--assessment", "Checking approval"]) == 0
    updated = json.loads(capsys.readouterr().out)["incident"]
    assert updated["status"] == "investigating"
    assert updated["assessment"] == "Checking approval"
    assert updated["history"][-1]["action"] == "assessment_updated"
    assert main([*base, "incidents", "history", incident_id]) == 0
    history = json.loads(capsys.readouterr().out)["incident_history"]
    assert history["is_current"] is True
    assert history["history"][-1]["action"] == "assessment_updated"
    assert main([*base, "reprocess"]) == 0
    result = json.loads(capsys.readouterr().out)["reprocess"]
    assert set(result) == {"evaluations", "matches", "incidents_changed"}
    assert main([*base, "reprocess"]) == 0
    assert json.loads(capsys.readouterr().out)["reprocess"]["evaluations"] == 0


def test_invalid_json_line_does_not_block_correlation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = fixture("iam")[:2]
    path = tmp_path / "mixed.jsonl"
    path.write_text(json.dumps(raw[0]) + "\n{bad\n" + json.dumps(raw[1]), encoding="utf-8")
    db = tmp_path / "mixed.db"
    assert main(["--db", str(db), "--json", "ingest", "--file", str(path)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["invalid"] == 1
    assert result["summary"]["new_incidents"] == 1
    with SQLiteStore(db) as store:
        assert store.list_incidents()[0]["detection_count"] == 2


def test_rule_catalog_core_cases_remain_conservative() -> None:
    attach = fixture("iam")[0]
    assert detect(normalized(attach))[0].evidence["policyArn"] == ADMIN_POLICY_ARN
    failed = normalized(_change(attach, eventID="failed", errorCode="AccessDenied"))
    assert detect(failed) == ()


def test_display_control_characters_are_not_persisted(tmp_path: Path) -> None:
    raw = _change(fixture("iam")[0], userIdentity={
        "type": "IAMUser", "principalId": "AIDAEXAMPLEOPERATOR",
        "arn": "arn:aws:iam::111122223333:user/\u202eSpoofed",
        "accountId": "111122223333",
    })
    item = normalized(raw)
    assert item.actor_arn is None
    with SQLiteStore(tmp_path / "control.db") as store:
        store.ingest_batch([item])
    assert "\u202e".encode("utf-8") not in (tmp_path / "control.db").read_bytes()
