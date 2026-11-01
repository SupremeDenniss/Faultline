"""Local analyst CLI with stable JSON and readable incident timelines."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any

from faultline.input import InputError, read_records
from faultline.models import InputRecord
from faultline.normalize import normalize_record
from faultline.rules import detect
from faultline.storage import SQLiteStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="faultline", description="Local AWS activity detection")
    parser.add_argument("--db", type=Path, default=Path(".faultline/faultline.db"))
    parser.add_argument("--json", action="store_true", help="emit stable machine-readable JSON")
    parser.add_argument("--window-minutes", type=int, help="set window when creating a database")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="ingest bundled synthetic CloudTrail events")
    demo.add_argument("--scenario", choices=("phase1", "iam", "trail", "all"), default="phase1")
    ingest = commands.add_parser("ingest", help="ingest a local JSON or JSON Lines file")
    ingest.add_argument("--file", type=Path, required=True)
    commands.add_parser("reprocess", help="evaluate new rule versions against stored events")
    incidents = commands.add_parser("incidents", help="inspect and assess incidents")
    incident_commands = incidents.add_subparsers(dest="incident_command", required=True)
    incident_commands.add_parser("list")
    show = incident_commands.add_parser("show")
    show.add_argument("incident_id")
    history = incident_commands.add_parser("history")
    history.add_argument("incident_id")
    update = incident_commands.add_parser("update")
    update.add_argument("incident_id")
    update.add_argument("--status", choices=("open", "investigating", "closed"))
    update.add_argument("--assessment")
    return parser


def _emit(value: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _ingest(records: list[InputRecord], store: SQLiteStore, *, demo: bool, as_json: bool) -> int:
    outcomes: list[dict[str, Any]] = []
    events = []
    for record in records:
        if record.error:
            outcomes.append({
                "label": record.label, "status": "invalid", "diagnostic": record.error
            })
            continue
        result = normalize_record(record.value)
        if result.event is None:
            outcomes.append({
                "label": record.label, "status": result.status, "diagnostic": result.diagnostic
            })
            continue
        event = result.event
        findings = detect(event)
        events.append(event)
        outcomes.append({
            "label": record.label, "status": "pending", "event_reference": event.identity,
            "event_name": event.event_name, "error_code": event.error_code,
            "rule_ids": [finding.rule_id for finding in findings],
        })
    before = {item["incident_id"] for item in store.list_incidents()}
    results = iter(store.ingest_batch(events))
    for item in outcomes:
        if item["status"] != "pending":
            continue
        inserted, _matches = next(results)
        item["status"] = "ingested" if inserted else "duplicate"
    after = {item["incident_id"] for item in store.list_incidents()}
    counts = Counter(item["status"] for item in outcomes)
    summary = {
        "supported": counts["ingested"] + counts["duplicate"],
        "new_events": counts["ingested"],
        "new_incidents": len(after - before),
        "current_incidents": len(after),
        "duplicates": counts["duplicate"],
        "ignored": counts["ignored"],
        "invalid": counts["invalid"],
    }
    if as_json:
        _emit({"records": outcomes, "summary": summary}, True)
    else:
        for item in outcomes:
            label = item["label"]
            if item["status"] in ("invalid", "ignored"):
                print(f"{label}: {item['status']}: {item['diagnostic']}")
            elif item["status"] == "duplicate":
                print(f"{label}: duplicate event {item['event_reference']}")
            elif item["rule_ids"]:
                print(f"{label}: detections {', '.join(item['rule_ids'])}: {item['event_name']}")
            else:
                kind = "failed API call" if item["error_code"] else "benign/no matching rule"
                print(f"{label}: {kind}: {item['event_name']}")
        print(
            f"Summary: {summary['supported']} supported, {summary['new_events']} new events, "
            f"{summary['new_incidents']} new incidents, {summary['duplicates']} duplicates, "
            f"{summary['ignored']} ignored, {summary['invalid']} invalid."
        )
        if summary["new_incidents"]:
            print("Current incidents:")
            _print_list(store.list_incidents())
    return 0 if demo or summary["invalid"] == 0 else 1


def _print_list(incidents: list[dict[str, Any]]) -> None:
    if not incidents:
        print("No incidents recorded.")
    for item in incidents:
        print(
            f"{item['incident_id']}  {item['status']:<13} {item['severity']:<6} "
            f"{item['first_seen']}  {item['detection_count']} detection(s)  {item['title']}"
        )


def _display(value: object, missing: str = "missing from event") -> str:
    return missing if value is None else str(value)


def _print_report(report: dict[str, Any]) -> None:
    print(f"Incident {report['incident_id']} - {report['title']}")
    print(f"Status: {report['status']}   Severity: {report['severity']}")
    print(f"Account: {report['account_id']}   Resource: {report['resource']}")
    print(f"Observed: {report['first_seen']} to {report['last_seen']}")
    print(f"Assessment: {_display(report['assessment'], 'not assessed')}")
    print("\nObserved timeline (UTC):")
    for event in report["observed_timeline"]:
        actor = event["actor"]
        print(
            f"  {event['occurred_at']}  {event['event_name']}  "
            f"{event['event_reference']}"
        )
        print(
            f"    Caller: {_display(actor['arn'])}  "
            f"Principal: {_display(actor['principal_id'])}"
        )
    print("\nDetections:")
    for detection in report["detections"]:
        print(
            f"  {detection['rule_id']} v{detection['rule_version']} "
            f"({detection['severity']}): {detection['title']}"
        )
        print(f"    evidence: {json.dumps(detection['evidence'], sort_keys=True)}")
    print("\nCorrelation-derived conclusions:")
    if report["correlation_conclusions"]:
        for link in report["correlation_conclusions"]:
            print(f"  {link['rule_id']} v{link['rule_version']}: {link['explanation']}")
    else:
        print("  No multi-event linkage established.")
    print("\nUnknowns:")
    for value in report["unknowns"]:
        print(f"  - {value}")
    print("\nUnverified possibilities:")
    for value in report["unverified_possibilities"]:
        print(f"  - {value}")
    print("\nInvestigate next:")
    for value in report["investigation_steps"]:
        print(f"  - {value}")
    print("\nHistory:")
    for item in report["history"]:
        print(f"  {item['changed_at']}  {item['action']}")


def _demo_records(scenario: str) -> list[InputRecord]:
    names = (
        ("demo.jsonl",) if scenario == "phase1" else
        ("demo-iam.jsonl", "demo-trail.jsonl") if scenario == "all" else
        (f"demo-{scenario}.jsonl",)
    )
    result = []
    for name in names:
        fixture = resources.files("faultline").joinpath(f"fixtures/{name}")
        with resources.as_file(fixture) as path:
            result.extend(
                InputRecord(f"{name}:{record.label}", record.value, record.error)
                for record in read_records(path)
            )
    return result


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "demo":
            records = _demo_records(args.scenario)
            with SQLiteStore(args.db, args.window_minutes) as store:
                if not args.json:
                    print(f"Faultline synthetic local demo: {args.scenario}")
                return _ingest(records, store, demo=True, as_json=args.json)
        if args.command == "ingest":
            records = read_records(args.file)
            with SQLiteStore(args.db, args.window_minutes) as store:
                return _ingest(records, store, demo=False, as_json=args.json)
        with SQLiteStore(args.db, args.window_minutes) as store:
            if args.command == "reprocess":
                result = store.reprocess()
                if args.json:
                    _emit({"reprocess": result}, True)
                else:
                    print(
                        f"Reprocessed: {result['evaluations']} new rule evaluations, "
                        f"{result['matches']} matches, "
                        f"{result['incidents_changed']} incidents changed."
                    )
                return 0
            if args.incident_command == "list":
                incidents = store.list_incidents()
                if args.json:
                    _emit({"incidents": incidents}, True)
                else:
                    _print_list(incidents)
                return 0
            if args.incident_command == "show":
                report = store.show_incident(args.incident_id)
                if report is None:
                    print(f"Incident not found: {args.incident_id}", file=sys.stderr)
                    return 1
                if args.json:
                    _emit({"incident": report}, True)
                else:
                    _print_report(report)
                return 0
            if args.incident_command == "history":
                history = store.incident_history(args.incident_id)
                if history is None:
                    print(f"Incident not found: {args.incident_id}", file=sys.stderr)
                    return 1
                if args.json:
                    _emit({"incident_history": history}, True)
                else:
                    print(
                        f"Incident {args.incident_id} history "
                        f"({'current' if history['is_current'] else 'superseded'}):"
                    )
                    for entry in history["history"]:
                        print(
                            f"  {entry['changed_at']}  {entry['action']}  "
                            f"{json.dumps(entry['details'], sort_keys=True)}"
                        )
                return 0
            if args.status is None and args.assessment is None:
                raise ValueError("provide --status or --assessment")
            if not store.update_incident(
                args.incident_id, status=args.status, assessment=args.assessment
            ):
                print(f"Incident not found: {args.incident_id}", file=sys.stderr)
                return 1
            report = store.show_incident(args.incident_id)
            if args.json:
                _emit({"incident": report}, True)
            else:
                print(f"Updated {args.incident_id}: {report['status']}")
            return 0
    except (InputError, OSError, ValueError, sqlite3.DatabaseError) as exc:
        print(f"Faultline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
