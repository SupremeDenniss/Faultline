"""Human-readable local command line interface."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from importlib import resources
from pathlib import Path

from faultline.input import InputError, read_records
from faultline.models import InputRecord
from faultline.normalize import normalize_record
from faultline.rules import detect
from faultline.storage import SQLiteStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="faultline", description="Local AWS activity detection")
    parser.add_argument("--db", type=Path, default=Path(".faultline/faultline.db"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="ingest bundled synthetic CloudTrail events")
    ingest = commands.add_parser("ingest", help="ingest a local JSON or JSON Lines file")
    ingest.add_argument("--file", type=Path, required=True)
    incidents = commands.add_parser("incidents", help="inspect recorded incidents")
    incident_commands = incidents.add_subparsers(dest="incident_command", required=True)
    incident_commands.add_parser("list")
    show = incident_commands.add_parser("show")
    show.add_argument("incident_id")
    return parser


def _ingest(records: list[InputRecord], db: Path, *, demo: bool = False) -> int:
    counts: Counter[str] = Counter()
    with SQLiteStore(db) as store:
        for record in records:
            if record.error:
                counts["invalid"] += 1
                print(f"{record.label}: invalid: {record.error}")
                continue
            result = normalize_record(record.value)
            if result.status == "invalid":
                counts["invalid"] += 1
                print(f"{record.label}: invalid: {result.diagnostic}")
            elif result.status == "ignored":
                counts["ignored"] += 1
                print(f"{record.label}: ignored: {result.diagnostic}")
            else:
                event = result.event
                assert event is not None
                counts["supported"] += 1
                findings = detect(event)
                inserted, count = store.save(event, findings)
                if not inserted:
                    counts["duplicates"] += 1
                    print(f"{record.label}: duplicate event {event.identity}")
                else:
                    counts["new_events"] += 1
                    counts["incidents"] += count
                    if findings:
                        for finding in findings:
                            print(
                                f"{record.label}: incident {finding.rule_id}: {finding.title} "
                                f"[{finding.resource}]"
                            )
                    else:
                        label = "failed API call" if event.error_code else "benign/no matching rule"
                        print(f"{record.label}: {label}: {event.event_name}")
    print(
        "Summary: "
        f"{counts['supported']} supported, {counts['new_events']} new events, "
        f"{counts['incidents']} new incidents, {counts['duplicates']} duplicates, "
        f"{counts['ignored']} ignored, {counts['invalid']} invalid."
    )
    return 0 if demo or counts["invalid"] == 0 else 1


def _show(store: SQLiteStore, incident_id: str) -> int:
    incident = store.show_incident(incident_id)
    if incident is None:
        print(f"Incident not found: {incident_id}", file=sys.stderr)
        return 1
    for key in (
        "incident_id", "status", "created_at", "updated_at", "rule_id", "severity",
        "title", "explanation", "resource", "event_reference", "account_id",
        "event_id", "occurred_at",
        "event_source", "event_name", "region", "actor_type", "actor_arn",
        "principal_id", "session_issuer_arn", "source_format", "envelope_id",
        "error_code", "evidence",
    ):
        value = incident[key]
        if value is not None:
            print(f"{key}: {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "demo":
            fixture = resources.files("faultline").joinpath("fixtures/demo.jsonl")
            with resources.as_file(fixture) as path:
                records = read_records(path)
            print("Faultline synthetic local demo")
            return _ingest(records, args.db, demo=True)
        if args.command == "ingest":
            return _ingest(read_records(args.file), args.db)
        with SQLiteStore(args.db) as store:
            if args.incident_command == "show":
                return _show(store, args.incident_id)
            incidents = store.list_incidents()
            if not incidents:
                print("No incidents recorded.")
            for incident in incidents:
                print(
                    f"{incident['incident_id']}  {incident['status']}  "
                    f"{incident['severity']}  {incident['rule_id']}  "
                    f"{incident['resource']}  {incident['occurred_at']}"
                )
            return 0
    except (InputError, OSError) as exc:
        print(f"Faultline error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
