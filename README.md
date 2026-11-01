# Faultline

Faultline is a local-first AWS security-event analysis tool. It turns selected CloudTrail API events into detections and groups related detections into explainable investigations. It analyzes activity over time; it does not scan cloud configuration or vulnerabilities. Project Blacklight addresses security posture; Faultline addresses observed activity. Running the tool needs no AWS credentials, network connection, or cloud resources.

## Current scope

Phase 2 supports raw CloudTrail event objects and EventBridge envelopes in JSON, arrays, or JSON Lines. It detects AdministratorAccess attachment to an IAM role, STS AssumeRole, CloudTrail StopLogging, and CloudTrail DeleteTrail. Two correlation rules link policy attachment to later assumption of the *explicitly identified same role*, and StopLogging to later DeleteTrail of the *same trail*. Findings describe API activity, not confirmed compromise or verified cloud state.

SQLite keeps events, versioned rule evaluations, detections, incidents, membership, linkage explanations, and incident history. A transactional migration preserves Phase 1 databases. Replaying events does not duplicate incidents. A dedicated reprocess command evaluates new rule versions against stored normalized events. Only selected fields are retained; source payloads and STS credentials are not stored.

## Install and run

Requires Python 3.12 or newer. From this repository:

```sh
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in Windows PowerShell or `source .venv/bin/activate` on Linux/macOS, then:

```sh
python -m pip install -e ".[dev]"
faultline --db .faultline/iam.db demo --scenario iam
faultline --db .faultline/trail.db demo --scenario trail
faultline --db .faultline/iam.db incidents list
faultline --db .faultline/iam.db incidents show <incident-id>
```

`demo` without `--scenario` retains the Phase 1 synthetic demonstration. `demo --scenario all` runs both Phase 2 scenarios in one database. All fixture accounts and identities are fictional; fixtures are not authenticated AWS events.

For another local input file:

```sh
faultline --db .faultline/local.db --window-minutes 30 ingest --file path/to/events.jsonl
faultline --db .faultline/local.db --json incidents list
faultline --db .faultline/local.db --json incidents show <incident-id>
faultline --db .faultline/local.db --json incidents history <incident-id>
faultline --db .faultline/local.db incidents update <incident-id> --status investigating --assessment "Reviewing approved change"
faultline --db .faultline/local.db reprocess
```

The correlation window defaults to 30 minutes and is fixed when a database is created; use a new database for a different window. `--json` precedes the command and emits one JSON value. Input is limited to 10 MiB, 10,000 records, and 256 KiB per record. Invalid records are diagnosed without executing payload content. A file with invalid records exits with code 1 after valid records have been processed; unreadable or unsafe files exit with code 2.

Run `python -m pytest` and `python -m ruff check .`. GitHub Actions checks Python 3.12 and 3.14 on Windows and Linux.

## Investigation example

An AdministratorAccess attachment and an AssumeRole event can share an account, a caller principal and ARN, and an exact role ARN within 30 minutes. Faultline records those observed facts, the linking rule, and an ordered timeline. An analyst should check the approved change record, the role's trust policy, and subsequent session activity before deciding whether it is suspicious. If the attachment has only a role name and no trustworthy role ARN, the events remain separate.

See the [architecture](docs/ARCHITECTURE.md), [rule catalog](docs/RULES.md), [threat model](docs/THREAT_MODEL.md), and [roadmap](docs/ROADMAP.md). AWS integration, response actions, and a dashboard remain planned.
