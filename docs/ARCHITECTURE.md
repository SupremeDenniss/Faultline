# Architecture (Phase 1)

## Local pipeline

`JSON/JSONL file → bounded parser → CloudTrail normalizer → pure detection rules → SQLite store → CLI`

The parser accepts one object, an array, or JSON Lines. Input is capped at 10 MiB, 10,000 records, and 256 KiB per record. Each record is classified as supported, ignored (an unrelated EventBridge envelope), or invalid with a diagnostic. Missing or malformed timestamps make a record invalid; accepted timestamps require an offset and are converted to UTC. Optional fields may be absent and are never inferred.

The core `Event` and `Detection` contracts have no CLI or storage dependency. Rules match exact API source, name, and relevant parameters. A nonempty `errorCode` prevents a completed-change finding. An absent `errorCode` means the API call was not reported as failed, not proof that a cloud-side change occurred. Findings call for investigation and do not assert compromise.

SQLite stores a normalized allowlist of metadata and selected request fields, plus detection evidence and an incident with status and creation/update timestamps. It never stores the full raw event, response, error message, credentials, or arbitrary request payload. `account_id:event_id` is the event key. Incident IDs derive from that key and the rule ID. Replays do not alter incidents, status, or creation time. The `SQLiteStore` API is the persistence boundary for a future DynamoDB adapter.

## Trust boundaries

Files and JSON values are untrusted. Parsing does not evaluate code and rejects duplicate JSON keys. Required identifiers and timestamps are validated; optional strings are bounded and control characters are rejected. The CLI reports fixed diagnostics rather than printing source payloads. Local SQLite files contain selected actor identifiers, resources, and evidence; protect the database with normal local file permissions. The source file itself is outside Faultline's control.

## Planned AWS integration and limits

Future adapters may feed the same normalizer from EventBridge/CloudTrail and use DynamoDB persistence. They are not implemented. Phase 1 has no live AWS access, correlation, remediation, dashboard, or claim of compromise. It supports only two activity rules. Event ID deduplication assumes CloudTrail event IDs are stable within an account; conflicting replays with the same key are treated as duplicates. Detection does not verify eventual AWS state.
