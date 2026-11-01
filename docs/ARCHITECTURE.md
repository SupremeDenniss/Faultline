# Architecture

## Local pipeline and boundaries

`bounded file parser → CloudTrail normalizer → versioned pure rules → SQLite adapter → correlation projection → CLI reports`

`input.py` limits file and record size, rejects duplicate JSON keys, and separates invalid records from usable records. `normalize.py` converts required timestamps to UTC, validates required identifiers, and selects only known event fields. `rules.py` contains deterministic single-event rules. `correlation.py` has no storage or CLI imports; it uses event time and explicit account, actor, and resource evidence. `storage.py` owns transactions, migration, evaluations, and projection into incidents. `cli.py` handles input, command output, and analyst display.

The v2 SQLite schema separates:

- **Events:** deduplicated normalized observations, keyed by `account_id:event_id`.
- **Rule evaluations:** one result for each event, rule ID, and rule version.
- **Detections:** current match for an event and rule ID, with stable `det-` ID, version, evidence, and active flag.
- **Incidents:** investigation status, assessment, created/update timestamps, and current flag.
- **Incident membership and links:** detection membership plus versioned, explicit explanations for paired evidence. A detection belongs to one current incident.
- **History:** audit records for migration, membership changes, supersession, rule reprocessing, and analyst assessment changes.

No full CloudTrail payload, `responseElements`, credentials, STS session name, source IP, user agent, or error message is persisted. A later DynamoDB adapter can implement the same ingest, reprocess, incident query, and assessment operations; none exists yet.

`--json` emits one object per command. Ingestion returns `records` and `summary`; incident listing returns `incidents`; a detail query or update returns `incident`; history lookup returns `incident_history`; reprocessing returns `reprocess`. Incident detail separates `observed_timeline`, `detections`, `correlation_conclusions`, `unknowns`, `unverified_possibilities`, `investigation_steps`, and `history`. `incidents history` can inspect a superseded incident after rekeying. Absent event fields are JSON `null`; unknown conclusions are written as explicit explanations. Times are UTC ISO 8601 strings. The output schema is stable within the 0.2 release; changes will be versioned with the package.

## Correlation semantics

The default window is 30 minutes, configurable from 1 to 1,440 minutes when creating a database. It is stored in `settings`, so a restart uses the same window. Changing it for an existing database is rejected; create a new database and reingest to compare windows. Time comparisons use normalized `eventTime`, never arrival order. A successor at the same timestamp is eligible. For each successor, the latest prior matching precursor is selected. Components are capped so their total event-time span does not exceed one window. Ties are deterministic by rule and detection ID.

IAM linking requires matching recipient account, caller type, principal ID, caller ARN, caller account when present, session issuer when present, and exact role ARN. AttachRolePolicy supplies only `roleName`; a matching ARN must also be present in that event's `resources` list. A role name alone is insufficient because IAM role paths can differ. STS supplies `requestParameters.roleArn`. No role ARN is fabricated.

CloudTrail linking requires the same recipient account, caller identifiers, region, and exact `requestParameters.name`. Both simple trail names and full trail ARNs are supported, but mixed representations are not linked. Full trail ARNs must agree with the account and region. This avoids merging same-named trails in different regions.

Events outside the window, with failed API calls, missing caller identity, or ambiguous resource identity remain separate. ARN correlation currently recognizes the standard `aws` partition; GovCloud and China partitions need explicit validation before use. A lone rule match is still an incident for review. Pairing does not claim malicious intent, a successful credential issuance, or eventual AWS state.

Late arrivals can join or split an incident after chronological recomputation. The current incident ID derives from the earliest event-time detection in its group. If an earlier late arrival changes that anchor, the old incident is marked non-current, a replacement is created, status and assessment are carried from overlapping current incidents, and history records the change. Current incident membership and JSON timelines are deterministic for a fixed event set and rule set. Ingestion audit timestamps and history order naturally reflect processing order.

Repeated event identities are ignored even if a conflicting payload is later presented. To evaluate changed rule logic, bump the rule version and run `faultline reprocess`. Evaluations for old versions remain as audit records; the active detection for each event/rule is updated or deactivated. Incidents are reconciled from active detections. Reprocessing the same rule version again is a no-op. Changing rule logic without a version bump is unsupported. Historical raw payloads are unavailable by design, and Phase 1 rows lack caller account IDs; missing fields are never reconstructed.

## Migration and trust

Opening a Phase 1 SQLite database with its three known tables triggers a single transaction that copies all normalized events, detections, statuses, and timestamps into v2, then sets `PRAGMA user_version=2`. An unknown schema or failed migration is rejected without resetting data. Back up valuable local databases before upgrading. SQLite file permissions and backups remain the operator's responsibility.

Inputs and fixtures are untrusted. The parser cannot authenticate CloudTrail provenance. Rule evidence is an allowlist of normalized fields and may still contain sensitive identifiers, so protect reports and databases accordingly. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Authoritative field references

AWS documents `AttachRolePolicy` parameters as a role **name** and policy ARN, while `AssumeRole` takes a role **ARN**. AWS CloudTrail examples show STS `requestParameters.roleArn` and sensitive credentials in `responseElements`, which Faultline discards. `StopLogging` and `DeleteTrail` accept a trail name or ARN. See [AttachRolePolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html), [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [IAM/STS CloudTrail examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html), [StopLogging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html), and [DeleteTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html).
