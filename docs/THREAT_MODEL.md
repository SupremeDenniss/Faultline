# Local threat model

## Assumptions and boundaries

Phase 2 reads local files supplied by an operator. The files and synthetic fixtures are **not authenticated AWS events**. The tool makes no AWS or network calls. Local users with access to the database or reports can see selected account, principal, role, and trail identifiers. OS file permissions, backups, and source provenance are operator responsibilities.

| Risk | Current control | Remaining limitation |
| --- | --- | --- |
| Malformed or malicious JSON | 10 MiB file, 10,000 record, and 256 KiB record limits; strict UTF-8, duplicate-key rejection, structural validation; no payload evaluation | Parsing still consumes local CPU and memory up to those limits |
| Forged event metadata | Required identifiers and timezone-aware timestamps validated; matching EventBridge account/region checked | Local events are not cryptographically authenticated |
| Correlation poisoning | Exact account, caller principal/ARN, resource, region, ordering, and window constraints; absent evidence blocks linkage | A forged internally consistent dataset can still produce a false investigation |
| Duplicate-event abuse | Unique account/event identity and transactional inserts; replay is idempotent | A conflicting later payload with the same key is ignored rather than adjudicated |
| Sensitive evidence exposure | Store allowlists known metadata and request fields; never stores raw response elements, STS credentials, error messages, or tokens | Selected identifiers and analyst assessments can still be sensitive; protect the SQLite file and JSON output |
| SQLite corruption or migration failure | Known v1 schema check, transactional migration, `quick_check`, foreign-key and membership checks, uniqueness constraints | Local disk corruption and backup recovery are outside the tool; back up before migration |
| Event ordering and partial evidence | Event-time sorting and persistent recomputation; missing actor or exact resource evidence prevents correlation | Late arrivals may change current incident grouping and ID; clocks or missing logs may mislead |
| Future live AWS integration | Planned adapter boundary keeps rule logic independent of transport | Authentication, least privilege, delivery integrity, retries, and provenance must be designed before Phase 3 use |

Faultline's conclusions are limited to observed API metadata and deterministic relationships. It does not establish compromise, successful exfiltration, or verified current AWS state.
