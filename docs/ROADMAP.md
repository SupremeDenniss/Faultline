# Roadmap

1. **Foundation (implemented):** bounded local ingestion, normalization, two event rules, SQLite incidents, CLI, synthetic fixtures, tests, and CI.
2. **Detection and correlation (implemented):** four event rules, two event-time correlation rules, versioned evaluations, multi-detection incidents, history, Phase 1 migration, JSON reports, and threat model.
3. **AWS infrastructure (implemented locally, deployment pending):** EventBridge/SQS/Lambda/CloudFormation definitions, bounded DynamoDB adapter, simulated end-to-end tests, deployment and teardown runbook. Live coverage, performance, and cost remain unverified.
3B. **Deployment validation readiness (implemented locally, execution pending):** read-only preflight, Linux Lambda ZIP verification, gated direct-SQS smoke test, structured evidence report, safe failure diagnostics, and paginated store reads. No live AWS checks have run.
3C. **First controlled AWS deployment (pending separate approval):** inspect resources in a sandbox account, test direct SQS ingestion and replay, then test real CloudTrail/EventBridge delivery with an approved AssumeRole operation. Record outcomes and teardown evidence.
4. **Incident response (planned):** controlled workflows, approval gates, and audited response actions.
5. **Monitoring and reliability (planned):** operational metrics, retries, dead-letter handling, and health checks.
6. **Advanced detection (planned):** richer temporal and identity context with explainable evidence.
7. **Dashboard (planned):** incident review and investigation interface.
8. **Production hardening (planned):** security review, scale testing, access control, and runbooks.
