# Roadmap

1. **Foundation (implemented):** bounded local ingestion, normalization, two event rules, SQLite incidents, CLI, synthetic fixtures, tests, and CI.
2. **Detection and correlation (implemented):** four event rules, two event-time correlation rules, versioned evaluations, multi-detection incidents, history, Phase 1 migration, JSON reports, and threat model.
3. **AWS infrastructure (implemented locally, deployment pending):** EventBridge/SQS/Lambda/CloudFormation definitions, bounded DynamoDB adapter, simulated end-to-end tests, deployment and teardown runbook. Live coverage, performance, and cost remain unverified.
4. **Incident response (planned):** controlled workflows, approval gates, and audited response actions.
5. **Monitoring and reliability (planned):** operational metrics, retries, dead-letter handling, and health checks.
6. **Advanced detection (planned):** richer temporal and identity context with explainable evidence.
7. **Dashboard (planned):** incident review and investigation interface.
8. **Production hardening (planned):** security review, scale testing, access control, and runbooks.
