# Detection rule catalog

All rules are deterministic and use normalized CloudTrail API events. Version `1.0.0` is the initial Phase 2 catalog version (including the two Phase 1 rules). A nonempty `errorCode` prevents a detection. Missing error status means only that failure was not reported in the provided event. `high` marks changes that could affect broad permissions or audit visibility; `medium` marks role assumption activity that needs context. Severity is a triage label, not a probability or arbitrary score.

ATT&CK mappings below refer to [Enterprise ATT&CK v20.0](https://attack.mitre.org/resources/versions/) (October 2026). They describe potentially relevant *observed behavior*, not attacker attribution or proof of intent.

| Rule | Trigger and evidence | Severity | ATT&CK alignment |
| --- | --- | --- | --- |
| `FLT-IAM-001` v1.0.0 | `iam.amazonaws.com` `AttachRolePolicy`; exact AWS-managed AdministratorAccess policy ARN and role name; evidence: `roleName`, `policyArn` | High: broad role permissions | [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| `FLT-STS-001` v1.0.0 | `sts.amazonaws.com` `AssumeRole`; explicit `requestParameters.roleArn`; evidence: `roleArn` | Medium: role assumption requires context | No standalone mapping; ordinary role assumption is too broad |
| `FLT-CT-001` v1.0.0 | `cloudtrail.amazonaws.com` `StopLogging`; trail `name` or resource; evidence: trail | High: audit visibility may be affected | [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/) |
| `FLT-CT-002` v1.0.0 | `cloudtrail.amazonaws.com` `DeleteTrail`; trail `name` or resource; evidence: trail | High: trail removal may affect audit visibility | [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/) |
| `FLT-CORR-IAM-001` v1.0.0 | `FLT-IAM-001` before `FLT-STS-001`; same account, actor, exact role ARN, and window; evidence: two detection IDs and equality explanation | High: broad permission change followed by use of same role | T1098.003 from attachment; no extra mapping inferred |
| `FLT-CORR-CT-001` v1.0.0 | `FLT-CT-001` before `FLT-CT-002`; same account, actor, region, exact trail identifier, and window; evidence: two detection IDs and equality explanation | High: two audit-impacting API activities | T1685.002 |

## Required sources and limitations

All rules require CloudTrail-style `eventID`, `eventTime` with timezone, `recipientAccountId` (or matching EventBridge account), `eventSource`, and `eventName`. The IAM and CloudTrail single-event rules require their listed request fields; the trail rules can use a resource value for a standalone finding. Correlation has stricter requirements: complete caller principal ID and ARN, the attachment's explicit role ARN in `resources`, or exact trail `requestParameters.name` plus region. An STS response can include credentials; they are neither needed nor stored. Phase 1 events lack caller account ID and cannot gain it during migration.

The rules do not inspect trust policies, effective permissions, trail configuration, returned credentials, or subsequent cloud state. API metadata can be forged in local input. Incorrect clocks, incomplete trails, unusual cross-account patterns, omitted resources, mixed trail name/ARN representations, or AWS partitions other than `aws` can prevent a link. A legitimate administrator may perform every operation listed here during approved maintenance, testing, or access management. These are expected false-positive contexts for triage, not evidence of compromise.

## Rule review notes

**FLT-IAM-001 — AdministratorAccess attachment API activity.** Source: IAM management API event. It triggers only on the exact AWS-managed policy ARN and `AttachRolePolicy` with `roleName`; the role name and policy ARN are the evidence. It cannot establish the role's trust policy, effective permissions, or who later used it. Approved privilege changes are a likely false-positive context. Check the change request, role path/ARN, trust policy, and surrounding IAM activity.

**FLT-STS-001 — Role assumption requested.** Source: STS management API event. It triggers on `AssumeRole` with `requestParameters.roleArn`; that ARN is evidence. It does not inspect the sensitive STS response, so it does not claim credentials were issued. Routine role switching is a common false-positive context. Check the caller, session, target role, and subsequent activity. No standalone ATT&CK mapping is assigned.

**FLT-CT-001 — CloudTrail StopLogging API activity.** Source: CloudTrail management API event. It triggers on `StopLogging` with a trail name or resource; the selected trail identifier is evidence. It cannot verify that logging actually stopped or that another trail did not continue collecting. Approved maintenance is a false-positive context. Verify current trail state and the change approval.

**FLT-CT-002 — CloudTrail DeleteTrail API activity.** Source: CloudTrail management API event. It triggers on `DeleteTrail` with a trail name or resource; the selected trail identifier is evidence. It cannot verify deletion or infer deletion of historical S3 logs. Approved trail replacement is a false-positive context. Verify trail inventory, log retention, and the change approval.

**FLT-CORR-IAM-001 — Policy attachment followed by role assumption.** Sources: the two IAM/STS detections and their normalized events. The link requires the same account, complete matching caller identity and session context, exact role ARN from the attachment's `resources`, the same requested STS role ARN, and event-time order within the window. Evidence is the two detection IDs, timestamps, actor fields, and explicit role ARN equality. Omitted or ambiguous role ARNs prevent a link; cross-account sequences with different recipient accounts are not correlated. An approved administrator might attach and then test a policy. Review the approval, trust policy, and assumed session's later actions.

**FLT-CORR-CT-001 — Logging stop followed by trail deletion.** Sources: the two CloudTrail detections and their normalized events. The link requires the same account, complete matching caller identity and session context, region, exact trail `name`, and event-time order within the window. Evidence is the two detection IDs, timestamps, actor fields, and trail identity equality. Mixed simple-name/ARN representations, missing region, or another actor prevent a link. Planned trail migration is a false-positive context. Verify trail state, other logging paths, and the approved change.

## Analyst steps

For IAM: compare the policy change and role assumption with approved work, check the role trust policy and path, identify the caller and session, and review subsequent CloudTrail activity. For CloudTrail: verify trail state and other logging paths independently, check change approvals, and inspect events around the stop/delete sequence. In both cases, preserve the original authenticated cloud evidence outside Faultline if a formal investigation is needed.
