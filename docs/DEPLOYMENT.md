# Phase 3B deployment and validation runbook

The AWS stack has only been checked offline. These commands are **operator actions** for a separate deployment review; none are run by tests or by the local CLI. Use a dedicated account or authorized test environment. The stack does not create or alter a CloudTrail trail. Do not use an existing project bucket or trail without its owner's approval. The Phase 3B tools have not been run against AWS.

## 1. Build and validate locally

Use Python 3.12 on Windows or Linux. The builder packages the allowlisted Faultline Python modules and pinned Linux x86_64 dependency wheels into a Lambda ZIP; it never contacts AWS. It needs package-index access to download dependencies. It refuses an output path outside the repository. Install the optional AWS tooling with `python -m pip install -e ".[dev,aws]"`; ordinary local use needs neither boto3 nor AWS credentials.

```sh
python scripts/build_lambda.py --output .faultline/dist/faultline-lambda.zip
python scripts/verify_lambda.py .faultline/dist/faultline-lambda.zip
python -m pytest
python -m ruff check .
cfn-lint -t infra/cloudformation/faultline.yaml
```

On Windows, use `py -3.12` in place of `python` if needed; on Linux, use `python3.12`. The build writes `.zip.sha256` beside the artifact. It removes only SDK documentation/example members whose hashes match the pinned wheel `RECORD` manifests, retaining DynamoDB service models. The verifier checks the handler path, required modules, Python 3.12 syntax, pure Python wheels, credential patterns, and development files. The build also imports the extracted handler and loads the DynamoDB model with Python 3.12. These checks do not prove Lambda execution in AWS. Review the ZIP and checksum before upload. The stack points to an existing S3 object; CloudFormation does not build or upload code. Build again for code changes, use a new object key, and review a stack update.

## 2. Read-only AWS preflight

Choose an AWS CLI profile and Region explicitly and record the expected account ID. The reusable preflight runs only read APIs, fails on account or Region mismatch, and produces a sanitized JSON report. It conservatively checks active CloudTrail trails and both basic and advanced management-event selectors. Full IAM/global STS coverage is validated only for `us-east-1`; regional STS endpoints in other Regions need separate stacks or checks. IAM policy simulation is advisory and cannot prove effective deployment permission under SCPs, permission boundaries, or resource policies.

The preflight principal needs `sts:GetCallerIdentity`, `cloudformation:DescribeStacks`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, and S3 bucket metadata access. `iam:SimulatePrincipalPolicy` and `iam:GetRole` are optional advisory checks. A denied read check fails readiness unless explicitly marked unverified for IAM simulation; no write privilege is exercised by preflight.

```sh
python scripts/aws_preflight.py --profile YOUR_PROFILE --region us-east-1 --expected-account 123456789012 --stack faultline-phase3-demo --bucket YOUR_DEDICATED_ARTIFACT_BUCKET
```

Review every failed and unverified check. An expired session, conflicting stack, incomplete read/write selector, missing global-service coverage, or bucket in another Region blocks readiness. This preflight makes no AWS changes. For independent manual verification, in PowerShell:

```powershell
$profileName = 'YOUR_PROFILE'
$awsRegion = 'us-east-1'
$expectedAccount = '123456789012'
$stackName = 'faultline-phase3-demo'
$artifactBucket = 'YOUR_DEDICATED_ARTIFACT_BUCKET'
$artifactKey = 'faultline/phase3/faultline-lambda.zip'
$identity = aws sts get-caller-identity --profile $profileName --region $awsRegion | ConvertFrom-Json
if ($identity.Account -ne $expectedAccount) { throw 'Wrong AWS account' }
aws cloudtrail list-trails --profile $profileName --region $awsRegion
aws cloudtrail describe-trails --include-shadow-trails --profile $profileName --region $awsRegion
```

For each relevant trail ARN found above, run the following read-only checks and inspect the output:

```powershell
$trailArn = 'arn:aws:cloudtrail:us-east-1:123456789012:trail/YOUR_TRAIL'
aws cloudtrail get-trail-status --name $trailArn --profile $profileName --region $awsRegion
aws cloudtrail get-event-selectors --trail-name $trailArn --profile $profileName --region $awsRegion
aws cloudformation validate-template --template-body file://infra/cloudformation/faultline.yaml --profile $profileName --region $awsRegion
```

Confirm `IsLogging=true`, management events include **write and read** (especially STS `AssumeRole`), and the trail's region/multi-region and global-service-event settings cover the intended activity. Trail status alone is insufficient. EventBridge's CloudTrail-originated events are best effort. Do not generate real `StopLogging`, `DeleteTrail`, or administrator policy changes for a smoke test. Confirm permission to create IAM roles and policies (`CAPABILITY_IAM`), Lambda, SQS, DynamoDB, EventBridge rules, and log groups. `validate-template` is read-only and does not prove resources will work after creation.

For Bash, use `profile_name`, `aws_region`, `expected_account`, and command substitution instead of PowerShell variables; keep `--profile` and `--region` on every command. The Python build and offline checks are identical on both systems.

## 3. Upload, create, and review a change set

The artifact bucket must already exist in the chosen account, be in the Lambda deployment Region, and be under the operator's control. Uploading creates an S3 object and can incur charges. Execute only after reviewing the bucket and ZIP checksum.

```powershell
aws s3api put-object --bucket $artifactBucket --key $artifactKey --body .faultline/dist/faultline-lambda.zip --profile $profileName --region $awsRegion
aws cloudformation create-change-set --stack-name $stackName --change-set-name phase3-initial --change-set-type CREATE --template-body file://infra/cloudformation/faultline.yaml --capabilities CAPABILITY_IAM --parameters ParameterKey=ArtifactBucket,ParameterValue=$artifactBucket ParameterKey=ArtifactKey,ParameterValue=$artifactKey --profile $profileName --region $awsRegion
aws cloudformation wait change-set-create-complete --stack-name $stackName --change-set-name phase3-initial --profile $profileName --region $awsRegion
aws cloudformation describe-change-set --stack-name $stackName --change-set-name phase3-initial --profile $profileName --region $awsRegion
```

Review every resource, IAM statement, S3 key, and replacement warning. A no-change change set may make the `wait` command fail; inspect `describe-change-set` before proceeding. CloudFormation's `CAPABILITY_IAM` acknowledges creation of the named execution role. No application role has administrator permissions.

## 4. Explicit deployment action and verification

Only after an operator approves the reviewed change set:

```powershell
aws cloudformation execute-change-set --stack-name $stackName --change-set-name phase3-initial --profile $profileName --region $awsRegion
aws cloudformation wait stack-create-complete --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation describe-stacks --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation list-stack-resources --stack-name $stackName --profile $profileName --region $awsRegion
```

Run the read-only inspector after deployment. It checks the stack and outputs, EventBridge states/patterns/targets, queue encryption/visibility/redrive and sender policy, Lambda runtime/mapping, table and index state, execution-role policy, log retention, recent CloudWatch metrics, observed DLQ depth, and stack/table deletion protection. Missing metrics remain unverified; no zero is invented. The operator running inspection needs read access to CloudFormation, EventBridge, SQS attributes, Lambda configuration, DynamoDB table descriptions, IAM role policies, CloudWatch metrics, and logs. The smoke test additionally needs `sqs:SendMessage`, DynamoDB `GetItem`/`Query`, and CloudWatch Logs `FilterLogEvents` on this stack's resources.

```sh
python scripts/aws_validate.py --profile YOUR_PROFILE --region us-east-1 --expected-account 123456789012 --stack faultline-phase3-demo --report .faultline/inspection.json inspect
```

After separately approving test messages, use a **fresh** test ID. The two gates are deliberate. The script sends four sanitized EventBridge-style fixtures directly to the stack queue, waits for strongly consistent DynamoDB event/detection/incident reads, replays the same four messages, and checks duplicate log markers and unchanged incident history. It writes no STS response data and reports failures without source payloads. The JSON report includes application version, commit SHA, working-tree state, account, Region, timestamp, test ID, resource checks, counts, DLQ depth, and unverified conditions. A dirty tree means the SHA alone does not identify the tested code. Protect the report because it contains account and resource identifiers.

```sh
python scripts/aws_validate.py --profile YOUR_PROFILE --region us-east-1 --expected-account 123456789012 --stack faultline-phase3-demo --report .faultline/smoke.json smoke --send --confirm-account 123456789012 --test-id UNIQUE_TEST_ID
```

**This proves only the direct SQS → Lambda → DynamoDB path.** It does not prove CloudTrail → EventBridge delivery or exactly-once processing. If CloudWatch duplicate markers are delayed or absent, the report marks replay unverified. Inspect CloudWatch Lambda errors/throttles, queue age and DLQ depth, EventBridge failed invocations, and DynamoDB throttles. Export only sanitized evidence to an access-controlled location.

For a separate real-delivery test, obtain approval for a sandbox IAM role with a narrow trust policy. Use `scripts/aws_assume_role_probe.py` with `--run`, `--confirm-account`, and that exact role ARN. It calls a legitimate `AssumeRole` and discards returned temporary credentials without printing them. Correlate its request ID and session name with CloudTrail Event History, the STS EventBridge rule metrics, and the resulting standalone `FLT-STS-001` detection in DynamoDB. Wait for best-effort delivery and document any absence as unverified. Do not attach AdministratorAccess, stop logging, or delete a trail to generate traffic. The real-delivery test needs its own written approval and has **not** been executed.

```sh
python scripts/aws_assume_role_probe.py --profile YOUR_PROFILE --region us-east-1 --expected-account 123456789012 --confirm-account 123456789012 --role-arn arn:aws:iam::123456789012:role/YOUR_APPROVED_SANDBOX_ROLE --run
```

If a message reaches the DLQ, record its message ID and safe failure category, inspect it only with restricted access, correct the cause, and redrive only the intended message after approving the action. A blocked 16-detection scope or unsupported rule change will fail again without a controlled rebuild or rule rollback; repeated blind redrive is not recovery. Preserve evidence before deletion. See [AWS architecture](AWS_ARCHITECTURE.md) for data-state implications.

## 5. Complete teardown

Stack deletion destroys both DynamoDB tables **and all stored investigations**, both SQS queues and DLQ bodies, rules, Lambda, role, and the seven-day log group. Export any authorized evidence first. CloudFormation does not delete the pre-existing CloudTrail trail, S3 artifact object, or S3 bucket. Delete the stack deliberately:

```powershell
aws cloudformation delete-stack --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation wait stack-delete-complete --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation describe-stacks --stack-name $stackName --profile $profileName --region $awsRegion
aws s3api delete-object --bucket $artifactBucket --key $artifactKey --profile $profileName --region $awsRegion
aws s3api head-object --bucket $artifactBucket --key $artifactKey --profile $profileName --region $awsRegion
```

The final `describe-stacks` and `head-object` should report absence after deletion. Verify the stack reaches `DELETE_COMPLETE`; inspect stack events and remaining physical resources if it reaches `DELETE_FAILED`. A failed command alone is never proof of deletion. If the S3 bucket has versioning, delete all versions and delete markers of this key separately; `delete-object` alone may leave charged versions. An operator may delete a dedicated empty artifact bucket after checking ownership and contents. Verify no stack resources remain with `list-stack-resources`/service-specific `list-*` calls, and inspect billing later for residual CloudTrail, CloudWatch, S3, or other account resources. No AWS Budget is created by the template.
