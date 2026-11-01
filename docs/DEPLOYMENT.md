# Phase 3 deployment and teardown runbook

The AWS stack has only been checked offline. These commands are **operator actions** for a separate deployment review; none are run by tests or by the local CLI. Use a dedicated account or authorized test environment. The stack does not create or alter a CloudTrail trail. Do not use an existing project bucket or trail without its owner's approval.

## 1. Build and validate locally

Use Python 3.12 on Windows or Linux. The builder packages Faultline and pinned boto3 dependencies into a Lambda ZIP; it never contacts AWS. It needs package-index access to download build dependencies. It refuses an output path outside the repository.

```sh
python scripts/build_lambda.py --output .faultline/dist/faultline-lambda.zip
python -m pytest
python -m ruff check .
cfn-lint -t infra/cloudformation/faultline.yaml
```

Review the generated ZIP contents (`faultline/aws/handler.py`, package modules, boto3, botocore) and checksum. The stack points to an existing S3 object; CloudFormation itself does not build or upload code. Build the same Python 3.12 artifact again for any code change, use a new object key, and review a stack update.

## 2. Read-only AWS preflight

Choose an AWS CLI profile and Region explicitly and record the expected account ID. In PowerShell:

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

Confirm `IsLogging=true`, management events include **write and read** (especially STS `AssumeRole`), and the trail's region/multi-region and global-service-event settings actually cover the intended IAM, STS, and CloudTrail activity. Trail status by itself is insufficient. EventBridge's CloudTrail-originated events are best effort and may not appear in all regions for global services. Verify expected event routing with synthetic, non-sensitive test events after deployment; do not generate real `StopLogging`, `DeleteTrail`, or administrator policy changes for a smoke test. Confirm permission to create IAM roles and policies (`CAPABILITY_IAM`), Lambda, SQS, DynamoDB, EventBridge rules, and log groups. `validate-template` is a read-only API call; it does not prove resources will work after creation.

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

Check all three rules are enabled, including the STS all-management-events state; the event source mapping is enabled with `ReportBatchItemFailures`; queue visibility is 180 seconds and redrive count five; DynamoDB tables are active; the Lambda role and queue policy match the template. Send a synthetic EventBridge envelope to the processing queue only with explicit operator authority, then inspect CloudWatch batch counts, DynamoDB event/detection/incident rows, and DLQ depth. A local test alone cannot establish live coverage. Monitor Lambda errors and throttles, SQS oldest-message age and DLQ messages, EventBridge failed invocations, and DynamoDB throttles. Restrict access to CloudTrail identifiers and SQS bodies.

## 5. Complete teardown

Stack deletion destroys both DynamoDB tables **and all stored investigations**, both SQS queues and DLQ bodies, rules, Lambda, role, and the seven-day log group. Export any authorized evidence first. CloudFormation does not delete the pre-existing CloudTrail trail, S3 artifact object, or S3 bucket. Delete the stack deliberately:

```powershell
aws cloudformation delete-stack --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation wait stack-delete-complete --stack-name $stackName --profile $profileName --region $awsRegion
aws cloudformation describe-stacks --stack-name $stackName --profile $profileName --region $awsRegion
aws s3api delete-object --bucket $artifactBucket --key $artifactKey --profile $profileName --region $awsRegion
aws s3api head-object --bucket $artifactBucket --key $artifactKey --profile $profileName --region $awsRegion
```

The final `describe-stacks` and `head-object` should report absence after deletion. If the S3 bucket has versioning, delete all versions and delete markers of this key separately; `delete-object` alone may leave charged versions. An operator may delete a dedicated empty artifact bucket after checking ownership and contents. Verify no stack resources remain with `list-stack-resources`/service-specific `list-*` calls, and inspect billing later for residual CloudTrail, CloudWatch, S3, or other account resources. A failed CloudFormation delete requires inspecting stack events and removing the blocking resource manually; do not assume costs have stopped. No AWS Budget is created by the template.
